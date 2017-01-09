package quic

import (
	"errors"
	"fmt"
	"net"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/lucas-clemente/quic-go/ackhandler"
	"github.com/lucas-clemente/quic-go/flowcontrol"
	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/handshake"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
	"github.com/lucas-clemente/quic-go/utils"
)

type unpacker interface {
	Unpack(publicHeaderBinary []byte, hdr *PublicHeader, data []byte) (*unpackedPacket, error)
}

type receivedPacket struct {
	remoteAddr   interface{}
	publicHeader *PublicHeader
	data         []byte
	rcvTime      time.Time
}

var (
	errRstStreamOnInvalidStream   = errors.New("RST_STREAM received for unknown stream")
	errWindowUpdateOnClosedStream = errors.New("WINDOW_UPDATE received for an already closed stream")
)

// StreamCallback gets a stream frame and returns a reply frame
type StreamCallback func(*Session, utils.Stream)

// closeCallback is called when a session is closed
type closeCallback func(id protocol.ConnectionID)

// A Session is a QUIC session
type Session struct {
	connectionID protocol.ConnectionID
	version      protocol.VersionNumber

	streamCallback StreamCallback
	closeCallback  closeCallback

	conn connection

	streamsMap *streamsMap

	sentPacketHandler     ackhandler.SentPacketHandler
	receivedPacketHandler ackhandler.ReceivedPacketHandler
	streamFramer          *streamFramer

	flowControlManager flowcontrol.FlowControlManager

	unpacker unpacker
	packer   *packetPacker

	cryptoSetup *handshake.CryptoSetup

	receivedPackets  chan *receivedPacket
	sendingScheduled chan struct{}
	// closeChan is used to notify the run loop that it should terminate.
	// If the value is not nil, the error is sent as a CONNECTION_CLOSE.
	closeChan chan *qerr.QuicError
	closed    uint32 // atomic bool

	undecryptablePackets []*receivedPacket
	aeadChanged          chan struct{}

	delayedAckOriginTime time.Time

	connectionParametersManager *handshake.ConnectionParametersManager

	lastRcvdPacketNumber protocol.PacketNumber
	// Used to calculate the next packet number from the truncated wire
	// representation, and sent back in public reset packets
	largestRcvdPacketNumber protocol.PacketNumber

	sessionCreationTime     time.Time
	lastNetworkActivityTime time.Time

	timer           *time.Timer
	currentDeadline time.Time
	timerRead       bool
}

// newSession makes a new session
func newSession(conn connection, v protocol.VersionNumber, connectionID protocol.ConnectionID, sCfg *handshake.ServerConfig, streamCallback StreamCallback, closeCallback closeCallback) (packetHandler, error) {
	connectionParametersManager := handshake.NewConnectionParamatersManager()
	flowControlManager := flowcontrol.NewFlowControlManager(connectionParametersManager)

	var sentPacketHandler ackhandler.SentPacketHandler
	var receivedPacketHandler ackhandler.ReceivedPacketHandler

	sentPacketHandler = ackhandler.NewSentPacketHandler()
	receivedPacketHandler = ackhandler.NewReceivedPacketHandler()

	now := time.Now()
	session := &Session{
		conn:         conn,
		connectionID: connectionID,
		version:      v,

		streamCallback: streamCallback,
		closeCallback:  closeCallback,

		connectionParametersManager: connectionParametersManager,
		sentPacketHandler:           sentPacketHandler,
		receivedPacketHandler:       receivedPacketHandler,
		flowControlManager:          flowControlManager,

		receivedPackets:      make(chan *receivedPacket, protocol.MaxSessionUnprocessedPackets),
		closeChan:            make(chan *qerr.QuicError, 1),
		sendingScheduled:     make(chan struct{}, 1),
		undecryptablePackets: make([]*receivedPacket, 0, protocol.MaxUndecryptablePackets),
		aeadChanged:          make(chan struct{}, 1),

		timer: time.NewTimer(0),
		lastNetworkActivityTime: now,
		sessionCreationTime:     now,
	}

	session.streamsMap = newStreamsMap(session.newStream)

	cryptoStream, _ := session.GetOrOpenStream(1)
	var err error
	session.cryptoSetup, err = handshake.NewCryptoSetup(connectionID, conn.RemoteAddr().IP, v, sCfg, cryptoStream, session.connectionParametersManager, session.aeadChanged)
	if err != nil {
		return nil, err
	}

	session.streamFramer = newStreamFramer(session.streamsMap, flowControlManager)
	session.packer = newPacketPacker(connectionID, session.cryptoSetup, session.connectionParametersManager, session.streamFramer, v)
	session.unpacker = &packetUnpacker{aead: session.cryptoSetup, version: v}

	return session, err
}

// run the session main loop
func (s *Session) run() {
	// Start the crypto stream handler
	go func() {
		if err := s.cryptoSetup.HandleCryptoStream(); err != nil {
			s.Close(err)
		}
	}()

	for {
		// Close immediately if requested
		select {
		case errForConnClose := <-s.closeChan:
			if errForConnClose != nil {
				s.sendConnectionClose(errForConnClose)
			}
			return
		default:
		}

		s.maybeResetTimer()

		var err error
		select {
		case errForConnClose := <-s.closeChan:
			if errForConnClose != nil {
				s.sendConnectionClose(errForConnClose)
			}
			return
		case <-s.timer.C:
			s.timerRead = true
			// We do all the interesting stuff after the switch statement, so
			// nothing to see here.
		case <-s.sendingScheduled:
			// We do all the interesting stuff after the switch statement, so
			// nothing to see here.
		case p := <-s.receivedPackets:
			err = s.handlePacketImpl(p)
			if qErr, ok := err.(*qerr.QuicError); ok && qErr.ErrorCode == qerr.DecryptionFailure {
				s.tryQueueingUndecryptablePacket(p)
				continue
			}
			// This is a bit unclean, but works properly, since the packet always
			// begins with the public header and we never copy it.
			putPacketBuffer(p.publicHeader.Raw)
			if s.delayedAckOriginTime.IsZero() {
				s.delayedAckOriginTime = p.rcvTime
			}
		case <-s.aeadChanged:
			s.tryDecryptingQueuedPackets()
		}

		if err != nil {
			s.Close(err)
		}

		if err := s.sendPacket(); err != nil {
			s.Close(err)
		}
		if time.Now().Sub(s.lastNetworkActivityTime) >= s.idleTimeout() {
			s.Close(qerr.Error(qerr.NetworkIdleTimeout, "No recent network activity."))
		}
		if !s.cryptoSetup.HandshakeComplete() && time.Now().Sub(s.sessionCreationTime) >= protocol.MaxTimeForCryptoHandshake {
			s.Close(qerr.Error(qerr.NetworkIdleTimeout, "Crypto handshake did not complete in time."))
		}
		s.garbageCollectStreams()
	}
}

func (s *Session) maybeResetTimer() {
	nextDeadline := s.lastNetworkActivityTime.Add(s.idleTimeout())

	if !s.delayedAckOriginTime.IsZero() {
		nextDeadline = utils.MinTime(nextDeadline, s.delayedAckOriginTime.Add(protocol.AckSendDelay))
	}
	if rtoTime := s.sentPacketHandler.TimeOfFirstRTO(); !rtoTime.IsZero() {
		nextDeadline = utils.MinTime(nextDeadline, rtoTime)
	}
	if !s.cryptoSetup.HandshakeComplete() {
		handshakeDeadline := s.sessionCreationTime.Add(protocol.MaxTimeForCryptoHandshake)
		nextDeadline = utils.MinTime(nextDeadline, handshakeDeadline)
	}

	if nextDeadline.Equal(s.currentDeadline) {
		// No need to reset the timer
		return
	}

	// We need to drain the timer if the value from its channel was not read yet.
	// See https://groups.google.com/forum/#!topic/golang-dev/c9UUfASVPoU
	if !s.timer.Stop() && !s.timerRead {
		<-s.timer.C
	}
	s.timer.Reset(nextDeadline.Sub(time.Now()))

	s.timerRead = false
	s.currentDeadline = nextDeadline
}

func (s *Session) idleTimeout() time.Duration {
	if s.cryptoSetup.HandshakeComplete() {
		return s.connectionParametersManager.GetIdleConnectionStateLifetime()
	}
	return protocol.InitialIdleTimeout
}

func (s *Session) handlePacketImpl(p *receivedPacket) error {
	if p.rcvTime.IsZero() {
		// To simplify testing
		p.rcvTime = time.Now()
	}

	s.lastNetworkActivityTime = p.rcvTime
	hdr := p.publicHeader
	data := p.data

	// Calculate packet number
	hdr.PacketNumber = protocol.InferPacketNumber(
		hdr.PacketNumberLen,
		s.largestRcvdPacketNumber,
		hdr.PacketNumber,
	)
	if utils.Debug() {
		utils.Debugf("<- Reading packet 0x%x (%d bytes) for connection %x", hdr.PacketNumber, len(data)+len(hdr.Raw), hdr.ConnectionID)
	}

	// TODO: Only do this after authenticating
	s.conn.setCurrentRemoteAddr(p.remoteAddr)

	packet, err := s.unpacker.Unpack(hdr.Raw, hdr, data)
	if err != nil {
		return err
	}

	s.lastRcvdPacketNumber = hdr.PacketNumber
	// Only do this after decrypting, so we are sure the packet is not attacker-controlled
	s.largestRcvdPacketNumber = utils.MaxPacketNumber(s.largestRcvdPacketNumber, hdr.PacketNumber)

	err = s.receivedPacketHandler.ReceivedPacket(hdr.PacketNumber)
	// ignore duplicate packets
	if err == ackhandler.ErrDuplicatePacket {
		utils.Infof("Ignoring packet 0x%x due to ErrDuplicatePacket", hdr.PacketNumber)
		return nil
	}
	// ignore packets with packet numbers smaller than the LeastUnacked of a StopWaiting
	if err == ackhandler.ErrPacketSmallerThanLastStopWaiting {
		utils.Infof("Ignoring packet 0x%x due to ErrPacketSmallerThanLastStopWaiting", hdr.PacketNumber)
		return nil
	}

	if err != nil {
		return err
	}

	return s.handleFrames(packet.frames)
}

func (s *Session) handleFrames(fs []frames.Frame) error {
	for _, ff := range fs {
		var err error
		frames.LogFrame(ff, false)
		switch frame := ff.(type) {
		case *frames.StreamFrame:
			err = s.handleStreamFrame(frame)
			// TODO: send RstStreamFrame
		case *frames.AckFrame:
			err = s.handleAckFrame(frame)
		case *frames.ConnectionCloseFrame:
			s.closeImpl(qerr.Error(frame.ErrorCode, frame.ReasonPhrase), true)
		case *frames.GoawayFrame:
			err = errors.New("unimplemented: handling GOAWAY frames")
		case *frames.StopWaitingFrame:
			err = s.receivedPacketHandler.ReceivedStopWaiting(frame)
		case *frames.RstStreamFrame:
			err = s.handleRstStreamFrame(frame)
		case *frames.WindowUpdateFrame:
			err = s.handleWindowUpdateFrame(frame)
		case *frames.BlockedFrame:
		case *frames.PingFrame:
		default:
			return errors.New("Session BUG: unexpected frame type")
		}

		if err != nil {
			switch err {
			case ackhandler.ErrDuplicateOrOutOfOrderAck:
				// Can happen e.g. when packets thought missing arrive late
			case errRstStreamOnInvalidStream:
				// Can happen when RST_STREAMs arrive early or late (?)
				utils.Errorf("Ignoring error in session: %s", err.Error())
			case errWindowUpdateOnClosedStream:
				// Can happen when we already sent the last StreamFrame with the FinBit, but the client already sent a WindowUpdate for this Stream
			default:
				return err
			}
		}
	}
	return nil
}

// handlePacket is called by the server with a new packet
func (s *Session) handlePacket(p *receivedPacket) {
	// Discard packets once the amount of queued packets is larger than
	// the channel size, protocol.MaxSessionUnprocessedPackets
	select {
	case s.receivedPackets <- p:
	default:
	}
}

func (s *Session) handleStreamFrame(frame *frames.StreamFrame) error {
	str, err := s.streamsMap.GetOrOpenStream(frame.StreamID)
	if err != nil {
		return err
	}
	if str == nil {
		// Stream is closed, ignore
		return nil
	}
	err = str.AddStreamFrame(frame)
	if err != nil {
		return err
	}
	return nil
}

func (s *Session) handleWindowUpdateFrame(frame *frames.WindowUpdateFrame) error {
	if frame.StreamID != 0 {
		str, err := s.streamsMap.GetOrOpenStream(frame.StreamID)
		if err != nil {
			return err
		}
		if str == nil {
			return errWindowUpdateOnClosedStream
		}
	}
	_, err := s.flowControlManager.UpdateWindow(frame.StreamID, frame.ByteOffset)
	return err
}

// TODO: Handle frame.byteOffset
func (s *Session) handleRstStreamFrame(frame *frames.RstStreamFrame) error {
	str, err := s.streamsMap.GetOrOpenStream(frame.StreamID)
	if err != nil {
		return err
	}
	if str == nil {
		return errRstStreamOnInvalidStream
	}
	s.closeStreamWithError(str, fmt.Errorf("RST_STREAM received with code %d", frame.ErrorCode))
	return nil
}

func (s *Session) handleAckFrame(frame *frames.AckFrame) error {
	if err := s.sentPacketHandler.ReceivedAck(frame, s.lastRcvdPacketNumber, s.lastNetworkActivityTime); err != nil {
		return err
	}
	return nil
}

// Close the connection. If err is nil it will be set to qerr.PeerGoingAway.
func (s *Session) Close(e error) error {
	return s.closeImpl(e, false)
}

func (s *Session) closeImpl(e error, remoteClose bool) error {
	// Only close once
	if !atomic.CompareAndSwapUint32(&s.closed, 0, 1) {
		return nil
	}

	if e == nil {
		e = qerr.PeerGoingAway
	}

	quicErr := qerr.ToQuicError(e)

	// Don't log 'normal' reasons
	if quicErr.ErrorCode == qerr.PeerGoingAway || quicErr.ErrorCode == qerr.NetworkIdleTimeout {
		utils.Infof("Closing connection %x", s.connectionID)
	} else {
		utils.Errorf("Closing session with error: %s", e.Error())
	}

	s.closeStreamsWithError(quicErr)
	s.closeCallback(s.connectionID)

	if remoteClose {
		// If this is a remote close we don't need to send a CONNECTION_CLOSE
		s.closeChan <- nil
		return nil
	}

	if quicErr.ErrorCode == qerr.DecryptionFailure {
		// If we send a public reset, don't send a CONNECTION_CLOSE
		s.closeChan <- nil
		return s.sendPublicReset(s.lastRcvdPacketNumber)
	}
	s.closeChan <- quicErr
	return nil
}

func (s *Session) closeStreamsWithError(err error) {
	s.streamsMap.Iterate(func(str *stream) (bool, error) {
		s.closeStreamWithError(str, err)
		return true, nil
	})
}

func (s *Session) closeStreamWithError(str *stream, err error) {
	str.RegisterError(err)
}

func (s *Session) sendPacket() error {
	// Repeatedly try sending until we don't have any more data, or run out of the congestion window
	for {
		err := s.sentPacketHandler.CheckForError()
		if err != nil {
			return err
		}

		// Do this before checking the congestion, since we might de-congestionize here :)
		s.sentPacketHandler.MaybeQueueRTOs()

		if !s.sentPacketHandler.SendingAllowed() {
			return nil
		}

		var controlFrames []frames.Frame

		// check for retransmissions first
		for {
			retransmitPacket := s.sentPacketHandler.DequeuePacketForRetransmission()
			if retransmitPacket == nil {
				break
			}
			utils.Debugf("\tDequeueing retransmission for packet 0x%x", retransmitPacket.PacketNumber)

			// resend the frames that were in the packet
			controlFrames = append(controlFrames, retransmitPacket.GetControlFramesForRetransmission()...)
			for _, streamFrame := range retransmitPacket.GetStreamFramesForRetransmission() {
				s.streamFramer.AddFrameForRetransmission(streamFrame)
			}
		}

		windowUpdateFrames, err := s.getWindowUpdateFrames()
		if err != nil {
			return err
		}

		for _, wuf := range windowUpdateFrames {
			controlFrames = append(controlFrames, wuf)
		}

		ack, err := s.receivedPacketHandler.GetAckFrame(false)
		if err != nil {
			return err
		}
		if ack != nil {
			controlFrames = append(controlFrames, ack)
		}

		// Check whether we are allowed to send a packet containing only an ACK
		maySendOnlyAck := time.Now().Sub(s.delayedAckOriginTime) > protocol.AckSendDelay
		if runtime.GOOS == "windows" {
			maySendOnlyAck = true
		}

		hasRetransmission := s.streamFramer.HasFramesForRetransmission()

		var stopWaitingFrame *frames.StopWaitingFrame
		if ack != nil || hasRetransmission {
			stopWaitingFrame = s.sentPacketHandler.GetStopWaitingFrame(hasRetransmission)
		}
		packet, err := s.packer.PackPacket(stopWaitingFrame, controlFrames, s.sentPacketHandler.GetLeastUnacked(), maySendOnlyAck)
		if err != nil {
			return err
		}
		if packet == nil {
			return nil
		}

		// Pop the ACK frame now that we are sure we're gonna send it
		_, err = s.receivedPacketHandler.GetAckFrame(true)
		if err != nil {
			return err
		}

		for _, f := range windowUpdateFrames {
			s.packer.QueueControlFrameForNextPacket(f)
		}

		err = s.sentPacketHandler.SentPacket(&ackhandler.Packet{
			PacketNumber: packet.number,
			Frames:       packet.frames,
			Length:       protocol.ByteCount(len(packet.raw)),
		})
		if err != nil {
			return err
		}

		s.logPacket(packet)
		s.delayedAckOriginTime = time.Time{}

		err = s.conn.write(packet.raw)
		putPacketBuffer(packet.raw)
		if err != nil {
			return err
		}
	}
}

func (s *Session) sendConnectionClose(quicErr *qerr.QuicError) error {
	packet, err := s.packer.PackConnectionClose(&frames.ConnectionCloseFrame{ErrorCode: quicErr.ErrorCode, ReasonPhrase: quicErr.ErrorMessage}, s.sentPacketHandler.GetLeastUnacked())
	if err != nil {
		return err
	}
	if packet == nil {
		return errors.New("Session BUG: expected packet not to be nil")
	}
	s.logPacket(packet)
	return s.conn.write(packet.raw)
}

func (s *Session) logPacket(packet *packedPacket) {
	if !utils.Debug() {
		// We don't need to allocate the slices for calling the format functions
		return
	}
	if utils.Debug() {
		utils.Debugf("-> Sending packet 0x%x (%d bytes)", packet.number, len(packet.raw))
		for _, frame := range packet.frames {
			frames.LogFrame(frame, true)
		}
	}
}

// GetOrOpenStream either returns an existing stream, a newly opened stream, or nil if a stream with the provided ID is already closed.
// Newly opened streams should only originate from the client. To open a stream from the server, OpenStream should be used.
func (s *Session) GetOrOpenStream(id protocol.StreamID) (utils.Stream, error) {
	return s.streamsMap.GetOrOpenStream(id)
}

// OpenStream opens a stream from the server's side
func (s *Session) OpenStream(id protocol.StreamID) (utils.Stream, error) {
	return s.streamsMap.OpenStream(id)
}

func (s *Session) newStreamImpl(id protocol.StreamID) (*stream, error) {
	return s.streamsMap.GetOrOpenStream(id)
}

func (s *Session) newStream(id protocol.StreamID) (*stream, error) {
	stream, err := newStream(id, s.scheduleSending, s.flowControlManager)
	if err != nil {
		return nil, err
	}

	// TODO: find a better solution for determining which streams contribute to connection level flow control
	if id == 1 || id == 3 {
		s.flowControlManager.NewStream(id, false)
	} else {
		s.flowControlManager.NewStream(id, true)
	}

	s.streamCallback(s, stream)

	return stream, nil
}

// garbageCollectStreams goes through all streams and removes EOF'ed streams
// from the streams map.
func (s *Session) garbageCollectStreams() {
	s.streamsMap.Iterate(func(str *stream) (bool, error) {
		id := str.StreamID()
		if str.finished() {
			err := s.streamsMap.RemoveStream(id)
			if err != nil {
				return false, err
			}
			s.flowControlManager.RemoveStream(id)
		}
		return true, nil
	})
}

func (s *Session) sendPublicReset(rejectedPacketNumber protocol.PacketNumber) error {
	utils.Infof("Sending public reset for connection %x, packet number %d", s.connectionID, rejectedPacketNumber)
	return s.conn.write(writePublicReset(s.connectionID, rejectedPacketNumber, 0))
}

// scheduleSending signals that we have data for sending
func (s *Session) scheduleSending() {
	select {
	case s.sendingScheduled <- struct{}{}:
	default:
	}
}

func (s *Session) tryQueueingUndecryptablePacket(p *receivedPacket) {
	if s.cryptoSetup.HandshakeComplete() {
		return
	}
	utils.Infof("Queueing packet 0x%x for later decryption", p.publicHeader.PacketNumber)
	if len(s.undecryptablePackets)+1 >= protocol.MaxUndecryptablePackets {
		s.Close(qerr.Error(qerr.DecryptionFailure, "too many undecryptable packets received"))
	}
	s.undecryptablePackets = append(s.undecryptablePackets, p)
}

func (s *Session) tryDecryptingQueuedPackets() {
	for _, p := range s.undecryptablePackets {
		s.handlePacket(p)
	}
	s.undecryptablePackets = s.undecryptablePackets[:0]
}

func (s *Session) getWindowUpdateFrames() ([]*frames.WindowUpdateFrame, error) {
	updates := s.flowControlManager.GetWindowUpdates()
	res := make([]*frames.WindowUpdateFrame, len(updates))
	for i, u := range updates {
		res[i] = &frames.WindowUpdateFrame{StreamID: u.StreamID, ByteOffset: u.Offset}
	}
	return res, nil
}

// RemoteAddr returns the net.UDPAddr of the client
func (s *Session) RemoteAddr() *net.UDPAddr {
	return s.conn.RemoteAddr()
}
