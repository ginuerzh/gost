package quic

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/lucas-clemente/quic-go/ackhandler"
	"github.com/lucas-clemente/quic-go/congestion"
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
	errSessionAlreadyClosed       = errors.New("Cannot close Session. It was already closed before.")
)

// StreamCallback gets a stream frame and returns a reply frame
type StreamCallback func(*Session, utils.Stream)

// CryptoChangeCallback is called every time the encryption level changes
// Once the callback has been called with isForwardSecure = true, it is guarantueed to not be called with isForwardSecure = false after that
type CryptoChangeCallback func(isForwardSecure bool)

// closeCallback is called when a session is closed
type closeCallback func(id protocol.ConnectionID)

// A Session is a QUIC session
type Session struct {
	connectionID protocol.ConnectionID
	perspective  protocol.Perspective
	version      protocol.VersionNumber

	streamCallback       StreamCallback
	closeCallback        closeCallback
	cryptoChangeCallback CryptoChangeCallback

	conn connection

	streamsMap *streamsMap

	rttStats *congestion.RTTStats

	sentPacketHandler     ackhandler.SentPacketHandler
	receivedPacketHandler ackhandler.ReceivedPacketHandler
	streamFramer          *streamFramer

	flowControlManager flowcontrol.FlowControlManager

	unpacker unpacker
	packer   *packetPacker

	cryptoSetup handshake.CryptoSetup

	receivedPackets  chan *receivedPacket
	sendingScheduled chan struct{}
	// closeChan is used to notify the run loop that it should terminate.
	// If the value is not nil, the error is sent as a CONNECTION_CLOSE.
	closeChan chan *qerr.QuicError
	runClosed chan struct{}
	closed    uint32 // atomic bool

	undecryptablePackets []*receivedPacket
	aeadChanged          chan struct{}

	nextAckScheduledTime time.Time

	connectionParameters handshake.ConnectionParametersManager

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
	session := &Session{
		conn:         conn,
		connectionID: connectionID,
		perspective:  protocol.PerspectiveServer,
		version:      v,

		streamCallback:       streamCallback,
		closeCallback:        closeCallback,
		cryptoChangeCallback: func(bool) {},
		connectionParameters: handshake.NewConnectionParamatersManager(protocol.PerspectiveServer, v),
	}

	session.setup()
	cryptoStream, _ := session.GetOrOpenStream(1)
	var err error
	session.cryptoSetup, err = handshake.NewCryptoSetup(connectionID, conn.RemoteAddr().IP, v, sCfg, cryptoStream, session.connectionParameters, session.aeadChanged)
	if err != nil {
		return nil, err
	}

	session.packer = newPacketPacker(connectionID, session.cryptoSetup, session.connectionParameters, session.streamFramer, session.perspective, session.version)
	session.unpacker = &packetUnpacker{aead: session.cryptoSetup, version: session.version}

	return session, err
}

func newClientSession(conn *net.UDPConn, addr *net.UDPAddr, hostname string, v protocol.VersionNumber, connectionID protocol.ConnectionID, tlsConfig *tls.Config, streamCallback StreamCallback, closeCallback closeCallback, cryptoChangeCallback CryptoChangeCallback, negotiatedVersions []protocol.VersionNumber) (*Session, error) {
	session := &Session{
		conn:         &udpConn{conn: conn, currentAddr: addr},
		connectionID: connectionID,
		perspective:  protocol.PerspectiveClient,
		version:      v,

		streamCallback:       streamCallback,
		closeCallback:        closeCallback,
		cryptoChangeCallback: cryptoChangeCallback,
		connectionParameters: handshake.NewConnectionParamatersManager(protocol.PerspectiveClient, v),
	}

	session.receivedPacketHandler = ackhandler.NewReceivedPacketHandler(session.ackAlarmChanged)
	session.setup()

	cryptoStream, _ := session.OpenStream(1)
	var err error
	session.cryptoSetup, err = handshake.NewCryptoSetupClient(hostname, connectionID, v, cryptoStream, tlsConfig, session.connectionParameters, session.aeadChanged, negotiatedVersions)
	if err != nil {
		return nil, err
	}

	session.packer = newPacketPacker(connectionID, session.cryptoSetup, session.connectionParameters, session.streamFramer, session.perspective, session.version)
	session.unpacker = &packetUnpacker{aead: session.cryptoSetup, version: session.version}

	return session, err
}

// setup is called from newSession and newClientSession and initializes values that are independent of the perspective
func (s *Session) setup() {
	s.rttStats = &congestion.RTTStats{}
	flowControlManager := flowcontrol.NewFlowControlManager(s.connectionParameters, s.rttStats)

	var sentPacketHandler ackhandler.SentPacketHandler
	sentPacketHandler = ackhandler.NewSentPacketHandler(s.rttStats)

	now := time.Now()

	s.sentPacketHandler = sentPacketHandler
	s.flowControlManager = flowControlManager
	s.receivedPacketHandler = ackhandler.NewReceivedPacketHandler(s.ackAlarmChanged)

	s.receivedPackets = make(chan *receivedPacket, protocol.MaxSessionUnprocessedPackets)
	s.closeChan = make(chan *qerr.QuicError, 1)
	s.sendingScheduled = make(chan struct{}, 1)
	s.undecryptablePackets = make([]*receivedPacket, 0, protocol.MaxUndecryptablePackets)
	s.aeadChanged = make(chan struct{}, 1)
	s.runClosed = make(chan struct{}, 1)

	s.timer = time.NewTimer(0)
	s.lastNetworkActivityTime = now
	s.sessionCreationTime = now

	s.streamsMap = newStreamsMap(s.newStream, s.perspective, s.connectionParameters)
	s.streamFramer = newStreamFramer(s.streamsMap, s.flowControlManager)
}

// run the session main loop
func (s *Session) run() {
	// Start the crypto stream handler
	go func() {
		if err := s.cryptoSetup.HandleCryptoStream(); err != nil {
			s.Close(err)
		}
	}()

runLoop:
	for {
		// Close immediately if requested
		select {
		case errForConnClose := <-s.closeChan:
			if errForConnClose != nil {
				s.sendConnectionClose(errForConnClose)
			}
			break runLoop
		default:
		}

		s.maybeResetTimer()

		var err error
		select {
		case errForConnClose := <-s.closeChan:
			if errForConnClose != nil {
				s.sendConnectionClose(errForConnClose)
			}
			break runLoop
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
		case <-s.aeadChanged:
			s.tryDecryptingQueuedPackets()
			s.cryptoChangeCallback(s.cryptoSetup.HandshakeComplete())
		}

		if err != nil {
			s.close(err)
		}

		if err := s.sendPacket(); err != nil {
			s.close(err)
		}
		if time.Now().Sub(s.lastNetworkActivityTime) >= s.idleTimeout() {
			s.close(qerr.Error(qerr.NetworkIdleTimeout, "No recent network activity."))
		}
		if !s.cryptoSetup.HandshakeComplete() && time.Now().Sub(s.sessionCreationTime) >= protocol.MaxTimeForCryptoHandshake {
			s.close(qerr.Error(qerr.NetworkIdleTimeout, "Crypto handshake did not complete in time."))
		}
		s.garbageCollectStreams()
	}

	s.closeCallback(s.connectionID)
	s.runClosed <- struct{}{}
}

func (s *Session) maybeResetTimer() {
	nextDeadline := s.lastNetworkActivityTime.Add(s.idleTimeout())

	if !s.nextAckScheduledTime.IsZero() {
		nextDeadline = utils.MinTime(nextDeadline, s.nextAckScheduledTime)
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
		return s.connectionParameters.GetIdleConnectionStateLifetime()
	}
	return protocol.InitialIdleTimeout
}

func (s *Session) handlePacketImpl(p *receivedPacket) error {
	if s.perspective == protocol.PerspectiveClient {
		diversificationNonce := p.publicHeader.DiversificationNonce
		if len(diversificationNonce) > 0 {
			s.cryptoSetup.SetDiversificationNonce(diversificationNonce)
		}
	}

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
		utils.Debugf("<- Reading packet 0x%x (%d bytes) for connection %x @ %s", hdr.PacketNumber, len(data)+len(hdr.Raw), hdr.ConnectionID, time.Now().Format("15:04:05.000"))
	}

	packet, err := s.unpacker.Unpack(hdr.Raw, hdr, data)
	// if the decryption failed, this might be a packet sent by an attacker
	// don't update the remote address
	if quicErr, ok := err.(*qerr.QuicError); ok && quicErr.ErrorCode == qerr.DecryptionFailure {
		return err
	}
	if s.perspective == protocol.PerspectiveServer {
		// update the remote address, even if unpacking failed for any other reason than a decryption error
		s.conn.setCurrentRemoteAddr(p.remoteAddr)
	}
	if err != nil {
		return err
	}

	s.lastRcvdPacketNumber = hdr.PacketNumber
	// Only do this after decrypting, so we are sure the packet is not attacker-controlled
	s.largestRcvdPacketNumber = utils.MaxPacketNumber(s.largestRcvdPacketNumber, hdr.PacketNumber)

	err = s.receivedPacketHandler.ReceivedPacket(hdr.PacketNumber, packet.IsRetransmittable())
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
		// Stream is closed and already garbage collected
		// ignore this StreamFrame
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

func (s *Session) handleRstStreamFrame(frame *frames.RstStreamFrame) error {
	str, err := s.streamsMap.GetOrOpenStream(frame.StreamID)
	if err != nil {
		return err
	}
	if str == nil {
		return errRstStreamOnInvalidStream
	}

	str.RegisterRemoteError(fmt.Errorf("RST_STREAM received with code %d", frame.ErrorCode))
	return s.flowControlManager.ResetStream(frame.StreamID, frame.ByteOffset)
}

func (s *Session) handleAckFrame(frame *frames.AckFrame) error {
	if err := s.sentPacketHandler.ReceivedAck(frame, s.lastRcvdPacketNumber, s.lastNetworkActivityTime); err != nil {
		return err
	}
	return nil
}

// Close the connection. If err is nil it will be set to qerr.PeerGoingAway.
// It waits until the run loop has stopped before returning
func (s *Session) Close(e error) error {
	err := s.closeImpl(e, false)
	if err == errSessionAlreadyClosed {
		return nil
	}

	// wait for the run loop to finish
	<-s.runClosed
	return err
}

// close the connection. Use this when called from the run loop
func (s *Session) close(e error) error {
	err := s.closeImpl(e, false)
	if err == errSessionAlreadyClosed {
		return nil
	}
	return err
}

func (s *Session) closeImpl(e error, remoteClose bool) error {
	// Only close once
	if !atomic.CompareAndSwapUint32(&s.closed, 0, 1) {
		return errSessionAlreadyClosed
	}

	if e == errCloseSessionForNewVersion {
		s.closeStreamsWithError(e)
		// when the run loop exits, it will call the closeCallback
		// replace it with an noop function to make sure this doesn't have any effect
		s.closeCallback = func(protocol.ConnectionID) {}
		s.closeChan <- nil
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
		str.Cancel(err)
		return true, nil
	})
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

		// get WindowUpdate frames
		// this call triggers the flow controller to increase the flow control windows, if necessary
		windowUpdateFrames, err := s.getWindowUpdateFrames()
		if err != nil {
			return err
		}
		for _, wuf := range windowUpdateFrames {
			controlFrames = append(controlFrames, wuf)
		}

		// check for retransmissions first
		for {
			retransmitPacket := s.sentPacketHandler.DequeuePacketForRetransmission()
			if retransmitPacket == nil {
				break
			}
			utils.Debugf("\tDequeueing retransmission for packet 0x%x", retransmitPacket.PacketNumber)

			// resend the frames that were in the packet
			for _, frame := range retransmitPacket.GetFramesForRetransmission() {
				switch frame.(type) {
				case *frames.StreamFrame:
					s.streamFramer.AddFrameForRetransmission(frame.(*frames.StreamFrame))
				case *frames.WindowUpdateFrame:
					// only retransmit WindowUpdates if the stream is not yet closed and the we haven't sent another WindowUpdate with a higher ByteOffset for the stream
					var currentOffset protocol.ByteCount
					f := frame.(*frames.WindowUpdateFrame)
					currentOffset, err = s.flowControlManager.GetReceiveWindow(f.StreamID)
					if err == nil && f.ByteOffset >= currentOffset {
						controlFrames = append(controlFrames, frame)
					}
				default:
					controlFrames = append(controlFrames, frame)
				}
			}
		}

		ack := s.receivedPacketHandler.GetAckFrame()
		if ack != nil {
			controlFrames = append(controlFrames, ack)
		}
		hasRetransmission := s.streamFramer.HasFramesForRetransmission()
		var stopWaitingFrame *frames.StopWaitingFrame
		if ack != nil || hasRetransmission {
			stopWaitingFrame = s.sentPacketHandler.GetStopWaitingFrame(hasRetransmission)
		}
		packet, err := s.packer.PackPacket(stopWaitingFrame, controlFrames, s.sentPacketHandler.GetLeastUnacked())
		if err != nil {
			return err
		}
		if packet == nil {
			return nil
		}
		// send every window update twice
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

		err = s.conn.write(packet.raw)
		putPacketBuffer(packet.raw)
		if err != nil {
			return err
		}
		s.nextAckScheduledTime = time.Time{}
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
		utils.Debugf("-> Sending packet 0x%x (%d bytes) @ %s", packet.number, len(packet.raw), time.Now().Format("15:04:05.000"))
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

func (s *Session) queueResetStreamFrame(id protocol.StreamID, offset protocol.ByteCount) {
	s.packer.QueueControlFrameForNextPacket(&frames.RstStreamFrame{
		StreamID:   id,
		ByteOffset: offset,
	})
	s.scheduleSending()
}

func (s *Session) newStream(id protocol.StreamID) (*stream, error) {
	stream, err := newStream(id, s.scheduleSending, s.queueResetStreamFrame, s.flowControlManager)
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
		s.close(qerr.Error(qerr.DecryptionFailure, "too many undecryptable packets received"))
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

func (s *Session) ackAlarmChanged(t time.Time) {
	s.nextAckScheduledTime = t
	s.maybeResetTimer()
}

// RemoteAddr returns the net.UDPAddr of the client
func (s *Session) RemoteAddr() *net.UDPAddr {
	return s.conn.RemoteAddr()
}
