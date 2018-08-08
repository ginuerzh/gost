package quic

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go/ackhandler"
	"github.com/lucas-clemente/quic-go/congestion"
	"github.com/lucas-clemente/quic-go/internal/flowcontrol"
	"github.com/lucas-clemente/quic-go/internal/handshake"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
	"github.com/lucas-clemente/quic-go/qerr"
)

type unpacker interface {
	Unpack(headerBinary []byte, hdr *wire.Header, data []byte) (*unpackedPacket, error)
}

type receivedPacket struct {
	remoteAddr net.Addr
	header     *wire.Header
	data       []byte
	rcvTime    time.Time
}

var (
	errRstStreamOnInvalidStream   = errors.New("RST_STREAM received for unknown stream")
	errWindowUpdateOnClosedStream = errors.New("WINDOW_UPDATE received for an already closed stream")
)

var (
	newCryptoSetup       = handshake.NewCryptoSetup
	newCryptoSetupClient = handshake.NewCryptoSetupClient
)

type handshakeEvent struct {
	encLevel protocol.EncryptionLevel
	err      error
}

type closeError struct {
	err    error
	remote bool
}

// A Session is a QUIC session
type session struct {
	connectionID protocol.ConnectionID
	perspective  protocol.Perspective
	version      protocol.VersionNumber
	config       *Config

	conn connection

	streamsMap   *streamsMap
	cryptoStream streamI

	rttStats *congestion.RTTStats

	sentPacketHandler     ackhandler.SentPacketHandler
	receivedPacketHandler ackhandler.ReceivedPacketHandler
	streamFramer          *streamFramer

	connFlowController flowcontrol.ConnectionFlowController

	unpacker unpacker
	packer   *packetPacker

	cryptoSetup handshake.CryptoSetup

	receivedPackets  chan *receivedPacket
	sendingScheduled chan struct{}
	// closeChan is used to notify the run loop that it should terminate.
	closeChan chan closeError
	closeOnce sync.Once

	ctx       context.Context
	ctxCancel context.CancelFunc

	// when we receive too many undecryptable packets during the handshake, we send a Public reset
	// but only after a time of protocol.PublicResetTimeout has passed
	undecryptablePackets                   []*receivedPacket
	receivedTooManyUndecrytablePacketsTime time.Time

	// this channel is passed to the CryptoSetup and receives the transport parameters, as soon as the peer sends them
	paramsChan <-chan handshake.TransportParameters
	// this channel is passed to the CryptoSetup and receives the current encryption level
	// it is closed as soon as the handshake is complete
	aeadChanged       <-chan protocol.EncryptionLevel
	handshakeComplete bool
	// will be closed as soon as the handshake completes, and receive any error that might occur until then
	// it is used to block WaitUntilHandshakeComplete()
	handshakeCompleteChan chan error
	// handshakeChan receives handshake events and is closed as soon the handshake completes
	// the receiving end of this channel is passed to the creator of the session
	// it receives at most 3 handshake events: 2 when the encryption level changes, and one error
	handshakeChan chan<- handshakeEvent

	lastRcvdPacketNumber protocol.PacketNumber
	// Used to calculate the next packet number from the truncated wire
	// representation, and sent back in public reset packets
	largestRcvdPacketNumber protocol.PacketNumber

	sessionCreationTime     time.Time
	lastNetworkActivityTime time.Time

	peerParams *handshake.TransportParameters

	timer *utils.Timer
	// keepAlivePingSent stores whether a Ping frame was sent to the peer or not
	// it is reset as soon as we receive a packet from the peer
	keepAlivePingSent bool
}

var _ Session = &session{}

// newSession makes a new session
func newSession(
	conn connection,
	v protocol.VersionNumber,
	connectionID protocol.ConnectionID,
	sCfg *handshake.ServerConfig,
	tlsConf *tls.Config,
	config *Config,
) (packetHandler, <-chan handshakeEvent, error) {
	s := &session{
		conn:         conn,
		connectionID: connectionID,
		perspective:  protocol.PerspectiveServer,
		version:      v,
		config:       config,
	}
	return s.setup(sCfg, "", tlsConf, v, nil)
}

// declare this as a variable, such that we can it mock it in the tests
var newClientSession = func(
	conn connection,
	hostname string,
	v protocol.VersionNumber,
	connectionID protocol.ConnectionID,
	tlsConf *tls.Config,
	config *Config,
	initialVersion protocol.VersionNumber,
	negotiatedVersions []protocol.VersionNumber, // needed for validation of the GQUIC version negotiaton
) (packetHandler, <-chan handshakeEvent, error) {
	s := &session{
		conn:         conn,
		connectionID: connectionID,
		perspective:  protocol.PerspectiveClient,
		version:      v,
		config:       config,
	}
	return s.setup(nil, hostname, tlsConf, initialVersion, negotiatedVersions)
}

func (s *session) setup(
	scfg *handshake.ServerConfig,
	hostname string,
	tlsConf *tls.Config,
	initialVersion protocol.VersionNumber,
	negotiatedVersions []protocol.VersionNumber,
) (packetHandler, <-chan handshakeEvent, error) {
	aeadChanged := make(chan protocol.EncryptionLevel, 2)
	paramsChan := make(chan handshake.TransportParameters)
	s.aeadChanged = aeadChanged
	s.paramsChan = paramsChan
	handshakeChan := make(chan handshakeEvent, 3)
	s.handshakeChan = handshakeChan
	s.handshakeCompleteChan = make(chan error, 1)
	s.receivedPackets = make(chan *receivedPacket, protocol.MaxSessionUnprocessedPackets)
	s.closeChan = make(chan closeError, 1)
	s.sendingScheduled = make(chan struct{}, 1)
	s.undecryptablePackets = make([]*receivedPacket, 0, protocol.MaxUndecryptablePackets)
	s.ctx, s.ctxCancel = context.WithCancel(context.Background())

	s.timer = utils.NewTimer()
	now := time.Now()
	s.lastNetworkActivityTime = now
	s.sessionCreationTime = now

	s.rttStats = &congestion.RTTStats{}
	transportParams := &handshake.TransportParameters{
		StreamFlowControlWindow:     protocol.ReceiveStreamFlowControlWindow,
		ConnectionFlowControlWindow: protocol.ReceiveConnectionFlowControlWindow,
		MaxStreams:                  protocol.MaxIncomingStreams,
		IdleTimeout:                 s.config.IdleTimeout,
	}
	s.sentPacketHandler = ackhandler.NewSentPacketHandler(s.rttStats)
	s.receivedPacketHandler = ackhandler.NewReceivedPacketHandler(s.version)
	s.connFlowController = flowcontrol.NewConnectionFlowController(
		protocol.ReceiveConnectionFlowControlWindow,
		protocol.ByteCount(s.config.MaxReceiveConnectionFlowControlWindow),
		s.rttStats,
	)
	s.streamsMap = newStreamsMap(s.newStream, s.perspective, s.version)
	s.cryptoStream = s.newStream(s.version.CryptoStreamID())
	s.streamFramer = newStreamFramer(s.cryptoStream, s.streamsMap, s.connFlowController)

	var err error
	if s.perspective == protocol.PerspectiveServer {
		verifySourceAddr := func(clientAddr net.Addr, cookie *Cookie) bool {
			return s.config.AcceptCookie(clientAddr, cookie)
		}
		if s.version.UsesTLS() {
			s.cryptoSetup, err = handshake.NewCryptoSetupTLSServer(
				s.cryptoStream,
				s.connectionID,
				tlsConf,
				s.conn.RemoteAddr(),
				transportParams,
				paramsChan,
				aeadChanged,
				verifySourceAddr,
				s.config.Versions,
				s.version,
			)
		} else {
			s.cryptoSetup, err = newCryptoSetup(
				s.cryptoStream,
				s.connectionID,
				s.conn.RemoteAddr(),
				s.version,
				scfg,
				transportParams,
				s.config.Versions,
				verifySourceAddr,
				paramsChan,
				aeadChanged,
			)
		}
	} else {
		transportParams.OmitConnectionID = s.config.RequestConnectionIDOmission
		if s.version.UsesTLS() {
			s.cryptoSetup, err = handshake.NewCryptoSetupTLSClient(
				s.cryptoStream,
				s.connectionID,
				hostname,
				tlsConf,
				transportParams,
				paramsChan,
				aeadChanged,
				initialVersion,
				s.config.Versions,
				s.version,
			)
		} else {
			s.cryptoSetup, err = newCryptoSetupClient(
				s.cryptoStream,
				hostname,
				s.connectionID,
				s.version,
				tlsConf,
				transportParams,
				paramsChan,
				aeadChanged,
				initialVersion,
				negotiatedVersions,
			)
		}
	}
	if err != nil {
		return nil, nil, err
	}

	s.packer = newPacketPacker(s.connectionID,
		s.cryptoSetup,
		s.streamFramer,
		s.perspective,
		s.version,
	)
	s.unpacker = &packetUnpacker{aead: s.cryptoSetup, version: s.version}

	return s, handshakeChan, nil
}

// run the session main loop
func (s *session) run() error {
	defer s.ctxCancel()

	go func() {
		if err := s.cryptoSetup.HandleCryptoStream(); err != nil {
			s.Close(err)
		}
	}()

	var closeErr closeError
	aeadChanged := s.aeadChanged

runLoop:
	for {
		// Close immediately if requested
		select {
		case closeErr = <-s.closeChan:
			break runLoop
		default:
		}

		s.maybeResetTimer()

		select {
		case closeErr = <-s.closeChan:
			break runLoop
		case <-s.timer.Chan():
			s.timer.SetRead()
			// We do all the interesting stuff after the switch statement, so
			// nothing to see here.
		case <-s.sendingScheduled:
			// We do all the interesting stuff after the switch statement, so
			// nothing to see here.
		case p := <-s.receivedPackets:
			err := s.handlePacketImpl(p)
			if err != nil {
				if qErr, ok := err.(*qerr.QuicError); ok && qErr.ErrorCode == qerr.DecryptionFailure {
					s.tryQueueingUndecryptablePacket(p)
					continue
				}
				s.closeLocal(err)
				continue
			}
			// This is a bit unclean, but works properly, since the packet always
			// begins with the public header and we never copy it.
			putPacketBuffer(p.header.Raw)
		case p := <-s.paramsChan:
			s.processTransportParameters(&p)
		case l, ok := <-aeadChanged:
			if !ok { // the aeadChanged chan was closed. This means that the handshake is completed.
				s.handshakeComplete = true
				aeadChanged = nil // prevent this case from ever being selected again
				s.sentPacketHandler.SetHandshakeComplete()
				close(s.handshakeChan)
				close(s.handshakeCompleteChan)
			} else {
				s.tryDecryptingQueuedPackets()
				s.handshakeChan <- handshakeEvent{encLevel: l}
			}
		}

		now := time.Now()
		if timeout := s.sentPacketHandler.GetAlarmTimeout(); !timeout.IsZero() && timeout.Before(now) {
			// This could cause packets to be retransmitted, so check it before trying
			// to send packets.
			s.sentPacketHandler.OnAlarm()
		}

		if s.config.KeepAlive && s.handshakeComplete && time.Since(s.lastNetworkActivityTime) >= s.peerParams.IdleTimeout/2 {
			// send the PING frame since there is no activity in the session
			s.packer.QueueControlFrame(&wire.PingFrame{})
			s.keepAlivePingSent = true
		}

		if err := s.sendPacket(); err != nil {
			s.closeLocal(err)
		}
		if !s.receivedTooManyUndecrytablePacketsTime.IsZero() && s.receivedTooManyUndecrytablePacketsTime.Add(protocol.PublicResetTimeout).Before(now) && len(s.undecryptablePackets) != 0 {
			s.closeLocal(qerr.Error(qerr.DecryptionFailure, "too many undecryptable packets received"))
		}
		if !s.handshakeComplete && now.Sub(s.sessionCreationTime) >= s.config.HandshakeTimeout {
			s.closeLocal(qerr.Error(qerr.HandshakeTimeout, "Crypto handshake did not complete in time."))
		}
		if s.handshakeComplete && now.Sub(s.lastNetworkActivityTime) >= s.config.IdleTimeout {
			s.closeLocal(qerr.Error(qerr.NetworkIdleTimeout, "No recent network activity."))
		}

		if err := s.streamsMap.DeleteClosedStreams(); err != nil {
			s.closeLocal(err)
		}
	}

	// only send the error the handshakeChan when the handshake is not completed yet
	// otherwise this chan will already be closed
	if !s.handshakeComplete {
		s.handshakeCompleteChan <- closeErr.err
		s.handshakeChan <- handshakeEvent{err: closeErr.err}
	}
	s.handleCloseError(closeErr)
	return closeErr.err
}

func (s *session) Context() context.Context {
	return s.ctx
}

func (s *session) maybeResetTimer() {
	var deadline time.Time
	if s.config.KeepAlive && s.handshakeComplete && !s.keepAlivePingSent {
		deadline = s.lastNetworkActivityTime.Add(s.peerParams.IdleTimeout / 2)
	} else {
		deadline = s.lastNetworkActivityTime.Add(s.config.IdleTimeout)
	}

	if ackAlarm := s.receivedPacketHandler.GetAlarmTimeout(); !ackAlarm.IsZero() {
		deadline = utils.MinTime(deadline, ackAlarm)
	}
	if lossTime := s.sentPacketHandler.GetAlarmTimeout(); !lossTime.IsZero() {
		deadline = utils.MinTime(deadline, lossTime)
	}
	if !s.handshakeComplete {
		handshakeDeadline := s.sessionCreationTime.Add(s.config.HandshakeTimeout)
		deadline = utils.MinTime(deadline, handshakeDeadline)
	}
	if !s.receivedTooManyUndecrytablePacketsTime.IsZero() {
		deadline = utils.MinTime(deadline, s.receivedTooManyUndecrytablePacketsTime.Add(protocol.PublicResetTimeout))
	}

	s.timer.Reset(deadline)
}

func (s *session) handlePacketImpl(p *receivedPacket) error {
	if s.perspective == protocol.PerspectiveClient {
		diversificationNonce := p.header.DiversificationNonce
		if len(diversificationNonce) > 0 {
			s.cryptoSetup.SetDiversificationNonce(diversificationNonce)
		}
	}

	if p.rcvTime.IsZero() {
		// To simplify testing
		p.rcvTime = time.Now()
	}

	s.lastNetworkActivityTime = p.rcvTime
	s.keepAlivePingSent = false
	hdr := p.header
	data := p.data

	// Calculate packet number
	hdr.PacketNumber = protocol.InferPacketNumber(
		hdr.PacketNumberLen,
		s.largestRcvdPacketNumber,
		hdr.PacketNumber,
	)

	packet, err := s.unpacker.Unpack(hdr.Raw, hdr, data)
	if utils.Debug() {
		if err != nil {
			utils.Debugf("<- Reading packet 0x%x (%d bytes) for connection %x", hdr.PacketNumber, len(data)+len(hdr.Raw), hdr.ConnectionID)
		} else {
			utils.Debugf("<- Reading packet 0x%x (%d bytes) for connection %x, %s", hdr.PacketNumber, len(data)+len(hdr.Raw), hdr.ConnectionID, packet.encryptionLevel)
		}
		hdr.Log()
	}
	// if the decryption failed, this might be a packet sent by an attacker
	// don't update the remote address
	if quicErr, ok := err.(*qerr.QuicError); ok && quicErr.ErrorCode == qerr.DecryptionFailure {
		return err
	}
	if s.perspective == protocol.PerspectiveServer {
		// update the remote address, even if unpacking failed for any other reason than a decryption error
		s.conn.SetCurrentRemoteAddr(p.remoteAddr)
	}
	if err != nil {
		return err
	}

	s.lastRcvdPacketNumber = hdr.PacketNumber
	// Only do this after decrypting, so we are sure the packet is not attacker-controlled
	s.largestRcvdPacketNumber = utils.MaxPacketNumber(s.largestRcvdPacketNumber, hdr.PacketNumber)

	isRetransmittable := ackhandler.HasRetransmittableFrames(packet.frames)
	if err = s.receivedPacketHandler.ReceivedPacket(hdr.PacketNumber, isRetransmittable); err != nil {
		return err
	}

	return s.handleFrames(packet.frames, packet.encryptionLevel)
}

func (s *session) handleFrames(fs []wire.Frame, encLevel protocol.EncryptionLevel) error {
	for _, ff := range fs {
		var err error
		wire.LogFrame(ff, false)
		switch frame := ff.(type) {
		case *wire.StreamFrame:
			err = s.handleStreamFrame(frame)
		case *wire.AckFrame:
			err = s.handleAckFrame(frame, encLevel)
		case *wire.ConnectionCloseFrame:
			s.closeRemote(qerr.Error(frame.ErrorCode, frame.ReasonPhrase))
		case *wire.GoawayFrame:
			err = errors.New("unimplemented: handling GOAWAY frames")
		case *wire.StopWaitingFrame:
			// LeastUnacked is guaranteed to have LeastUnacked > 0
			// therefore this will never underflow
			s.receivedPacketHandler.SetLowerLimit(frame.LeastUnacked - 1)
		case *wire.RstStreamFrame:
			err = s.handleRstStreamFrame(frame)
		case *wire.MaxDataFrame:
			s.handleMaxDataFrame(frame)
		case *wire.MaxStreamDataFrame:
			err = s.handleMaxStreamDataFrame(frame)
		case *wire.BlockedFrame:
		case *wire.StreamBlockedFrame:
		case *wire.PingFrame:
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
func (s *session) handlePacket(p *receivedPacket) {
	// Discard packets once the amount of queued packets is larger than
	// the channel size, protocol.MaxSessionUnprocessedPackets
	select {
	case s.receivedPackets <- p:
	default:
	}
}

func (s *session) handleStreamFrame(frame *wire.StreamFrame) error {
	if frame.StreamID == s.version.CryptoStreamID() {
		return s.cryptoStream.AddStreamFrame(frame)
	}
	str, err := s.streamsMap.GetOrOpenStream(frame.StreamID)
	if err != nil {
		return err
	}
	if str == nil {
		// Stream is closed and already garbage collected
		// ignore this StreamFrame
		return nil
	}
	return str.AddStreamFrame(frame)
}

func (s *session) handleMaxDataFrame(frame *wire.MaxDataFrame) {
	s.connFlowController.UpdateSendWindow(frame.ByteOffset)
}

func (s *session) handleMaxStreamDataFrame(frame *wire.MaxStreamDataFrame) error {
	str, err := s.streamsMap.GetOrOpenStream(frame.StreamID)
	if err != nil {
		return err
	}
	if str == nil {
		return errWindowUpdateOnClosedStream
	}
	str.UpdateSendWindow(frame.ByteOffset)
	return nil
}

func (s *session) handleRstStreamFrame(frame *wire.RstStreamFrame) error {
	str, err := s.streamsMap.GetOrOpenStream(frame.StreamID)
	if err != nil {
		return err
	}
	if str == nil {
		return errRstStreamOnInvalidStream
	}
	return str.RegisterRemoteError(fmt.Errorf("RST_STREAM received with code %d", frame.ErrorCode), frame.ByteOffset)
}

func (s *session) handleAckFrame(frame *wire.AckFrame, encLevel protocol.EncryptionLevel) error {
	return s.sentPacketHandler.ReceivedAck(frame, s.lastRcvdPacketNumber, encLevel, s.lastNetworkActivityTime)
}

func (s *session) closeLocal(e error) {
	s.closeOnce.Do(func() {
		s.closeChan <- closeError{err: e, remote: false}
	})
}

func (s *session) closeRemote(e error) {
	s.closeOnce.Do(func() {
		s.closeChan <- closeError{err: e, remote: true}
	})
}

// Close the connection. If err is nil it will be set to qerr.PeerGoingAway.
// It waits until the run loop has stopped before returning
func (s *session) Close(e error) error {
	s.closeLocal(e)
	<-s.ctx.Done()
	return nil
}

func (s *session) handleCloseError(closeErr closeError) error {
	if closeErr.err == nil {
		closeErr.err = qerr.PeerGoingAway
	}

	var quicErr *qerr.QuicError
	var ok bool
	if quicErr, ok = closeErr.err.(*qerr.QuicError); !ok {
		quicErr = qerr.ToQuicError(closeErr.err)
	}
	// Don't log 'normal' reasons
	if quicErr.ErrorCode == qerr.PeerGoingAway || quicErr.ErrorCode == qerr.NetworkIdleTimeout {
		utils.Infof("Closing connection %x", s.connectionID)
	} else {
		utils.Errorf("Closing session with error: %s", closeErr.err.Error())
	}

	s.cryptoStream.Cancel(quicErr)
	s.streamsMap.CloseWithError(quicErr)

	if closeErr.err == errCloseSessionForNewVersion {
		return nil
	}

	// If this is a remote close we're done here
	if closeErr.remote {
		return nil
	}

	if quicErr.ErrorCode == qerr.DecryptionFailure ||
		quicErr == handshake.ErrHOLExperiment ||
		quicErr == handshake.ErrNSTPExperiment {
		return s.sendPublicReset(s.lastRcvdPacketNumber)
	}
	return s.sendConnectionClose(quicErr)
}

func (s *session) processTransportParameters(params *handshake.TransportParameters) {
	s.peerParams = params
	s.streamsMap.UpdateMaxStreamLimit(params.MaxStreams)
	if params.OmitConnectionID {
		s.packer.SetOmitConnectionID()
	}
	s.connFlowController.UpdateSendWindow(params.ConnectionFlowControlWindow)
	s.streamsMap.Range(func(str streamI) {
		str.UpdateSendWindow(params.StreamFlowControlWindow)
	})
}

func (s *session) sendPacket() error {
	s.packer.SetLeastUnacked(s.sentPacketHandler.GetLeastUnacked())

	// Get MAX_DATA and MAX_STREAM_DATA frames
	// this call triggers the flow controller to increase the flow control windows, if necessary
	windowUpdates := s.getWindowUpdates()
	for _, f := range windowUpdates {
		s.packer.QueueControlFrame(f)
	}

	ack := s.receivedPacketHandler.GetAckFrame()
	if ack != nil {
		s.packer.QueueControlFrame(ack)
	}

	// Repeatedly try sending until we don't have any more data, or run out of the congestion window
	for {
		if !s.sentPacketHandler.SendingAllowed() {
			if ack == nil {
				return nil
			}
			// If we aren't allowed to send, at least try sending an ACK frame
			swf := s.sentPacketHandler.GetStopWaitingFrame(false)
			if swf != nil {
				s.packer.QueueControlFrame(swf)
			}
			packet, err := s.packer.PackAckPacket()
			if err != nil {
				return err
			}
			return s.sendPackedPacket(packet)
		}

		// check for retransmissions first
		for {
			retransmitPacket := s.sentPacketHandler.DequeuePacketForRetransmission()
			if retransmitPacket == nil {
				break
			}

			if retransmitPacket.EncryptionLevel != protocol.EncryptionForwardSecure {
				if s.handshakeComplete {
					// Don't retransmit handshake packets when the handshake is complete
					continue
				}
				utils.Debugf("\tDequeueing handshake retransmission for packet 0x%x", retransmitPacket.PacketNumber)
				s.packer.QueueControlFrame(s.sentPacketHandler.GetStopWaitingFrame(true))
				packet, err := s.packer.PackHandshakeRetransmission(retransmitPacket)
				if err != nil {
					return err
				}
				if err = s.sendPackedPacket(packet); err != nil {
					return err
				}
			} else {
				utils.Debugf("\tDequeueing retransmission for packet 0x%x", retransmitPacket.PacketNumber)
				// resend the frames that were in the packet
				for _, frame := range retransmitPacket.GetFramesForRetransmission() {
					// TODO: only retransmit WINDOW_UPDATEs if they actually enlarge the window
					switch f := frame.(type) {
					case *wire.StreamFrame:
						s.streamFramer.AddFrameForRetransmission(f)
					default:
						s.packer.QueueControlFrame(frame)
					}
				}
			}
		}

		hasRetransmission := s.streamFramer.HasFramesForRetransmission()
		if ack != nil || hasRetransmission {
			swf := s.sentPacketHandler.GetStopWaitingFrame(hasRetransmission)
			if swf != nil {
				s.packer.QueueControlFrame(swf)
			}
		}
		// add a retransmittable frame
		if s.sentPacketHandler.ShouldSendRetransmittablePacket() {
			s.packer.QueueControlFrame(&wire.PingFrame{})
		}
		packet, err := s.packer.PackPacket()
		if err != nil || packet == nil {
			return err
		}
		if err = s.sendPackedPacket(packet); err != nil {
			return err
		}

		// send every window update twice
		for _, f := range windowUpdates {
			s.packer.QueueControlFrame(f)
		}
		windowUpdates = nil
		ack = nil
	}
}

func (s *session) sendPackedPacket(packet *packedPacket) error {
	defer putPacketBuffer(packet.raw)
	err := s.sentPacketHandler.SentPacket(&ackhandler.Packet{
		PacketNumber:    packet.header.PacketNumber,
		Frames:          packet.frames,
		Length:          protocol.ByteCount(len(packet.raw)),
		EncryptionLevel: packet.encryptionLevel,
	})
	if err != nil {
		return err
	}
	s.logPacket(packet)
	return s.conn.Write(packet.raw)
}

func (s *session) sendConnectionClose(quicErr *qerr.QuicError) error {
	s.packer.SetLeastUnacked(s.sentPacketHandler.GetLeastUnacked())
	packet, err := s.packer.PackConnectionClose(&wire.ConnectionCloseFrame{
		ErrorCode:    quicErr.ErrorCode,
		ReasonPhrase: quicErr.ErrorMessage,
	})
	if err != nil {
		return err
	}
	s.logPacket(packet)
	return s.conn.Write(packet.raw)
}

func (s *session) logPacket(packet *packedPacket) {
	if !utils.Debug() {
		// We don't need to allocate the slices for calling the format functions
		return
	}
	utils.Debugf("-> Sending packet 0x%x (%d bytes) for connection %x, %s", packet.header.PacketNumber, len(packet.raw), s.connectionID, packet.encryptionLevel)
	packet.header.Log()
	for _, frame := range packet.frames {
		wire.LogFrame(frame, true)
	}
}

// GetOrOpenStream either returns an existing stream, a newly opened stream, or nil if a stream with the provided ID is already closed.
// Newly opened streams should only originate from the client. To open a stream from the server, OpenStream should be used.
func (s *session) GetOrOpenStream(id protocol.StreamID) (Stream, error) {
	str, err := s.streamsMap.GetOrOpenStream(id)
	if str != nil {
		return str, err
	}
	// make sure to return an actual nil value here, not an Stream with value nil
	return nil, err
}

// AcceptStream returns the next stream openend by the peer
func (s *session) AcceptStream() (Stream, error) {
	return s.streamsMap.AcceptStream()
}

// OpenStream opens a stream
func (s *session) OpenStream() (Stream, error) {
	return s.streamsMap.OpenStream()
}

func (s *session) OpenStreamSync() (Stream, error) {
	return s.streamsMap.OpenStreamSync()
}

func (s *session) WaitUntilHandshakeComplete() error {
	return <-s.handshakeCompleteChan
}

func (s *session) queueResetStreamFrame(id protocol.StreamID, offset protocol.ByteCount) {
	s.packer.QueueControlFrame(&wire.RstStreamFrame{
		StreamID:   id,
		ByteOffset: offset,
	})
	s.scheduleSending()
}

func (s *session) newStream(id protocol.StreamID) streamI {
	var initialSendWindow protocol.ByteCount
	if s.peerParams != nil {
		initialSendWindow = s.peerParams.StreamFlowControlWindow
	}
	flowController := flowcontrol.NewStreamFlowController(
		id,
		s.version.StreamContributesToConnectionFlowControl(id),
		s.connFlowController,
		protocol.ReceiveStreamFlowControlWindow,
		protocol.ByteCount(s.config.MaxReceiveStreamFlowControlWindow),
		initialSendWindow,
		s.rttStats,
	)
	return newStream(id, s.scheduleSending, s.queueResetStreamFrame, flowController, s.version)
}

func (s *session) sendPublicReset(rejectedPacketNumber protocol.PacketNumber) error {
	utils.Infof("Sending public reset for connection %x, packet number %d", s.connectionID, rejectedPacketNumber)
	return s.conn.Write(wire.WritePublicReset(s.connectionID, rejectedPacketNumber, 0))
}

// scheduleSending signals that we have data for sending
func (s *session) scheduleSending() {
	select {
	case s.sendingScheduled <- struct{}{}:
	default:
	}
}

func (s *session) tryQueueingUndecryptablePacket(p *receivedPacket) {
	if s.handshakeComplete {
		utils.Debugf("Received undecryptable packet from %s after the handshake: %#v, %d bytes data", p.remoteAddr.String(), p.header, len(p.data))
		return
	}
	if len(s.undecryptablePackets)+1 > protocol.MaxUndecryptablePackets {
		// if this is the first time the undecryptablePackets runs full, start the timer to send a Public Reset
		if s.receivedTooManyUndecrytablePacketsTime.IsZero() {
			s.receivedTooManyUndecrytablePacketsTime = time.Now()
			s.maybeResetTimer()
		}
		utils.Infof("Dropping undecrytable packet 0x%x (undecryptable packet queue full)", p.header.PacketNumber)
		return
	}
	utils.Infof("Queueing packet 0x%x for later decryption", p.header.PacketNumber)
	s.undecryptablePackets = append(s.undecryptablePackets, p)
}

func (s *session) tryDecryptingQueuedPackets() {
	for _, p := range s.undecryptablePackets {
		s.handlePacket(p)
	}
	s.undecryptablePackets = s.undecryptablePackets[:0]
}

func (s *session) getWindowUpdates() []wire.Frame {
	var res []wire.Frame
	s.streamsMap.Range(func(str streamI) {
		if offset := str.GetWindowUpdate(); offset != 0 {
			res = append(res, &wire.MaxStreamDataFrame{
				StreamID:   str.StreamID(),
				ByteOffset: offset,
			})
		}
	})
	if offset := s.connFlowController.GetWindowUpdate(); offset != 0 {
		res = append(res, &wire.MaxDataFrame{
			ByteOffset: offset,
		})
	}
	return res
}

func (s *session) LocalAddr() net.Addr {
	return s.conn.LocalAddr()
}

// RemoteAddr returns the net.Addr of the client
func (s *session) RemoteAddr() net.Addr {
	return s.conn.RemoteAddr()
}

func (s *session) GetVersion() protocol.VersionNumber {
	return s.version
}
