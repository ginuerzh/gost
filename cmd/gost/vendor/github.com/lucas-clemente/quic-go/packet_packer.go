package quic

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/handshake"
	"github.com/lucas-clemente/quic-go/protocol"
)

type packedPacket struct {
	number protocol.PacketNumber
	raw    []byte
	frames []frames.Frame
}

type packetPacker struct {
	connectionID protocol.ConnectionID
	version      protocol.VersionNumber
	cryptoSetup  *handshake.CryptoSetup

	packetNumberGenerator *packetNumberGenerator

	connectionParametersManager *handshake.ConnectionParametersManager

	streamFramer  *streamFramer
	controlFrames []frames.Frame
}

func newPacketPacker(connectionID protocol.ConnectionID, cryptoSetup *handshake.CryptoSetup, connectionParametersHandler *handshake.ConnectionParametersManager, streamFramer *streamFramer, version protocol.VersionNumber) *packetPacker {
	return &packetPacker{
		cryptoSetup:                 cryptoSetup,
		connectionID:                connectionID,
		connectionParametersManager: connectionParametersHandler,
		version:                     version,
		streamFramer:                streamFramer,
		packetNumberGenerator:       newPacketNumberGenerator(protocol.SkipPacketAveragePeriodLength),
	}
}

func (p *packetPacker) PackConnectionClose(frame *frames.ConnectionCloseFrame, leastUnacked protocol.PacketNumber) (*packedPacket, error) {
	return p.packPacket(nil, []frames.Frame{frame}, leastUnacked, true, false)
}

func (p *packetPacker) PackPacket(stopWaitingFrame *frames.StopWaitingFrame, controlFrames []frames.Frame, leastUnacked protocol.PacketNumber, maySendOnlyAck bool) (*packedPacket, error) {
	return p.packPacket(stopWaitingFrame, controlFrames, leastUnacked, false, maySendOnlyAck)
}

func (p *packetPacker) packPacket(stopWaitingFrame *frames.StopWaitingFrame, controlFrames []frames.Frame, leastUnacked protocol.PacketNumber, onlySendOneControlFrame, maySendOnlyAck bool) (*packedPacket, error) {
	if len(controlFrames) > 0 {
		p.controlFrames = append(p.controlFrames, controlFrames...)
	}

	currentPacketNumber := p.packetNumberGenerator.Peek()

	// cryptoSetup needs to be locked here, so that the AEADs are not changed between
	// calling DiversificationNonce() and Seal().
	p.cryptoSetup.LockForSealing()
	defer p.cryptoSetup.UnlockForSealing()

	packetNumberLen := protocol.GetPacketNumberLengthForPublicHeader(currentPacketNumber, leastUnacked)
	responsePublicHeader := &PublicHeader{
		ConnectionID:         p.connectionID,
		PacketNumber:         currentPacketNumber,
		PacketNumberLen:      packetNumberLen,
		TruncateConnectionID: p.connectionParametersManager.TruncateConnectionID(),
		DiversificationNonce: p.cryptoSetup.DiversificationNonce(),
	}

	publicHeaderLength, err := responsePublicHeader.GetLength()
	if err != nil {
		return nil, err
	}

	if stopWaitingFrame != nil {
		stopWaitingFrame.PacketNumber = currentPacketNumber
		stopWaitingFrame.PacketNumberLen = packetNumberLen
	}

	var payloadFrames []frames.Frame
	if onlySendOneControlFrame {
		payloadFrames = []frames.Frame{controlFrames[0]}
	} else {
		payloadFrames, err = p.composeNextPacket(stopWaitingFrame, publicHeaderLength)
		if err != nil {
			return nil, err
		}
	}

	// Check if we have enough frames to send
	if len(payloadFrames) == 0 {
		return nil, nil
	}
	// Don't send out packets that only contain a StopWaitingFrame
	if !onlySendOneControlFrame && len(payloadFrames) == 1 && stopWaitingFrame != nil {
		return nil, nil
	}
	// Don't send out packets that only contain an ACK (plus optional STOP_WAITING), if requested
	if !maySendOnlyAck {
		if len(payloadFrames) == 1 {
			if _, ok := payloadFrames[0].(*frames.AckFrame); ok {
				return nil, nil
			}
		} else if len(payloadFrames) == 2 && stopWaitingFrame != nil {
			if _, ok := payloadFrames[1].(*frames.AckFrame); ok {
				return nil, nil
			}
		}
	}

	raw := getPacketBuffer()
	buffer := bytes.NewBuffer(raw)

	if err = responsePublicHeader.WritePublicHeader(buffer, p.version); err != nil {
		return nil, err
	}

	payloadStartIndex := buffer.Len()

	for _, frame := range payloadFrames {
		err := frame.Write(buffer, p.version)
		if err != nil {
			return nil, err
		}
	}

	if protocol.ByteCount(buffer.Len()+12) > protocol.MaxPacketSize {
		return nil, errors.New("PacketPacker BUG: packet too large")
	}

	raw = raw[0:buffer.Len()]
	p.cryptoSetup.Seal(raw[payloadStartIndex:payloadStartIndex], raw[payloadStartIndex:], currentPacketNumber, raw[:payloadStartIndex])
	raw = raw[0 : buffer.Len()+12]

	num := p.packetNumberGenerator.Pop()
	if num != currentPacketNumber {
		return nil, errors.New("PacketPacker BUG: Peeked and Popped packet numbers do not match.")
	}

	return &packedPacket{
		number: currentPacketNumber,
		raw:    raw,
		frames: payloadFrames,
	}, nil
}

func (p *packetPacker) composeNextPacket(stopWaitingFrame *frames.StopWaitingFrame, publicHeaderLength protocol.ByteCount) ([]frames.Frame, error) {
	var payloadLength protocol.ByteCount
	var payloadFrames []frames.Frame

	maxFrameSize := protocol.MaxFrameAndPublicHeaderSize - publicHeaderLength

	if stopWaitingFrame != nil {
		payloadFrames = append(payloadFrames, stopWaitingFrame)
		minLength, err := stopWaitingFrame.MinLength(p.version)
		if err != nil {
			return nil, err
		}
		payloadLength += minLength
	}

	for len(p.controlFrames) > 0 {
		frame := p.controlFrames[len(p.controlFrames)-1]
		minLength, _ := frame.MinLength(p.version) // controlFrames does not contain any StopWaitingFrames. So it will *never* return an error
		if payloadLength+minLength > maxFrameSize {
			break
		}
		payloadFrames = append(payloadFrames, frame)
		payloadLength += minLength
		p.controlFrames = p.controlFrames[:len(p.controlFrames)-1]
	}

	if payloadLength > maxFrameSize {
		return nil, fmt.Errorf("Packet Packer BUG: packet payload (%d) too large (%d)", payloadLength, maxFrameSize)
	}

	// temporarily increase the maxFrameSize by 2 bytes
	// this leads to a properly sized packet in all cases, since we do all the packet length calculations with StreamFrames that have the DataLen set
	// however, for the last StreamFrame in the packet, we can omit the DataLen, thus saving 2 bytes and yielding a packet of exactly the correct size
	maxFrameSize += 2

	fs := p.streamFramer.PopStreamFrames(maxFrameSize - payloadLength)
	if len(fs) != 0 {
		fs[len(fs)-1].DataLenPresent = false
	}

	// TODO: Simplify
	for _, f := range fs {
		payloadFrames = append(payloadFrames, f)
	}

	for b := p.streamFramer.PopBlockedFrame(); b != nil; b = p.streamFramer.PopBlockedFrame() {
		p.controlFrames = append(p.controlFrames, b)
	}

	return payloadFrames, nil
}

func (p *packetPacker) QueueControlFrameForNextPacket(f frames.Frame) {
	p.controlFrames = append(p.controlFrames, f)
}
