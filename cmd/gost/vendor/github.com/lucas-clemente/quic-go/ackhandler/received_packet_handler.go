package ackhandler

import (
	"errors"
	"time"

	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
)

var (
	// ErrDuplicatePacket occurres when a duplicate packet is received
	ErrDuplicatePacket = errors.New("ReceivedPacketHandler: Duplicate Packet")
	// ErrMapAccess occurs when a NACK contains invalid NACK ranges
	ErrMapAccess = qerr.Error(qerr.InvalidAckData, "Packet does not exist in PacketHistory")
	// ErrPacketSmallerThanLastStopWaiting occurs when a packet arrives with a packet number smaller than the largest LeastUnacked of a StopWaitingFrame. If this error occurs, the packet should be ignored
	ErrPacketSmallerThanLastStopWaiting = errors.New("ReceivedPacketHandler: Packet number smaller than highest StopWaiting")
)

var (
	errInvalidPacketNumber               = errors.New("ReceivedPacketHandler: Invalid packet number")
	errTooManyOutstandingReceivedPackets = qerr.Error(qerr.TooManyOutstandingReceivedPackets, "")
)

type receivedPacketHandler struct {
	largestInOrderObserved protocol.PacketNumber
	largestObserved        protocol.PacketNumber
	ignorePacketsBelow     protocol.PacketNumber
	currentAckFrame        *frames.AckFrame
	stateChanged           bool // has an ACK for this state already been sent? Will be set to false every time a new packet arrives, and to false every time an ACK is sent

	packetHistory *receivedPacketHistory

	receivedTimes         map[protocol.PacketNumber]time.Time
	lowestInReceivedTimes protocol.PacketNumber
}

// NewReceivedPacketHandler creates a new receivedPacketHandler
func NewReceivedPacketHandler() ReceivedPacketHandler {
	return &receivedPacketHandler{
		receivedTimes: make(map[protocol.PacketNumber]time.Time),
		packetHistory: newReceivedPacketHistory(),
	}
}

func (h *receivedPacketHandler) ReceivedPacket(packetNumber protocol.PacketNumber) error {
	if packetNumber == 0 {
		return errInvalidPacketNumber
	}

	// if the packet number is smaller than the largest LeastUnacked value of a StopWaiting we received, we cannot detect if this packet has a duplicate number
	// the packet has to be ignored anyway
	if packetNumber <= h.ignorePacketsBelow {
		return ErrPacketSmallerThanLastStopWaiting
	}

	_, ok := h.receivedTimes[packetNumber]
	if packetNumber <= h.largestInOrderObserved || ok {
		return ErrDuplicatePacket
	}

	h.packetHistory.ReceivedPacket(packetNumber)

	h.stateChanged = true
	h.currentAckFrame = nil

	if packetNumber > h.largestObserved {
		h.largestObserved = packetNumber
	}

	if packetNumber == h.largestInOrderObserved+1 {
		h.largestInOrderObserved = packetNumber
	}

	h.receivedTimes[packetNumber] = time.Now()

	if protocol.PacketNumber(len(h.receivedTimes)) > protocol.MaxTrackedReceivedPackets {
		return errTooManyOutstandingReceivedPackets
	}

	return nil
}

func (h *receivedPacketHandler) ReceivedStopWaiting(f *frames.StopWaitingFrame) error {
	// ignore if StopWaiting is unneeded, because we already received a StopWaiting with a higher LeastUnacked
	if h.ignorePacketsBelow >= f.LeastUnacked {
		return nil
	}

	h.ignorePacketsBelow = f.LeastUnacked - 1
	h.garbageCollectReceivedTimes()

	// the LeastUnacked is the smallest packet number of any packet for which the sender is still awaiting an ack. So the largestInOrderObserved is one less than that
	if f.LeastUnacked > h.largestInOrderObserved {
		h.largestInOrderObserved = f.LeastUnacked - 1
	}

	h.packetHistory.DeleteBelow(f.LeastUnacked)

	return nil
}

func (h *receivedPacketHandler) GetAckFrame(dequeue bool) (*frames.AckFrame, error) {
	if !h.stateChanged {
		return nil, nil
	}

	if dequeue {
		h.stateChanged = false
	}

	if h.currentAckFrame != nil {
		return h.currentAckFrame, nil
	}

	packetReceivedTime, ok := h.receivedTimes[h.largestObserved]
	if !ok {
		return nil, ErrMapAccess
	}

	ackRanges := h.packetHistory.GetAckRanges()
	h.currentAckFrame = &frames.AckFrame{
		LargestAcked:       h.largestObserved,
		LowestAcked:        ackRanges[len(ackRanges)-1].FirstPacketNumber,
		PacketReceivedTime: packetReceivedTime,
	}

	if len(ackRanges) > 1 {
		h.currentAckFrame.AckRanges = ackRanges
	}

	return h.currentAckFrame, nil
}

func (h *receivedPacketHandler) garbageCollectReceivedTimes() {
	for i := h.lowestInReceivedTimes; i <= h.ignorePacketsBelow; i++ {
		delete(h.receivedTimes, i)
	}
	if h.ignorePacketsBelow > h.lowestInReceivedTimes {
		h.lowestInReceivedTimes = h.ignorePacketsBelow + 1
	}
}
