package ackhandler

import (
	"time"

	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/protocol"
)

// SentPacketHandler handles ACKs received for outgoing packets
type SentPacketHandler interface {
	SentPacket(packet *Packet) error
	ReceivedAck(ackFrame *frames.AckFrame, withPacketNumber protocol.PacketNumber, recvTime time.Time) error

	GetStopWaitingFrame(force bool) *frames.StopWaitingFrame

	MaybeQueueRTOs()
	DequeuePacketForRetransmission() (packet *Packet)

	BytesInFlight() protocol.ByteCount
	GetLeastUnacked() protocol.PacketNumber

	SendingAllowed() bool
	CheckForError() error

	TimeOfFirstRTO() time.Time
}

// ReceivedPacketHandler handles ACKs needed to send for incoming packets
type ReceivedPacketHandler interface {
	ReceivedPacket(packetNumber protocol.PacketNumber, shouldInstigateAck bool) error
	ReceivedStopWaiting(*frames.StopWaitingFrame) error

	GetAckFrame() *frames.AckFrame
}
