package congestion

import "github.com/lucas-clemente/quic-go/protocol"

// PacketInfo combines packet number and length of a packet for congestion calculation
type PacketInfo struct {
	Number protocol.PacketNumber
	Length protocol.ByteCount
}

// PacketVector is passed to the congestion algorithm
type PacketVector []PacketInfo
