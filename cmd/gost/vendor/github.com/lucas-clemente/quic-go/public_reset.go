package quic

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/handshake"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/utils"
)

func writePublicReset(connectionID protocol.ConnectionID, rejectedPacketNumber protocol.PacketNumber, nonceProof uint64) []byte {
	b := &bytes.Buffer{}
	b.WriteByte(0x0a)
	utils.WriteUint64(b, uint64(connectionID))
	utils.WriteUint32(b, uint32(handshake.TagPRST))
	utils.WriteUint32(b, 2)
	utils.WriteUint32(b, uint32(handshake.TagRNON))
	utils.WriteUint32(b, 8)
	utils.WriteUint32(b, uint32(handshake.TagRSEQ))
	utils.WriteUint32(b, 16)
	utils.WriteUint64(b, nonceProof)
	utils.WriteUint64(b, uint64(rejectedPacketNumber))
	return b.Bytes()
}
