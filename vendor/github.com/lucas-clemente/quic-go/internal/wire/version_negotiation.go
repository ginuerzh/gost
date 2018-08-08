package wire

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

// ComposeGQUICVersionNegotiation composes a Version Negotiation Packet for gQUIC
func ComposeGQUICVersionNegotiation(connID protocol.ConnectionID, versions []protocol.VersionNumber) []byte {
	fullReply := &bytes.Buffer{}
	ph := Header{
		ConnectionID: connID,
		PacketNumber: 1,
		VersionFlag:  true,
	}
	if err := ph.writePublicHeader(fullReply, protocol.PerspectiveServer, protocol.VersionWhatever); err != nil {
		utils.Errorf("error composing version negotiation packet: %s", err.Error())
		return nil
	}
	for _, v := range versions {
		utils.BigEndian.WriteUint32(fullReply, uint32(v))
	}
	return fullReply.Bytes()
}

// ComposeVersionNegotiation composes a Version Negotiation according to the IETF draft
func ComposeVersionNegotiation(
	connID protocol.ConnectionID,
	pn protocol.PacketNumber,
	versionOffered protocol.VersionNumber,
	versions []protocol.VersionNumber,
) []byte {
	fullReply := &bytes.Buffer{}
	ph := Header{
		IsLongHeader: true,
		Type:         protocol.PacketTypeVersionNegotiation,
		ConnectionID: connID,
		PacketNumber: pn,
		Version:      versionOffered,
	}
	if err := ph.writeHeader(fullReply); err != nil {
		utils.Errorf("error composing version negotiation packet: %s", err.Error())
		return nil
	}
	for _, v := range versions {
		utils.BigEndian.WriteUint32(fullReply, uint32(v))
	}
	return fullReply.Bytes()
}
