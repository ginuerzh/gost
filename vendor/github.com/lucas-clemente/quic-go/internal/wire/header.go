package wire

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
)

// Header is the header of a QUIC packet.
// It contains fields that are only needed for the gQUIC Public Header and the IETF draft Header.
type Header struct {
	Raw               []byte
	ConnectionID      protocol.ConnectionID
	OmitConnectionID  bool
	PacketNumberLen   protocol.PacketNumberLen
	PacketNumber      protocol.PacketNumber
	Version           protocol.VersionNumber   // VersionNumber sent by the client
	SupportedVersions []protocol.VersionNumber // Version Number sent in a Version Negotiation Packet by the server

	// only needed for the gQUIC Public Header
	VersionFlag          bool
	ResetFlag            bool
	DiversificationNonce []byte

	// only needed for the IETF Header
	Type         protocol.PacketType
	IsLongHeader bool
	KeyPhase     int

	// only needed for logging
	isPublicHeader bool
}

// ParseHeaderSentByServer parses the header for a packet that was sent by the server.
func ParseHeaderSentByServer(b *bytes.Reader, version protocol.VersionNumber) (*Header, error) {
	typeByte, err := b.ReadByte()
	if err != nil {
		return nil, err
	}
	_ = b.UnreadByte() // unread the type byte

	var isPublicHeader bool
	// As a client, we know the version of the packet that the server sent, except for Version Negotiation Packets.
	if typeByte == 0x81 { // IETF draft Version Negotiation Packet
		isPublicHeader = false
	} else if typeByte&0xcf == 0x9 { // gQUIC Version Negotiation Packet
		// IETF QUIC Version Negotiation Packets are sent with the Long Header (indicated by the 0x80 bit)
		// gQUIC always has 0x80 unset
		isPublicHeader = true
	} else { // not a Version Negotiation Packet
		// the client knows the version that this packet was sent with
		isPublicHeader = !version.UsesTLS()
	}
	return parsePacketHeader(b, protocol.PerspectiveServer, isPublicHeader)
}

// ParseHeaderSentByClient parses the header for a packet that was sent by the client.
func ParseHeaderSentByClient(b *bytes.Reader) (*Header, error) {
	typeByte, err := b.ReadByte()
	if err != nil {
		return nil, err
	}
	_ = b.UnreadByte() // unread the type byte

	// If this is a gQUIC header 0x80 and 0x40 will be set to 0.
	// If this is an IETF QUIC header there are two options:
	// * either 0x80 will be 1 (for the Long Header)
	// * or 0x40 (the Connection ID Flag) will be 0 (for the Short Header), since we don't the client to omit it
	isPublicHeader := typeByte&0xc0 == 0

	return parsePacketHeader(b, protocol.PerspectiveClient, isPublicHeader)
}

func parsePacketHeader(b *bytes.Reader, sentBy protocol.Perspective, isPublicHeader bool) (*Header, error) {
	// This is a gQUIC Public Header.
	if isPublicHeader {
		hdr, err := parsePublicHeader(b, sentBy)
		if err != nil {
			return nil, err
		}
		hdr.isPublicHeader = true // save that this is a Public Header, so we can log it correctly later
		return hdr, nil
	}
	return parseHeader(b, sentBy)
}

// Write writes the Header.
func (h *Header) Write(b *bytes.Buffer, pers protocol.Perspective, version protocol.VersionNumber) error {
	if !version.UsesTLS() {
		h.isPublicHeader = true // save that this is a Public Header, so we can log it correctly later
		return h.writePublicHeader(b, pers, version)
	}
	return h.writeHeader(b)
}

// GetLength determines the length of the Header.
func (h *Header) GetLength(pers protocol.Perspective, version protocol.VersionNumber) (protocol.ByteCount, error) {
	if !version.UsesTLS() {
		return h.getPublicHeaderLength(pers)
	}
	return h.getHeaderLength()
}

// Log logs the Header
func (h *Header) Log() {
	if h.isPublicHeader {
		h.logPublicHeader()
	} else {
		h.logHeader()
	}
}
