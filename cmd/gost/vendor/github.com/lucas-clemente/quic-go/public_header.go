package quic

import (
	"bytes"
	"errors"
	"io"

	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
	"github.com/lucas-clemente/quic-go/utils"
)

var (
	errPacketNumberLenNotSet          = errors.New("PublicHeader: PacketNumberLen not set")
	errResetAndVersionFlagSet         = errors.New("PublicHeader: Reset Flag and Version Flag should not be set at the same time")
	errReceivedTruncatedConnectionID  = qerr.Error(qerr.InvalidPacketHeader, "receiving packets with truncated ConnectionID is not supported")
	errInvalidConnectionID            = qerr.Error(qerr.InvalidPacketHeader, "connection ID cannot be 0")
	errGetLengthOnlyForRegularPackets = errors.New("PublicHeader: GetLength can only be called for regular packets")
)

// The PublicHeader of a QUIC packet
type PublicHeader struct {
	Raw                  []byte
	ConnectionID         protocol.ConnectionID
	VersionFlag          bool
	ResetFlag            bool
	TruncateConnectionID bool
	PacketNumberLen      protocol.PacketNumberLen
	PacketNumber         protocol.PacketNumber
	VersionNumber        protocol.VersionNumber
	DiversificationNonce []byte
}

// WritePublicHeader writes a public header
func (h *PublicHeader) WritePublicHeader(b *bytes.Buffer, version protocol.VersionNumber) error {
	publicFlagByte := uint8(0x00)
	if h.VersionFlag && h.ResetFlag {
		return errResetAndVersionFlagSet
	}
	if h.VersionFlag {
		publicFlagByte |= 0x01
	}
	if h.ResetFlag {
		publicFlagByte |= 0x02
	}
	if !h.TruncateConnectionID {
		publicFlagByte |= 0x08
	}

	if len(h.DiversificationNonce) > 0 {
		if len(h.DiversificationNonce) != 32 {
			return errors.New("invalid diversification nonce length")
		}
		publicFlagByte |= 0x04
	}

	if !h.ResetFlag && !h.VersionFlag {
		switch h.PacketNumberLen {
		case protocol.PacketNumberLen1:
			publicFlagByte |= 0x00
		case protocol.PacketNumberLen2:
			publicFlagByte |= 0x10
		case protocol.PacketNumberLen4:
			publicFlagByte |= 0x20
		case protocol.PacketNumberLen6:
			publicFlagByte |= 0x30
		}
	}

	b.WriteByte(publicFlagByte)

	if !h.TruncateConnectionID {
		utils.WriteUint64(b, uint64(h.ConnectionID))
	}

	if len(h.DiversificationNonce) > 0 {
		b.Write(h.DiversificationNonce)
	}

	if !h.ResetFlag && !h.VersionFlag {
		switch h.PacketNumberLen {
		case protocol.PacketNumberLen1:
			b.WriteByte(uint8(h.PacketNumber))
		case protocol.PacketNumberLen2:
			utils.WriteUint16(b, uint16(h.PacketNumber))
		case protocol.PacketNumberLen4:
			utils.WriteUint32(b, uint32(h.PacketNumber))
		case protocol.PacketNumberLen6:
			utils.WriteUint48(b, uint64(h.PacketNumber))
		default:
			return errPacketNumberLenNotSet
		}
	}

	return nil
}

// ParsePublicHeader parses a QUIC packet's public header
func ParsePublicHeader(b io.ByteReader) (*PublicHeader, error) {
	header := &PublicHeader{}

	// First byte
	publicFlagByte, err := b.ReadByte()
	if err != nil {
		return nil, err
	}
	header.VersionFlag = publicFlagByte&0x01 > 0
	header.ResetFlag = publicFlagByte&0x02 > 0

	// TODO: activate this check once Chrome sends the correct value
	// see https://github.com/lucas-clemente/quic-go/issues/232
	// if publicFlagByte&0x04 > 0 {
	// 	return nil, errors.New("diversification nonces should only be sent by servers")
	// }

	if publicFlagByte&0x08 == 0 {
		return nil, errReceivedTruncatedConnectionID
	}

	switch publicFlagByte & 0x30 {
	case 0x30:
		header.PacketNumberLen = protocol.PacketNumberLen6
	case 0x20:
		header.PacketNumberLen = protocol.PacketNumberLen4
	case 0x10:
		header.PacketNumberLen = protocol.PacketNumberLen2
	case 0x00:
		header.PacketNumberLen = protocol.PacketNumberLen1
	}

	// Connection ID
	connID, err := utils.ReadUint64(b)
	if err != nil {
		return nil, err
	}
	header.ConnectionID = protocol.ConnectionID(connID)
	if header.ConnectionID == 0 {
		return nil, errInvalidConnectionID
	}

	// Version (optional)
	if header.VersionFlag {
		var versionTag uint32
		versionTag, err = utils.ReadUint32(b)
		if err != nil {
			return nil, err
		}
		header.VersionNumber = protocol.VersionTagToNumber(versionTag)
	}

	// Packet number
	packetNumber, err := utils.ReadUintN(b, uint8(header.PacketNumberLen))
	if err != nil {
		return nil, err
	}
	header.PacketNumber = protocol.PacketNumber(packetNumber)

	return header, nil
}

// GetLength gets the length of the publicHeader in bytes
// can only be called for regular packets
func (h *PublicHeader) GetLength() (protocol.ByteCount, error) {
	if h.VersionFlag || h.ResetFlag {
		return 0, errGetLengthOnlyForRegularPackets
	}

	length := protocol.ByteCount(1) // 1 byte for public flags
	if h.PacketNumberLen != protocol.PacketNumberLen1 && h.PacketNumberLen != protocol.PacketNumberLen2 && h.PacketNumberLen != protocol.PacketNumberLen4 && h.PacketNumberLen != protocol.PacketNumberLen6 {
		return 0, errPacketNumberLenNotSet
	}
	if !h.TruncateConnectionID {
		length += 8 // 8 bytes for the connection ID
	}
	length += protocol.ByteCount(len(h.DiversificationNonce))
	length += protocol.ByteCount(h.PacketNumberLen)
	return length, nil
}
