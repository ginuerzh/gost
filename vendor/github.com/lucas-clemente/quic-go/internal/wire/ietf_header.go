package wire

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/qerr"
)

// parseHeader parses the header.
func parseHeader(b *bytes.Reader) (*Header, error) {
	typeByte, err := b.ReadByte()
	if err != nil {
		return nil, err
	}
	if typeByte&0x80 > 0 {
		return parseLongHeader(b, typeByte)
	}
	return parseShortHeader(b, typeByte)
}

// parse long header and version negotiation packets
func parseLongHeader(b *bytes.Reader, typeByte byte) (*Header, error) {
	v, err := utils.BigEndian.ReadUint32(b)
	if err != nil {
		return nil, err
	}

	connIDLenByte, err := b.ReadByte()
	if err != nil {
		return nil, err
	}
	dcil, scil := decodeConnIDLen(connIDLenByte)
	destConnID, err := protocol.ReadConnectionID(b, dcil)
	if err != nil {
		return nil, err
	}
	srcConnID, err := protocol.ReadConnectionID(b, scil)
	if err != nil {
		return nil, err
	}

	h := &Header{
		IsLongHeader:     true,
		Version:          protocol.VersionNumber(v),
		DestConnectionID: destConnID,
		SrcConnectionID:  srcConnID,
	}

	if v == 0 { // version negotiation packet
		if b.Len() == 0 {
			return nil, qerr.Error(qerr.InvalidVersionNegotiationPacket, "empty version list")
		}
		h.IsVersionNegotiation = true
		h.SupportedVersions = make([]protocol.VersionNumber, b.Len()/4)
		for i := 0; b.Len() > 0; i++ {
			v, err := utils.BigEndian.ReadUint32(b)
			if err != nil {
				return nil, qerr.InvalidVersionNegotiationPacket
			}
			h.SupportedVersions[i] = protocol.VersionNumber(v)
		}
		return h, nil
	}

	pl, err := utils.ReadVarInt(b)
	if err != nil {
		return nil, err
	}
	h.PayloadLen = protocol.ByteCount(pl)
	pn, err := utils.BigEndian.ReadUint32(b)
	if err != nil {
		return nil, err
	}
	h.PacketNumber = protocol.PacketNumber(pn)
	h.PacketNumberLen = protocol.PacketNumberLen4
	h.Type = protocol.PacketType(typeByte & 0x7f)

	if h.Type != protocol.PacketTypeInitial && h.Type != protocol.PacketTypeRetry && h.Type != protocol.PacketType0RTT && h.Type != protocol.PacketTypeHandshake {
		return nil, qerr.Error(qerr.InvalidPacketHeader, fmt.Sprintf("Received packet with invalid packet type: %d", h.Type))
	}
	return h, nil
}

func parseShortHeader(b *bytes.Reader, typeByte byte) (*Header, error) {
	connID := make(protocol.ConnectionID, 8)
	if _, err := io.ReadFull(b, connID); err != nil {
		if err == io.ErrUnexpectedEOF {
			err = io.EOF
		}
		return nil, err
	}
	// bits 2 and 3 must be set, bit 4 must be unset
	if typeByte&0x38 != 0x30 {
		return nil, errors.New("invalid bits 3, 4 and 5")
	}
	var pnLen protocol.PacketNumberLen
	switch typeByte & 0x3 {
	case 0x0:
		pnLen = protocol.PacketNumberLen1
	case 0x1:
		pnLen = protocol.PacketNumberLen2
	case 0x2:
		pnLen = protocol.PacketNumberLen4
	default:
		return nil, errors.New("invalid short header type")
	}
	pn, err := utils.BigEndian.ReadUintN(b, uint8(pnLen))
	if err != nil {
		return nil, err
	}
	return &Header{
		KeyPhase:         int(typeByte&0x40) >> 6,
		DestConnectionID: connID,
		PacketNumber:     protocol.PacketNumber(pn),
		PacketNumberLen:  pnLen,
	}, nil
}

// writeHeader writes the Header.
func (h *Header) writeHeader(b *bytes.Buffer) error {
	if h.IsLongHeader {
		return h.writeLongHeader(b)
	}
	return h.writeShortHeader(b)
}

// TODO: add support for the key phase
func (h *Header) writeLongHeader(b *bytes.Buffer) error {
	if h.SrcConnectionID.Len() != protocol.ConnectionIDLen {
		return fmt.Errorf("Header: source connection ID must be %d bytes, is %d", protocol.ConnectionIDLen, h.SrcConnectionID.Len())
	}
	b.WriteByte(byte(0x80 | h.Type))
	utils.BigEndian.WriteUint32(b, uint32(h.Version))
	connIDLen, err := encodeConnIDLen(h.DestConnectionID, h.SrcConnectionID)
	if err != nil {
		return err
	}
	b.WriteByte(connIDLen)
	b.Write(h.DestConnectionID.Bytes())
	b.Write(h.SrcConnectionID.Bytes())
	utils.WriteVarInt(b, uint64(h.PayloadLen))
	utils.BigEndian.WriteUint32(b, uint32(h.PacketNumber))
	return nil
}

func (h *Header) writeShortHeader(b *bytes.Buffer) error {
	typeByte := byte(0x30)
	typeByte |= byte(h.KeyPhase << 6)
	switch h.PacketNumberLen {
	case protocol.PacketNumberLen1:
	case protocol.PacketNumberLen2:
		typeByte |= 0x1
	case protocol.PacketNumberLen4:
		typeByte |= 0x2
	default:
		return fmt.Errorf("invalid packet number length: %d", h.PacketNumberLen)
	}
	b.WriteByte(typeByte)

	b.Write(h.DestConnectionID.Bytes())
	switch h.PacketNumberLen {
	case protocol.PacketNumberLen1:
		b.WriteByte(uint8(h.PacketNumber))
	case protocol.PacketNumberLen2:
		utils.BigEndian.WriteUint16(b, uint16(h.PacketNumber))
	case protocol.PacketNumberLen4:
		utils.BigEndian.WriteUint32(b, uint32(h.PacketNumber))
	}
	return nil
}

func (h *Header) getHeaderLength() (protocol.ByteCount, error) {
	if h.IsLongHeader {
		return 1 /* type byte */ + 4 /* version */ + 1 /* conn id len byte */ + protocol.ByteCount(h.DestConnectionID.Len()+h.SrcConnectionID.Len()) + utils.VarIntLen(uint64(h.PayloadLen)) + 4 /* packet number */, nil
	}

	length := protocol.ByteCount(1 /* type byte */ + h.DestConnectionID.Len())
	if h.PacketNumberLen != protocol.PacketNumberLen1 && h.PacketNumberLen != protocol.PacketNumberLen2 && h.PacketNumberLen != protocol.PacketNumberLen4 {
		return 0, fmt.Errorf("invalid packet number length: %d", h.PacketNumberLen)
	}
	length += protocol.ByteCount(h.PacketNumberLen)
	return length, nil
}

func (h *Header) logHeader(logger utils.Logger) {
	if h.IsLongHeader {
		if h.Version == 0 {
			logger.Debugf("\tVersionNegotiationPacket{DestConnectionID: %s, SrcConnectionID: %s, SupportedVersions: %s}", h.DestConnectionID, h.SrcConnectionID, h.SupportedVersions)
		} else {
			logger.Debugf("\tLong Header{Type: %s, DestConnectionID: %s, SrcConnectionID: %s, PacketNumber: %#x, PayloadLen: %d, Version: %s}", h.Type, h.DestConnectionID, h.SrcConnectionID, h.PacketNumber, h.PayloadLen, h.Version)
		}
	} else {
		logger.Debugf("\tShort Header{DestConnectionID: %s, PacketNumber: %#x, PacketNumberLen: %d, KeyPhase: %d}", h.DestConnectionID, h.PacketNumber, h.PacketNumberLen, h.KeyPhase)
	}
}

func encodeConnIDLen(dest, src protocol.ConnectionID) (byte, error) {
	dcil, err := encodeSingleConnIDLen(dest)
	if err != nil {
		return 0, err
	}
	scil, err := encodeSingleConnIDLen(src)
	if err != nil {
		return 0, err
	}
	return scil | dcil<<4, nil
}

func encodeSingleConnIDLen(id protocol.ConnectionID) (byte, error) {
	len := id.Len()
	if len == 0 {
		return 0, nil
	}
	if len < 4 || len > 18 {
		return 0, fmt.Errorf("invalid connection ID length: %d bytes", len)
	}
	return byte(len - 3), nil
}

func decodeConnIDLen(enc byte) (int /*dest conn id len*/, int /*src conn id len*/) {
	return decodeSingleConnIDLen(enc >> 4), decodeSingleConnIDLen(enc & 0xf)
}

func decodeSingleConnIDLen(enc uint8) int {
	if enc == 0 {
		return 0
	}
	return int(enc) + 3
}
