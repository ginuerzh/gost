package wire

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

// A RstStreamFrame in QUIC
type RstStreamFrame struct {
	StreamID   protocol.StreamID
	ErrorCode  uint32
	ByteOffset protocol.ByteCount
}

//Write writes a RST_STREAM frame
func (f *RstStreamFrame) Write(b *bytes.Buffer, version protocol.VersionNumber) error {
	b.WriteByte(0x01)
	utils.GetByteOrder(version).WriteUint32(b, uint32(f.StreamID))
	utils.GetByteOrder(version).WriteUint64(b, uint64(f.ByteOffset))
	utils.GetByteOrder(version).WriteUint32(b, f.ErrorCode)
	return nil
}

// MinLength of a written frame
func (f *RstStreamFrame) MinLength(version protocol.VersionNumber) (protocol.ByteCount, error) {
	return 1 + 4 + 8 + 4, nil
}

// ParseRstStreamFrame parses a RST_STREAM frame
func ParseRstStreamFrame(r *bytes.Reader, version protocol.VersionNumber) (*RstStreamFrame, error) {
	frame := &RstStreamFrame{}

	// read the TypeByte
	if _, err := r.ReadByte(); err != nil {
		return nil, err
	}

	sid, err := utils.GetByteOrder(version).ReadUint32(r)
	if err != nil {
		return nil, err
	}
	frame.StreamID = protocol.StreamID(sid)

	byteOffset, err := utils.GetByteOrder(version).ReadUint64(r)
	if err != nil {
		return nil, err
	}
	frame.ByteOffset = protocol.ByteCount(byteOffset)

	frame.ErrorCode, err = utils.GetByteOrder(version).ReadUint32(r)
	if err != nil {
		return nil, err
	}
	return frame, nil
}
