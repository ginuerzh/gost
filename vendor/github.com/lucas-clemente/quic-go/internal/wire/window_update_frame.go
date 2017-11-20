package wire

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

type windowUpdateFrame struct {
	StreamID   protocol.StreamID
	ByteOffset protocol.ByteCount
}

// ParseWindowUpdateFrame parses a WINDOW_UPDATE frame
// The frame returned is
// * a MAX_STREAM_DATA frame, if the WINDOW_UPDATE applies to a stream
// * a MAX_DATA frame, if the WINDOW_UPDATE applies to the connection
func ParseWindowUpdateFrame(r *bytes.Reader, version protocol.VersionNumber) (Frame, error) {
	f, err := ParseMaxStreamDataFrame(r, version)
	if err != nil {
		return nil, err
	}
	if f.StreamID == 0 {
		return &MaxDataFrame{ByteOffset: f.ByteOffset}, nil
	}
	return f, nil
}

func (f *windowUpdateFrame) Write(b *bytes.Buffer, version protocol.VersionNumber) error {
	b.WriteByte(0x4)
	utils.GetByteOrder(version).WriteUint32(b, uint32(f.StreamID))
	utils.GetByteOrder(version).WriteUint64(b, uint64(f.ByteOffset))
	return nil
}
