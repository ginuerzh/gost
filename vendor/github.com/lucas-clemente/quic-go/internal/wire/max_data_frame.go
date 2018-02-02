package wire

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

// A MaxDataFrame carries flow control information for the connection
type MaxDataFrame struct {
	ByteOffset protocol.ByteCount
}

// ParseMaxDataFrame parses a MAX_DATA frame
func ParseMaxDataFrame(r *bytes.Reader, version protocol.VersionNumber) (*MaxDataFrame, error) {
	// read the TypeByte
	if _, err := r.ReadByte(); err != nil {
		return nil, err
	}

	frame := &MaxDataFrame{}
	byteOffset, err := utils.GetByteOrder(version).ReadUint64(r)
	if err != nil {
		return nil, err
	}
	frame.ByteOffset = protocol.ByteCount(byteOffset)
	return frame, nil
}

//Write writes a MAX_STREAM_DATA frame
func (f *MaxDataFrame) Write(b *bytes.Buffer, version protocol.VersionNumber) error {
	if !version.UsesMaxDataFrame() {
		// write a gQUIC WINDOW_UPDATE frame (with stream ID 0, which means connection-level there)
		return (&windowUpdateFrame{
			StreamID:   0,
			ByteOffset: f.ByteOffset,
		}).Write(b, version)
	}
	b.WriteByte(0x4)
	utils.GetByteOrder(version).WriteUint64(b, uint64(f.ByteOffset))
	return nil
}

// MinLength of a written frame
func (f *MaxDataFrame) MinLength(version protocol.VersionNumber) (protocol.ByteCount, error) {
	if !version.UsesMaxDataFrame() { // writing this frame would result in a gQUIC WINDOW_UPDATE being written, which is longer
		return 1 + 4 + 8, nil
	}
	return 1 + 8, nil
}
