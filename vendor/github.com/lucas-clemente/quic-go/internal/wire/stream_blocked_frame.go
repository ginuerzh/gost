package wire

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

// A StreamBlockedFrame in QUIC
type StreamBlockedFrame struct {
	StreamID protocol.StreamID
}

// ParseStreamBlockedFrame parses a STREAM_BLOCKED frame
func ParseStreamBlockedFrame(r *bytes.Reader, version protocol.VersionNumber) (*StreamBlockedFrame, error) {
	frame := &StreamBlockedFrame{}

	// read the TypeByte
	if _, err := r.ReadByte(); err != nil {
		return nil, err
	}
	sid, err := utils.GetByteOrder(version).ReadUint32(r)
	if err != nil {
		return nil, err
	}
	frame.StreamID = protocol.StreamID(sid)
	return frame, nil
}

// Write writes a STREAM_BLOCKED frame
func (f *StreamBlockedFrame) Write(b *bytes.Buffer, version protocol.VersionNumber) error {
	if !version.UsesMaxDataFrame() {
		return (&blockedFrameLegacy{StreamID: f.StreamID}).Write(b, version)
	}
	b.WriteByte(0x09)
	utils.GetByteOrder(version).WriteUint32(b, uint32(f.StreamID))
	return nil
}

// MinLength of a written frame
func (f *StreamBlockedFrame) MinLength(version protocol.VersionNumber) (protocol.ByteCount, error) {
	return 1 + 4, nil
}
