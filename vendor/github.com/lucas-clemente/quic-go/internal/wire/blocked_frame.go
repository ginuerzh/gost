package wire

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
)

// A BlockedFrame is a BLOCKED frame
type BlockedFrame struct{}

// ParseBlockedFrame parses a BLOCKED frame
func ParseBlockedFrame(r *bytes.Reader, version protocol.VersionNumber) (*BlockedFrame, error) {
	if _, err := r.ReadByte(); err != nil {
		return nil, err
	}
	return &BlockedFrame{}, nil
}

func (f *BlockedFrame) Write(b *bytes.Buffer, version protocol.VersionNumber) error {
	if !version.UsesMaxDataFrame() {
		return (&blockedFrameLegacy{}).Write(b, version)
	}
	typeByte := uint8(0x08)
	b.WriteByte(typeByte)
	return nil
}

// MinLength of a written frame
func (f *BlockedFrame) MinLength(version protocol.VersionNumber) (protocol.ByteCount, error) {
	if !version.UsesMaxDataFrame() { // writing this frame would result in a legacy BLOCKED being written, which is longer
		return 1 + 4, nil
	}
	return 1, nil
}
