package utils

import (
	"io"

	"github.com/lucas-clemente/quic-go/protocol"
)

// Stream is the interface for QUIC streams
type Stream interface {
	io.Reader
	io.Writer
	io.Closer
	StreamID() protocol.StreamID
	CloseRemote(offset protocol.ByteCount)
	Reset(error)
}
