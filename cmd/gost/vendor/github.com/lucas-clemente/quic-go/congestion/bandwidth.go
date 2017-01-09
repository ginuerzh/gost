package congestion

import (
	"time"

	"github.com/lucas-clemente/quic-go/protocol"
)

// Bandwidth of a connection
type Bandwidth uint64

const (
	// BitsPerSecond is 1 bit per second
	BitsPerSecond Bandwidth = 1
	// KBitsPerSecond is 1000 bits per second
	KBitsPerSecond = 1000 * BitsPerSecond
	// BytesPerSecond is 1 byte per second
	BytesPerSecond = 8 * BitsPerSecond
	// KBytesPerSecond is 1000 bytes per second
	KBytesPerSecond = 1000 * BytesPerSecond
)

// BandwidthFromDelta calculates the bandwidth from a number of bytes and a time delta
func BandwidthFromDelta(bytes protocol.ByteCount, delta time.Duration) Bandwidth {
	return Bandwidth(bytes) * Bandwidth(time.Second) / Bandwidth(delta) * BytesPerSecond
}
