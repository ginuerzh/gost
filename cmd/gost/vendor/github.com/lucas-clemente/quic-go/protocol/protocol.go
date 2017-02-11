package protocol

import (
	"math"
	"time"
)

// A PacketNumber in QUIC
type PacketNumber uint64

// PacketNumberLen is the length of the packet number in bytes
type PacketNumberLen uint8

const (
	// PacketNumberLenInvalid is the default value and not a valid length for a packet number
	PacketNumberLenInvalid PacketNumberLen = 0
	// PacketNumberLen1 is a packet number length of 1 byte
	PacketNumberLen1 PacketNumberLen = 1
	// PacketNumberLen2 is a packet number length of 2 bytes
	PacketNumberLen2 PacketNumberLen = 2
	// PacketNumberLen4 is a packet number length of 4 bytes
	PacketNumberLen4 PacketNumberLen = 4
	// PacketNumberLen6 is a packet number length of 6 bytes
	PacketNumberLen6 PacketNumberLen = 6
)

// A ConnectionID in QUIC
type ConnectionID uint64

// A StreamID in QUIC
type StreamID uint32

// A ByteCount in QUIC
type ByteCount uint64

// MaxByteCount is the maximum value of a ByteCount
const MaxByteCount = math.MaxUint64

// MaxPacketSize is the maximum packet size, including the public header
// This is the value used by Chromium for a QUIC packet sent using IPv6 (for IPv4 it would be 1370)
const MaxPacketSize ByteCount = 1350

// MaxFrameAndPublicHeaderSize is the maximum size of a QUIC frame plus PublicHeader
const MaxFrameAndPublicHeaderSize = MaxPacketSize - 12 /*crypto signature*/

// DefaultTCPMSS is the default maximum packet size used in the Linux TCP implementation.
// Used in QUIC for congestion window computations in bytes.
const DefaultTCPMSS ByteCount = 1460

// InitialStreamFlowControlWindow is the initial stream-level flow control window for sending
const InitialStreamFlowControlWindow ByteCount = (1 << 14) // 16 kB

// InitialConnectionFlowControlWindow is the initial connection-level flow control window for sending
const InitialConnectionFlowControlWindow ByteCount = (1 << 14) // 16 kB

// DefaultRetransmissionTime is the RTO time on new connections
const DefaultRetransmissionTime = 500 * time.Millisecond

// MinRetransmissionTime is the minimum RTO time
const MinRetransmissionTime = 200 * time.Millisecond

// MaxRetransmissionTime is the maximum RTO time
const MaxRetransmissionTime = 60 * time.Second

// ClientHelloMinimumSize is the minimum size the server expects an inchoate CHLO to have.
const ClientHelloMinimumSize = 1024

// MaxClientHellos is the maximum number of times we'll send a client hello
// The value 3 accounts for:
// * one failure due to an incorrect or missing source-address token
// * one failure due the server's certificate chain being unavailible and the server being unwilling to send it without a valid source-address token
const MaxClientHellos = 3
