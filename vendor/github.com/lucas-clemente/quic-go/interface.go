package quic

import (
	"context"
	"io"
	"net"
	"time"

	"github.com/lucas-clemente/quic-go/internal/handshake"
	"github.com/lucas-clemente/quic-go/internal/protocol"
)

// The StreamID is the ID of a QUIC stream.
type StreamID = protocol.StreamID

// A VersionNumber is a QUIC version number.
type VersionNumber = protocol.VersionNumber

// A Cookie can be used to verify the ownership of the client address.
type Cookie = handshake.Cookie

// Stream is the interface implemented by QUIC streams
type Stream interface {
	// Read reads data from the stream.
	// Read can be made to time out and return a net.Error with Timeout() == true
	// after a fixed time limit; see SetDeadline and SetReadDeadline.
	io.Reader
	// Write writes data to the stream.
	// Write can be made to time out and return a net.Error with Timeout() == true
	// after a fixed time limit; see SetDeadline and SetWriteDeadline.
	io.Writer
	io.Closer
	StreamID() StreamID
	// Reset closes the stream with an error.
	Reset(error)
	// The context is canceled as soon as the write-side of the stream is closed.
	// This happens when Close() is called, or when the stream is reset (either locally or remotely).
	// Warning: This API should not be considered stable and might change soon.
	Context() context.Context
	// SetReadDeadline sets the deadline for future Read calls and
	// any currently-blocked Read call.
	// A zero value for t means Read will not time out.
	SetReadDeadline(t time.Time) error
	// SetWriteDeadline sets the deadline for future Write calls
	// and any currently-blocked Write call.
	// Even if write times out, it may return n > 0, indicating that
	// some of the data was successfully written.
	// A zero value for t means Write will not time out.
	SetWriteDeadline(t time.Time) error
	// SetDeadline sets the read and write deadlines associated
	// with the connection. It is equivalent to calling both
	// SetReadDeadline and SetWriteDeadline.
	SetDeadline(t time.Time) error
}

// A Session is a QUIC connection between two peers.
type Session interface {
	// AcceptStream returns the next stream opened by the peer, blocking until one is available.
	// Since stream 1 is reserved for the crypto stream, the first stream is either 2 (for a client) or 3 (for a server).
	AcceptStream() (Stream, error)
	// OpenStream opens a new QUIC stream, returning a special error when the peer's concurrent stream limit is reached.
	// New streams always have the smallest possible stream ID.
	// TODO: Enable testing for the special error
	OpenStream() (Stream, error)
	// OpenStreamSync opens a new QUIC stream, blocking until the peer's concurrent stream limit allows a new stream to be opened.
	// It always picks the smallest possible stream ID.
	OpenStreamSync() (Stream, error)
	// LocalAddr returns the local address.
	LocalAddr() net.Addr
	// RemoteAddr returns the address of the peer.
	RemoteAddr() net.Addr
	// Close closes the connection. The error will be sent to the remote peer in a CONNECTION_CLOSE frame. An error value of nil is allowed and will cause a normal PeerGoingAway to be sent.
	Close(error) error
	// The context is cancelled when the session is closed.
	// Warning: This API should not be considered stable and might change soon.
	Context() context.Context
}

// A NonFWSession is a QUIC connection between two peers half-way through the handshake.
// The communication is encrypted, but not yet forward secure.
type NonFWSession interface {
	Session
	WaitUntilHandshakeComplete() error
}

// Config contains all configuration data needed for a QUIC server or client.
type Config struct {
	// The QUIC versions that can be negotiated.
	// If not set, it uses all versions available.
	// Warning: This API should not be considered stable and will change soon.
	Versions []VersionNumber
	// Ask the server to omit the connection ID sent in the Public Header.
	// This saves 8 bytes in the Public Header in every packet. However, if the IP address of the server changes, the connection cannot be migrated.
	// Currently only valid for the client.
	RequestConnectionIDOmission bool
	// HandshakeTimeout is the maximum duration that the cryptographic handshake may take.
	// If the timeout is exceeded, the connection is closed.
	// If this value is zero, the timeout is set to 10 seconds.
	HandshakeTimeout time.Duration
	// IdleTimeout is the maximum duration that may pass without any incoming network activity.
	// This value only applies after the handshake has completed.
	// If the timeout is exceeded, the connection is closed.
	// If this value is zero, the timeout is set to 30 seconds.
	IdleTimeout time.Duration
	// AcceptCookie determines if a Cookie is accepted.
	// It is called with cookie = nil if the client didn't send an Cookie.
	// If not set, it verifies that the address matches, and that the Cookie was issued within the last 24 hours.
	// This option is only valid for the server.
	AcceptCookie func(clientAddr net.Addr, cookie *Cookie) bool
	// MaxReceiveStreamFlowControlWindow is the maximum stream-level flow control window for receiving data.
	// If this value is zero, it will default to 1 MB for the server and 6 MB for the client.
	MaxReceiveStreamFlowControlWindow uint64
	// MaxReceiveConnectionFlowControlWindow is the connection-level flow control window for receiving data.
	// If this value is zero, it will default to 1.5 MB for the server and 15 MB for the client.
	MaxReceiveConnectionFlowControlWindow uint64
	// KeepAlive defines whether this peer will periodically send PING frames to keep the connection alive.
	KeepAlive bool
}

// A Listener for incoming QUIC connections
type Listener interface {
	// Close the server, sending CONNECTION_CLOSE frames to each peer.
	Close() error
	// Addr returns the local network addr that the server is listening on.
	Addr() net.Addr
	// Accept returns new sessions. It should be called in a loop.
	Accept() (Session, error)
}
