package gost

import (
	"context"
	"crypto/tls"
	"net"
	"net/url"
	"time"

	"github.com/ginuerzh/gosocks5"
)

// Client is a proxy client.
// A client is divided into two layers: connector and transporter.
// Connector is responsible for connecting to the destination address through this proxy.
// Transporter performs a handshake with this proxy.
type Client struct {
	Connector
	Transporter
}

// DefaultClient is a standard HTTP proxy client.
var DefaultClient = &Client{Connector: HTTPConnector(nil), Transporter: TCPTransporter()}

// Dial connects to the address addr via the DefaultClient.
func Dial(addr string, options ...DialOption) (net.Conn, error) {
	return DefaultClient.Dial(addr, options...)
}

// Handshake performs a handshake via the DefaultClient.
func Handshake(conn net.Conn, options ...HandshakeOption) (net.Conn, error) {
	return DefaultClient.Handshake(conn, options...)
}

// Connect connects to the address addr via the DefaultClient.
func Connect(conn net.Conn, addr string) (net.Conn, error) {
	return DefaultClient.Connect(conn, addr)
}

// Connector is responsible for connecting to the destination address.
type Connector interface {
	// Deprecated: use ConnectContext instead.
	Connect(conn net.Conn, address string, options ...ConnectOption) (net.Conn, error)
	ConnectContext(ctx context.Context, conn net.Conn, network, address string, options ...ConnectOption) (net.Conn, error)
}

type autoConnector struct {
	User *url.Userinfo
}

// AutoConnector is a Connector.
func AutoConnector(user *url.Userinfo) Connector {
	return &autoConnector{
		User: user,
	}
}

func (c *autoConnector) Connect(conn net.Conn, address string, options ...ConnectOption) (net.Conn, error) {
	return c.ConnectContext(context.Background(), conn, "tcp", address, options...)
}

func (c *autoConnector) ConnectContext(ctx context.Context, conn net.Conn, network, address string, options ...ConnectOption) (net.Conn, error) {
	var cnr Connector
	switch network {
	case "tcp", "tcp4", "tcp6":
		cnr = &httpConnector{User: c.User}
	default:
		cnr = &socks5UDPTunConnector{User: c.User}
	}

	return cnr.ConnectContext(ctx, conn, network, address, options...)
}

// Transporter is responsible for handshaking with the proxy server.
type Transporter interface {
	Dial(addr string, options ...DialOption) (net.Conn, error)
	Handshake(conn net.Conn, options ...HandshakeOption) (net.Conn, error)
	// Indicate that the Transporter supports multiplex
	Multiplex() bool
}

// DialOptions describes the options for Transporter.Dial.
type DialOptions struct {
	Timeout time.Duration
	Chain   *Chain
}

// DialOption allows a common way to set DialOptions.
type DialOption func(opts *DialOptions)

// TimeoutDialOption specifies the timeout used by Transporter.Dial
func TimeoutDialOption(timeout time.Duration) DialOption {
	return func(opts *DialOptions) {
		opts.Timeout = timeout
	}
}

// ChainDialOption specifies a chain used by Transporter.Dial
func ChainDialOption(chain *Chain) DialOption {
	return func(opts *DialOptions) {
		opts.Chain = chain
	}
}

// HandshakeOptions describes the options for handshake.
type HandshakeOptions struct {
	Addr       string
	Host       string
	User       *url.Userinfo
	Timeout    time.Duration
	Interval   time.Duration
	Retry      int
	TLSConfig  *tls.Config
	WSOptions  *WSOptions
	KCPConfig  *KCPConfig
	QUICConfig *QUICConfig
}

// HandshakeOption allows a common way to set HandshakeOptions.
type HandshakeOption func(opts *HandshakeOptions)

// AddrHandshakeOption specifies the server address
func AddrHandshakeOption(addr string) HandshakeOption {
	return func(opts *HandshakeOptions) {
		opts.Addr = addr
	}
}

// HostHandshakeOption specifies the hostname
func HostHandshakeOption(host string) HandshakeOption {
	return func(opts *HandshakeOptions) {
		opts.Host = host
	}
}

// UserHandshakeOption specifies the user used by Transporter.Handshake
func UserHandshakeOption(user *url.Userinfo) HandshakeOption {
	return func(opts *HandshakeOptions) {
		opts.User = user
	}
}

// TimeoutHandshakeOption specifies the timeout used by Transporter.Handshake
func TimeoutHandshakeOption(timeout time.Duration) HandshakeOption {
	return func(opts *HandshakeOptions) {
		opts.Timeout = timeout
	}
}

// IntervalHandshakeOption specifies the interval time used by Transporter.Handshake
func IntervalHandshakeOption(interval time.Duration) HandshakeOption {
	return func(opts *HandshakeOptions) {
		opts.Interval = interval
	}
}

// RetryHandshakeOption specifies the times of retry used by Transporter.Handshake
func RetryHandshakeOption(retry int) HandshakeOption {
	return func(opts *HandshakeOptions) {
		opts.Retry = retry
	}
}

// TLSConfigHandshakeOption specifies the TLS config used by Transporter.Handshake
func TLSConfigHandshakeOption(config *tls.Config) HandshakeOption {
	return func(opts *HandshakeOptions) {
		opts.TLSConfig = config
	}
}

// WSOptionsHandshakeOption specifies the websocket options used by websocket handshake
func WSOptionsHandshakeOption(options *WSOptions) HandshakeOption {
	return func(opts *HandshakeOptions) {
		opts.WSOptions = options
	}
}

// KCPConfigHandshakeOption specifies the KCP config used by KCP handshake
func KCPConfigHandshakeOption(config *KCPConfig) HandshakeOption {
	return func(opts *HandshakeOptions) {
		opts.KCPConfig = config
	}
}

// QUICConfigHandshakeOption specifies the QUIC config used by QUIC handshake
func QUICConfigHandshakeOption(config *QUICConfig) HandshakeOption {
	return func(opts *HandshakeOptions) {
		opts.QUICConfig = config
	}
}

// ConnectOptions describes the options for Connector.Connect.
type ConnectOptions struct {
	Addr      string
	Timeout   time.Duration
	User      *url.Userinfo
	Selector  gosocks5.Selector
	UserAgent string
	NoTLS     bool
}

// ConnectOption allows a common way to set ConnectOptions.
type ConnectOption func(opts *ConnectOptions)

// AddrConnectOption specifies the corresponding address of the target.
func AddrConnectOption(addr string) ConnectOption {
	return func(opts *ConnectOptions) {
		opts.Addr = addr
	}
}

// TimeoutConnectOption specifies the timeout for connecting to target.
func TimeoutConnectOption(timeout time.Duration) ConnectOption {
	return func(opts *ConnectOptions) {
		opts.Timeout = timeout
	}
}

// UserConnectOption specifies the user info for authentication.
func UserConnectOption(user *url.Userinfo) ConnectOption {
	return func(opts *ConnectOptions) {
		opts.User = user
	}
}

// SelectorConnectOption specifies the SOCKS5 client selector.
func SelectorConnectOption(s gosocks5.Selector) ConnectOption {
	return func(opts *ConnectOptions) {
		opts.Selector = s
	}
}

// UserAgentConnectOption specifies the HTTP user-agent header.
func UserAgentConnectOption(ua string) ConnectOption {
	return func(opts *ConnectOptions) {
		opts.UserAgent = ua
	}
}

// NoTLSConnectOption specifies the SOCKS5 method without TLS.
func NoTLSConnectOption(b bool) ConnectOption {
	return func(opts *ConnectOptions) {
		opts.NoTLS = b
	}
}
