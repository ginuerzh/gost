package gost

import (
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
	Connector   Connector
	Transporter Transporter
}

// Dial connects to the target address.
func (c *Client) Dial(addr string, options ...DialOption) (net.Conn, error) {
	return c.Transporter.Dial(addr, options...)
}

// Handshake performs a handshake with the proxy over connection conn.
func (c *Client) Handshake(conn net.Conn, options ...HandshakeOption) (net.Conn, error) {
	return c.Transporter.Handshake(conn, options...)
}

// Connect connects to the address addr via the proxy over connection conn.
func (c *Client) Connect(conn net.Conn, addr string, options ...ConnectOption) (net.Conn, error) {
	return c.Connector.Connect(conn, addr, options...)
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
	Connect(conn net.Conn, addr string, options ...ConnectOption) (net.Conn, error)
}

// Transporter is responsible for handshaking with the proxy server.
type Transporter interface {
	Dial(addr string, options ...DialOption) (net.Conn, error)
	Handshake(conn net.Conn, options ...HandshakeOption) (net.Conn, error)
	// Indicate that the Transporter supports multiplex
	Multiplex() bool
}

// tcpTransporter is a raw TCP transporter.
type tcpTransporter struct{}

// TCPTransporter creates a raw TCP client.
func TCPTransporter() Transporter {
	return &tcpTransporter{}
}

func (tr *tcpTransporter) Dial(addr string, options ...DialOption) (net.Conn, error) {
	opts := &DialOptions{}
	for _, option := range options {
		option(opts)
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DialTimeout
	}
	if opts.Chain == nil {
		return net.DialTimeout("tcp", addr, timeout)
	}
	return opts.Chain.Dial(addr)
}

func (tr *tcpTransporter) Handshake(conn net.Conn, options ...HandshakeOption) (net.Conn, error) {
	return conn, nil
}

func (tr *tcpTransporter) Multiplex() bool {
	return false
}

// udpTransporter is a raw UDP transporter.
type udpTransporter struct{}

// UDPTransporter creates a raw UDP client.
func UDPTransporter() Transporter {
	return &udpTransporter{}
}

func (tr *udpTransporter) Dial(addr string, options ...DialOption) (net.Conn, error) {
	opts := &DialOptions{}
	for _, option := range options {
		option(opts)
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DialTimeout
	}

	return net.DialTimeout("udp", addr, timeout)
}

func (tr *udpTransporter) Handshake(conn net.Conn, options ...HandshakeOption) (net.Conn, error) {
	return conn, nil
}

func (tr *udpTransporter) Multiplex() bool {
	return false
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
	Addr     string
	Timeout  time.Duration
	User     *url.Userinfo
	Selector gosocks5.Selector
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
