package gost

import (
	"crypto/tls"
	"net"
	"net/url"
	"sync/atomic"
	"time"
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
func (c *Client) Connect(conn net.Conn, addr string) (net.Conn, error) {
	return c.Connector.Connect(conn, addr)
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
	Connect(conn net.Conn, addr string) (net.Conn, error)
}

// Transporter is responsible for handshaking with the proxy server.
type Transporter interface {
	Dial(addr string, options ...DialOption) (net.Conn, error)
	Handshake(conn net.Conn, options ...HandshakeOption) (net.Conn, error)
	// Indicate that the Transporter supports multiplex
	Multiplex() bool
}

type tcpTransporter struct {
	count uint64
}

// TCPTransporter creates a transporter for TCP proxy client.
func TCPTransporter() Transporter {
	return &tcpTransporter{}
}

func (tr *tcpTransporter) Dial(addr string, options ...DialOption) (net.Conn, error) {
	opts := &DialOptions{}
	for _, option := range options {
		option(opts)
	}

	if len(opts.IPs) > 0 {
		count := atomic.AddUint64(&tr.count, 1)
		_, sport, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		n := uint64(len(opts.IPs))
		addr = opts.IPs[int(count%n)] + ":" + sport
	}

	if opts.Chain == nil {
		return net.DialTimeout("tcp", addr, opts.Timeout)
	}
	return opts.Chain.Dial(addr)
}

func (tr *tcpTransporter) Handshake(conn net.Conn, options ...HandshakeOption) (net.Conn, error) {
	return conn, nil
}

func (tr *tcpTransporter) Multiplex() bool {
	return false
}

// DialOptions describes the options for dialing.
type DialOptions struct {
	Timeout time.Duration
	Chain   *Chain
	IPs     []string
}

// DialOption allows a common way to set dial options.
type DialOption func(opts *DialOptions)

func TimeoutDialOption(timeout time.Duration) DialOption {
	return func(opts *DialOptions) {
		opts.Timeout = timeout
	}
}

func ChainDialOption(chain *Chain) DialOption {
	return func(opts *DialOptions) {
		opts.Chain = chain
	}
}

func IPDialOption(ips ...string) DialOption {
	return func(opts *DialOptions) {
		opts.IPs = ips
	}
}

// HandshakeOptions describes the options for handshake.
type HandshakeOptions struct {
	Addr       string
	User       *url.Userinfo
	Timeout    time.Duration
	Interval   time.Duration
	Retry      int
	TLSConfig  *tls.Config
	WSOptions  *WSOptions
	KCPConfig  *KCPConfig
	QUICConfig *QUICConfig
}

// HandshakeOption allows a common way to set handshake options.
type HandshakeOption func(opts *HandshakeOptions)

func AddrHandshakeOption(addr string) HandshakeOption {
	return func(opts *HandshakeOptions) {
		opts.Addr = addr
	}
}

func UserHandshakeOption(user *url.Userinfo) HandshakeOption {
	return func(opts *HandshakeOptions) {
		opts.User = user
	}
}

func TimeoutHandshakeOption(timeout time.Duration) HandshakeOption {
	return func(opts *HandshakeOptions) {
		opts.Timeout = timeout
	}
}

func IntervalHandshakeOption(interval time.Duration) HandshakeOption {
	return func(opts *HandshakeOptions) {
		opts.Interval = interval
	}
}

func RetryHandshakeOption(retry int) HandshakeOption {
	return func(opts *HandshakeOptions) {
		opts.Retry = retry
	}
}

func TLSConfigHandshakeOption(config *tls.Config) HandshakeOption {
	return func(opts *HandshakeOptions) {
		opts.TLSConfig = config
	}
}

func WSOptionsHandshakeOption(options *WSOptions) HandshakeOption {
	return func(opts *HandshakeOptions) {
		opts.WSOptions = options
	}
}

func KCPConfigHandshakeOption(config *KCPConfig) HandshakeOption {
	return func(opts *HandshakeOptions) {
		opts.KCPConfig = config
	}
}

func QUICConfigHandshakeOption(config *QUICConfig) HandshakeOption {
	return func(opts *HandshakeOptions) {
		opts.QUICConfig = config
	}
}
