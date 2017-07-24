package gost

import (
	"net"
)

// Client is a proxy client.
// A client is divided into two layers: connector and transporter.
// Connector is responsible for connecting to the destination address through this proxy.
// Transporter performs a handshake with this proxy.
type Client struct {
	Connector   Connector
	Transporter Transporter
}

// NewClient creates a proxy client.
func NewClient(c Connector, tr Transporter) *Client {
	return &Client{
		Connector:   c,
		Transporter: tr,
	}
}

// Dial connects to the target address.
func (c *Client) Dial(addr string) (net.Conn, error) {
	return c.Transporter.Dial(addr)
}

// Handshake performs a handshake with the proxy over connection conn.
func (c *Client) Handshake(conn net.Conn) (net.Conn, error) {
	return c.Transporter.Handshake(conn)
}

// Connect connects to the address addr via the proxy over connection conn.
func (c *Client) Connect(conn net.Conn, addr string) (net.Conn, error) {
	return c.Connector.Connect(conn, addr)
}

// DefaultClient is a standard HTTP proxy client.
var DefaultClient = NewClient(HTTPConnector(nil), TCPTransporter())

// Dial connects to the address addr via the DefaultClient.
func Dial(addr string) (net.Conn, error) {
	return DefaultClient.Dial(addr)
}

// Handshake performs a handshake via the DefaultClient.
func Handshake(conn net.Conn) (net.Conn, error) {
	return DefaultClient.Handshake(conn)
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
	Dial(addr string) (net.Conn, error)
	Handshake(conn net.Conn) (net.Conn, error)
	// Indicate that the Transporter supports multiplex
	Multiplex() bool
}

type tcpTransporter struct {
}

// TCPTransporter creates a transporter for TCP proxy client.
func TCPTransporter() Transporter {
	return &tcpTransporter{}
}

func (tr *tcpTransporter) Dial(addr string) (net.Conn, error) {
	return net.Dial("tcp", addr)
}

func (tr *tcpTransporter) Handshake(conn net.Conn) (net.Conn, error) {
	return conn, nil
}

func (tr *tcpTransporter) Multiplex() bool {
	return false
}
