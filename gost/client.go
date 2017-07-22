package gost

import (
	"net"
)

type Client struct {
	Connector   Connector
	Transporter Transporter
}

func NewClient(c Connector, tr Transporter) *Client {
	return &Client{
		Connector:   c,
		Transporter: tr,
	}
}

// Dial connects to the target address
func (c *Client) Dial(addr string) (net.Conn, error) {
	return net.Dial(c.Transporter.Network(), addr)
}

func (c *Client) Handshake(conn net.Conn) (net.Conn, error) {
	return c.Transporter.Handshake(conn)
}

func (c *Client) Connect(conn net.Conn, addr string) (net.Conn, error) {
	return c.Connector.Connect(conn, addr)
}

// DefaultClient is a standard HTTP proxy client
var DefaultClient = NewClient(HTTPConnector(nil), TCPTransporter())

func Dial(addr string) (net.Conn, error) {
	return DefaultClient.Dial(addr)
}

func Handshake(conn net.Conn) (net.Conn, error) {
	return DefaultClient.Handshake(conn)
}

func Connect(conn net.Conn, addr string) (net.Conn, error) {
	return DefaultClient.Connect(conn, addr)
}

type Connector interface {
	Connect(conn net.Conn, addr string) (net.Conn, error)
}

type Transporter interface {
	Network() string
	Handshake(conn net.Conn) (net.Conn, error)
}

type tcpTransporter struct {
}

func TCPTransporter() Transporter {
	return &tcpTransporter{}
}

func (tr *tcpTransporter) Network() string {
	return "tcp"
}

func (tr *tcpTransporter) Handshake(conn net.Conn) (net.Conn, error) {
	return conn, nil
}
