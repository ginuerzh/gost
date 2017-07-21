package gost

import (
	"context"
	"net"
)

type Client struct {
	Connector   Connector
	Transporter Transporter
}

// DefaultClient is a standard HTTP proxy
var DefaultClient = NewClient(HTTPConnector(nil), TCPTransporter())

func NewClient(c Connector, tr Transporter) *Client {
	return &Client{
		Connector:   c,
		Transporter: tr,
	}
}

// Dial connects to the target address
func (c *Client) Dial(ctx context.Context, addr string) (net.Conn, error) {
	return net.Dial(c.Transporter.Network(), addr)
}

func (c *Client) Handshake(ctx context.Context, conn net.Conn) (net.Conn, error) {
	return c.Transporter.Handshake(ctx, conn)
}

func (c *Client) Connect(ctx context.Context, conn net.Conn, addr string) (net.Conn, error) {
	return c.Connector.Connect(ctx, conn, addr)
}

type Connector interface {
	Connect(ctx context.Context, conn net.Conn, addr string) (net.Conn, error)
}

type Transporter interface {
	Network() string
	Handshake(ctx context.Context, conn net.Conn) (net.Conn, error)
}

type tcpTransporter struct {
}

func TCPTransporter() Transporter {
	return &tcpTransporter{}
}

func (tr *tcpTransporter) Network() string {
	return "tcp"
}

func (tr *tcpTransporter) Handshake(ctx context.Context, conn net.Conn) (net.Conn, error) {
	return conn, nil
}
