package gost

import "net"

// Client represents a node client
type Client interface {
	Connect() (net.Conn, error)
	Handshake(conn net.Conn) (net.Conn, error)
	Dial(conn net.Conn, addr string) (net.Conn, error)
}
