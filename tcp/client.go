package tcp

import "net"

type nodeClient struct {
}

func (c *nodeClient) Connect() (net.Conn, error) {
	return nil, nil
}

func (c *nodeClient) Handshake(conn net.Conn) (net.Conn, error) {
	return conn, nil
}

func (c *nodeClient) Dial(conn net.Conn, addr string) (net.Conn, error) {
	return nil, nil
}
