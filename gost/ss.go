package gost

import (
	"net"
	"time"
)

// Due to in/out byte length is inconsistent of the shadowsocks.Conn.Write,
// we wrap around it to make io.Copy happy
type shadowConn struct {
	conn net.Conn
}

func ShadowConn(conn net.Conn) net.Conn {
	return &shadowConn{conn: conn}
}

func (c *shadowConn) Read(b []byte) (n int, err error) {
	return c.conn.Read(b)
}

func (c *shadowConn) Write(b []byte) (n int, err error) {
	n = len(b) // force byte length consistent
	_, err = c.conn.Write(b)
	return
}

func (c *shadowConn) Close() error {
	return c.conn.Close()
}

func (c *shadowConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *shadowConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *shadowConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *shadowConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *shadowConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}
