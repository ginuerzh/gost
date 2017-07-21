package gost

import (
	"context"
	"net"
	"net/url"
	"time"

	ss "github.com/shadowsocks/shadowsocks-go/shadowsocks"
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

type shadowConnector struct {
	Cipher *url.Userinfo
}

func ShadowConnector(cipher *url.Userinfo) Connector {
	return &shadowConnector{Cipher: cipher}
}

func (c *shadowConnector) Connect(ctx context.Context, conn net.Conn, addr string) (net.Conn, error) {
	rawaddr, err := ss.RawAddr(addr)
	if err != nil {
		return nil, err
	}

	var method, password string
	if c.Cipher != nil {
		method = c.Cipher.Username()
		password, _ = c.Cipher.Password()
	}

	cipher, err := ss.NewCipher(method, password)
	if err != nil {
		return nil, err
	}

	sc, err := ss.DialWithRawAddrConn(rawaddr, conn, cipher)
	if err != nil {
		return nil, err
	}
	return &shadowConn{conn: sc}, nil
}
