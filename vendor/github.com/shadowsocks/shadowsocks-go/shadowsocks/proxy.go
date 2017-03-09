package shadowsocks

import (
	"errors"
	"strings"
	"fmt"
	"net"
	"time"
)

type Dialer struct {
	cipher *Cipher
	server string
	support_udp bool
}

type ProxyConn struct {
	*Conn
	raddr *ProxyAddr
}

type ProxyAddr struct {
	network string
	address string
}

var ErrNilCipher = errors.New("cipher can't be nil.")

func NewDialer(server string, cipher *Cipher) (dialer *Dialer, err error) {
	// Currently shadowsocks-go do not support UDP
	if cipher == nil {
		return nil, ErrNilCipher
	}
	return &Dialer {
		cipher: cipher,
		server: server,
		support_udp: false,
	}, nil
}

func (d *Dialer) Dial(network, addr string) (c net.Conn, err error) {
	if strings.HasPrefix(network, "tcp") {
		conn, err := Dial(addr, d.server, d.cipher.Copy())
		if err != nil {
			return nil, err
		}
		return &ProxyConn {
			Conn: conn,
			raddr: &ProxyAddr {
				network: network,
				address: addr,
			},
		}, nil
	}
	return nil, fmt.Errorf("unsupported connection type: %s", network)
}

func (c *ProxyConn) LocalAddr() net.Addr {
	return c.Conn.LocalAddr()
}

func (c *ProxyConn) RemoteAddr() net.Addr {
	return c.raddr
}

func (c *ProxyConn) SetDeadline(t time.Time) error {
	return c.Conn.SetDeadline(t)
}

func (c *ProxyConn) SetReadDeadline(t time.Time) error {
	return c.Conn.SetReadDeadline(t)
}

func (c *ProxyConn) SetWriteDeadline(t time.Time) error {
	return c.Conn.SetWriteDeadline(t)
}

func (a *ProxyAddr) Network() string {
	return a.network
}

func (a *ProxyAddr) String() string {
	return a.address
}
