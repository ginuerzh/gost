package stun

import (
	"encoding/binary"
	"errors"
	"net"
)

type Listener interface {
	Addr() net.Addr
	Close() error
}

type Transport interface {
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	Write(p []byte) (int, error)
	Close() error
}

type Marshaler interface {
	Marshal(b []byte) []byte
}

type TransportHandler interface {
	ServeTransport(b []byte, tr Transport) (int, error)
}

func dialUDP(network, raddr string) (net.Conn, error) {
	addr, err := net.ResolveUDPAddr(network, raddr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP(network, nil)
	if err != nil {
		return nil, err
	}
	return &packetConn{conn, addr}, nil
}

func dialTCP(network, raddr string) (net.Conn, error) {
	addr, err := net.ResolveTCPAddr(network, raddr)
	if err != nil {
		return nil, err
	}
	return net.DialTCP(network, nil, addr)
}

type packetConn struct {
	net.PacketConn
	addr net.Addr
}

func (t *packetConn) Read(p []byte) (n int, err error) {
	n, _, err = t.ReadFrom(p)
	return
}

func (t *packetConn) Write(p []byte) (int, error) {
	return t.WriteTo(p, t.addr)
}

func (t *packetConn) RemoteAddr() net.Addr {
	return t.addr
}

var (
	errBufferOverflow = errors.New("stun: buffer overflow")
	errFormat         = errors.New("stun: format error")
)

func getBuffer() []byte {
	return make([]byte, 2048)
}

func putBuffer(b []byte) {
	if cap(b) >= 2048 {
	}
}

func grow(p []byte, n int) (b, a []byte) {
	l := len(p)
	r := l + n
	if r > cap(p) {
		b = make([]byte, (1+((r-1)>>10))<<10)[:r]
		a = b[l:r]
		if l > 0 {
			copy(b, p[:l])
		}
	} else {
		return p[:r], p[l:r]
	}
	return
}

var be = binary.BigEndian
