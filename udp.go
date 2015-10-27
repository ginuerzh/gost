package main

import (
	"bytes"
	"github.com/ginuerzh/gosocks5"
	"github.com/golang/glog"
	"net"
	"time"
)

type UDPConn struct {
	isClient bool
	udp      *net.UDPConn
	addr     net.Addr
	tcp      net.Conn
}

func Client(conn net.Conn, addr net.Addr) *UDPConn {
	c := &UDPConn{isClient: true}

	switch conn := conn.(type) {
	case *net.UDPConn:
		c.udp = conn
		c.addr = addr
	default:
		c.tcp = conn
	}

	return c
}

func Server(conn net.Conn) *UDPConn {
	c := &UDPConn{}

	switch conn := conn.(type) {
	case *net.UDPConn:
		c.udp = conn
	default:
		c.tcp = conn
	}

	return c
}

func (c *UDPConn) ReadUDP() (*gosocks5.UDPDatagram, error) {
	if c.isClient {
		return c.readUDPClient()
	}
	return c.readUDPServer()
}

func (c *UDPConn) ReadUDPTimeout(timeout time.Duration) (*gosocks5.UDPDatagram, error) {
	if c.udp != nil {
		c.udp.SetReadDeadline(time.Now().Add(timeout))
		defer c.udp.SetReadDeadline(time.Time{})
	} else {
		c.tcp.SetReadDeadline(time.Now().Add(timeout))
		defer c.tcp.SetReadDeadline(time.Time{})
	}
	if c.isClient {
		return c.readUDPClient()
	}
	return c.readUDPServer()
}

func (c *UDPConn) readUDPClient() (*gosocks5.UDPDatagram, error) {
	if c.udp != nil {
		return gosocks5.ReadUDPDatagram(c.udp)
	}
	return gosocks5.ReadUDPDatagram(c.tcp)
}

func (c *UDPConn) readUDPServer() (*gosocks5.UDPDatagram, error) {
	if c.udp != nil {
		b := make([]byte, 65535)
		n, addr, err := c.udp.ReadFrom(b)
		if err != nil {
			return nil, err
		}
		dgram := gosocks5.NewUDPDatagram(
			gosocks5.NewUDPHeader(0, 0, ToSocksAddr(addr)), b[:n])
		return dgram, nil
	}
	return gosocks5.ReadUDPDatagram(c.tcp)
}

func (c *UDPConn) WriteUDP(dgram *gosocks5.UDPDatagram) error {
	if c.isClient {
		return c.writeUDPClient(dgram)
	}
	return c.writeUDPServer(dgram)
}

func (c *UDPConn) WriteUDPTimeout(dgram *gosocks5.UDPDatagram, timeout time.Duration) error {
	if c.udp != nil {
		c.udp.SetWriteDeadline(time.Now().Add(timeout))
		defer c.udp.SetWriteDeadline(time.Time{})
	} else {
		c.tcp.SetWriteDeadline(time.Now().Add(timeout))
		defer c.tcp.SetWriteDeadline(time.Time{})
	}
	if c.isClient {
		return c.writeUDPClient(dgram)
	}
	return c.writeUDPServer(dgram)
}

func (c *UDPConn) writeUDPClient(dgram *gosocks5.UDPDatagram) error {
	if c.udp != nil {
		dgram.Header.Rsv = 0
		buffer := bytes.Buffer{}
		dgram.Write(&buffer)
		_, err := c.udp.WriteTo(buffer.Bytes(), c.addr)
		return err
	}

	dgram.Header.Rsv = uint16(len(dgram.Data))
	return dgram.Write(c.tcp)
}

func (c *UDPConn) writeUDPServer(dgram *gosocks5.UDPDatagram) error {
	if c.udp != nil {
		addr, err := net.ResolveUDPAddr("udp", dgram.Header.Addr.String())
		if err != nil {
			glog.V(LWARNING).Infoln(err)
			return nil // drop silently
		}
		_, err = c.udp.WriteTo(dgram.Data, addr)
		return err
	}
	dgram.Header.Rsv = uint16(len(dgram.Data))
	return dgram.Write(c.tcp)
}

func (c *UDPConn) Close() error {
	if c.udp != nil {
		return c.udp.Close()
	}
	return c.tcp.Close()
}

func (c *UDPConn) LocalAddr() net.Addr {
	if c.udp != nil {
		return c.udp.LocalAddr()
	}
	return c.tcp.LocalAddr()
}

func (c *UDPConn) RemoteAddr() net.Addr {
	if c.udp != nil {
		return c.udp.RemoteAddr()
	}
	return c.tcp.RemoteAddr()
}

func (c *UDPConn) SetDeadline(t time.Time) error {
	if c.udp != nil {
		return c.udp.SetDeadline(t)
	}
	return c.tcp.SetDeadline(t)
}

func (c *UDPConn) SetReadDeadline(t time.Time) error {
	if c.udp != nil {
		return c.udp.SetReadDeadline(t)
	}
	return c.tcp.SetReadDeadline(t)
}

func (c *UDPConn) SetWriteDeadline(t time.Time) error {
	if c.udp != nil {
		return c.udp.SetWriteDeadline(t)
	}
	return c.tcp.SetWriteDeadline(t)
}
