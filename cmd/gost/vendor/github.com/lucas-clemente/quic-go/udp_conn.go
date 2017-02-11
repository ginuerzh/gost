package quic

import (
	"net"
	"sync"
)

type connection interface {
	write([]byte) error
	setCurrentRemoteAddr(interface{})
	RemoteAddr() *net.UDPAddr
}

type udpConn struct {
	mutex sync.RWMutex

	conn        *net.UDPConn
	currentAddr *net.UDPAddr
}

var _ connection = &udpConn{}

func (c *udpConn) write(p []byte) error {
	_, err := c.conn.WriteToUDP(p, c.currentAddr)
	return err
}

func (c *udpConn) setCurrentRemoteAddr(addr interface{}) {
	c.mutex.Lock()
	c.currentAddr = addr.(*net.UDPAddr)
	c.mutex.Unlock()
}

func (c *udpConn) RemoteAddr() *net.UDPAddr {
	c.mutex.RLock()
	addr := c.currentAddr
	c.mutex.RUnlock()
	return addr
}
