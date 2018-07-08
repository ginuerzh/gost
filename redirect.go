// +build !windows

package gost

import (
	"errors"
	"fmt"
	"net"
	"syscall"

	"github.com/go-log/log"
)

type tcpRedirectHandler struct {
	options *HandlerOptions
}

// TCPRedirectHandler creates a server Handler for TCP redirect server.
func TCPRedirectHandler(opts ...HandlerOption) Handler {
	h := &tcpRedirectHandler{}
	h.Init(opts...)

	return h
}

func (h *tcpRedirectHandler) Init(options ...HandlerOption) {
	if h.options == nil {
		h.options = &HandlerOptions{}
	}

	for _, opt := range options {
		opt(h.options)
	}
}

func (h *tcpRedirectHandler) Handle(c net.Conn) {
	conn, ok := c.(*net.TCPConn)
	if !ok {
		log.Log("[red-tcp] not a TCP connection")
	}

	srcAddr := conn.RemoteAddr()
	dstAddr, conn, err := h.getOriginalDstAddr(conn)
	if err != nil {
		log.Logf("[red-tcp] %s -> %s : %s", srcAddr, dstAddr, err)
		return
	}
	defer conn.Close()

	log.Logf("[red-tcp] %s -> %s", srcAddr, dstAddr)

	cc, err := h.options.Chain.Dial(dstAddr.String(),
		RetryChainOption(h.options.Retries),
		TimeoutChainOption(h.options.Timeout),
	)
	if err != nil {
		log.Logf("[red-tcp] %s -> %s : %s", srcAddr, dstAddr, err)
		return
	}
	defer cc.Close()

	log.Logf("[red-tcp] %s <-> %s", srcAddr, dstAddr)
	transport(conn, cc)
	log.Logf("[red-tcp] %s >-< %s", srcAddr, dstAddr)
}

func (h *tcpRedirectHandler) getOriginalDstAddr(conn *net.TCPConn) (addr net.Addr, c *net.TCPConn, err error) {
	defer conn.Close()

	fc, err := conn.File()
	if err != nil {
		return
	}
	defer fc.Close()

	mreq, err := syscall.GetsockoptIPv6Mreq(int(fc.Fd()), syscall.IPPROTO_IP, 80)
	if err != nil {
		return
	}

	// only ipv4 support
	ip := net.IPv4(mreq.Multiaddr[4], mreq.Multiaddr[5], mreq.Multiaddr[6], mreq.Multiaddr[7])
	port := uint16(mreq.Multiaddr[2])<<8 + uint16(mreq.Multiaddr[3])
	addr, err = net.ResolveTCPAddr("tcp4", fmt.Sprintf("%s:%d", ip.String(), port))
	if err != nil {
		return
	}

	cc, err := net.FileConn(fc)
	if err != nil {
		return
	}

	c, ok := cc.(*net.TCPConn)
	if !ok {
		err = errors.New("not a TCP connection")
	}
	return
}
