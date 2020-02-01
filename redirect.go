// +build !windows

package gost

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/LiamHaworth/go-tproxy"
	"github.com/go-log/log"
)

type tcpRedirectHandler struct {
	options *HandlerOptions
}

// TCPRedirectHandler creates a server Handler for TCP transparent server.
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

type udpRedirectHandler struct {
	options *HandlerOptions
}

// UDPRedirectHandler creates a server Handler for UDP transparent server.
func UDPRedirectHandler(opts ...HandlerOption) Handler {
	h := &udpRedirectHandler{}
	h.Init(opts...)

	return h
}

func (h *udpRedirectHandler) Init(options ...HandlerOption) {
	if h.options == nil {
		h.options = &HandlerOptions{}
	}

	for _, opt := range options {
		opt(h.options)
	}
}

func (h *udpRedirectHandler) Handle(conn net.Conn) {
	defer conn.Close()

	raddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		log.Log("[red-udp] wrong connection type")
		return
	}

	var cc net.Conn
	var err error
	if h.options.Chain.IsEmpty() {
		cc, err = net.DialUDP("udp", nil, raddr)
		if err != nil {
			log.Logf("[red-udp] %s - %s : %s", conn.RemoteAddr(), raddr, err)
			return
		}
	} else if h.options.Chain.LastNode().Protocol == "ssu" {
		cc, err = h.options.Chain.Dial(raddr.String(),
			RetryChainOption(h.options.Retries),
			TimeoutChainOption(h.options.Timeout),
		)
		if err != nil {
			log.Logf("[red-udp] %s - %s : %s", conn.RemoteAddr(), raddr, err)
			return
		}
	} else {
		var err error
		cc, err = getSOCKS5UDPTunnel(h.options.Chain, nil)
		if err != nil {
			log.Logf("[red-udp] %s - %s : %s", conn.RemoteAddr(), raddr, err)
			return
		}

		cc = &udpTunnelConn{Conn: cc, raddr: raddr}
	}
	defer cc.Close()

	log.Logf("[red-udp] %s <-> %s", conn.RemoteAddr(), raddr)
	transport(conn, cc)
	log.Logf("[red-udp] %s >-< %s", conn.RemoteAddr(), raddr)
}

type udpRedirectListener struct {
	*net.UDPConn
	config *UDPListenConfig
}

// UDPRedirectListener creates a Listener for UDP transparent proxy server.
func UDPRedirectListener(addr string, cfg *UDPListenConfig) (Listener, error) {
	laddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}

	ln, err := tproxy.ListenUDP("udp", laddr)
	if err != nil {
		return nil, err
	}

	if cfg == nil {
		cfg = &UDPListenConfig{}
	}
	return &udpRedirectListener{
		UDPConn: ln,
		config:  cfg,
	}, nil
}

func (l *udpRedirectListener) Accept() (conn net.Conn, err error) {
	b := make([]byte, mediumBufferSize)

	n, raddr, dstAddr, err := tproxy.ReadFromUDP(l.UDPConn, b)
	if err != nil {
		log.Logf("[red-udp] %s : %s", l.Addr(), err)
		return
	}
	log.Logf("[red-udp] %s: %s -> %s", l.Addr(), raddr, dstAddr)

	c, err := tproxy.DialUDP("udp", dstAddr, raddr)
	if err != nil {
		log.Logf("[red-udp] %s -> %s : %s", raddr, dstAddr, err)
		return
	}

	ttl := l.config.TTL
	if ttl <= 0 {
		ttl = defaultTTL
	}

	conn = &udpRedirectServerConn{
		Conn: c,
		buf:  b[:n],
		ttl:  ttl,
	}
	return
}

func (l *udpRedirectListener) Addr() net.Addr {
	return l.UDPConn.LocalAddr()
}

type udpRedirectServerConn struct {
	net.Conn
	buf  []byte
	ttl  time.Duration
	once sync.Once
}

func (c *udpRedirectServerConn) Read(b []byte) (n int, err error) {
	if c.ttl > 0 {
		c.SetReadDeadline(time.Now().Add(c.ttl))
		defer c.SetReadDeadline(time.Time{})
	}
	c.once.Do(func() {
		n = copy(b, c.buf)
		c.buf = nil
	})

	if n == 0 {
		n, err = c.Conn.Read(b)
	}
	return
}

func (c *udpRedirectServerConn) Write(b []byte) (n int, err error) {
	if c.ttl > 0 {
		c.SetWriteDeadline(time.Now().Add(c.ttl))
		defer c.SetWriteDeadline(time.Time{})
	}
	return c.Conn.Write(b)
}
