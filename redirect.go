// +build !windows

package gost

import (
	"errors"
	"fmt"
	"net"
	"syscall"

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

func (h *udpRedirectHandler) Handle(c net.Conn) {
	defer c.Close()

	conn, ok := c.(*udpRedirectServerConn)
	if !ok {
		log.Log("wrong connection type")
		return
	}

	raddr := conn.DstAddr()

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
	ln       *net.UDPConn
	connChan chan net.Conn
	errChan  chan error
	connMap  udpConnMap
	config   *UDPListenConfig
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

	backlog := cfg.Backlog
	if backlog <= 0 {
		backlog = defaultBacklog
	}

	l := &udpRedirectListener{
		ln:       ln,
		connChan: make(chan net.Conn, backlog),
		errChan:  make(chan error, 1),
		config:   cfg,
	}
	go l.listenLoop()
	return l, nil
}

func (l *udpRedirectListener) listenLoop() {
	for {
		b := make([]byte, mediumBufferSize)
		n, raddr, dstAddr, err := tproxy.ReadFromUDP(l.ln, b)
		if err != nil {
			log.Logf("[red-udp] peer -> %s : %s", l.Addr(), err)
			l.Close()
			l.errChan <- err
			close(l.errChan)
			return
		}

		conn, ok := l.connMap.Get(raddr.String())
		if !ok {
			conn = newUDPServerConn(l.ln, raddr, &udpServerConnConfig{
				ttl:   l.config.TTL,
				qsize: l.config.QueueSize,
				onClose: func() {
					l.connMap.Delete(raddr.String())
					log.Logf("[red-udp] %s closed (%d)", raddr, l.connMap.Size())
				},
			})

			cc := udpRedirectServerConn{
				udpServerConn: conn,
				dstAddr:       dstAddr,
			}
			select {
			case l.connChan <- cc:
				l.connMap.Set(raddr.String(), conn)
				log.Logf("[red-udp] %s -> %s (%d)", raddr, l.Addr(), l.connMap.Size())
			default:
				conn.Close()
				log.Logf("[red-udp] %s - %s: connection queue is full (%d)",
					raddr, l.Addr(), cap(l.connChan))
			}
		}

		select {
		case conn.rChan <- b[:n]:
			if Debug {
				log.Logf("[red-udp] %s >>> %s : length %d", raddr, l.Addr(), n)
			}
		default:
			log.Logf("[red-udp] %s -> %s : recv queue is full (%d)",
				raddr, l.Addr(), cap(conn.rChan))
		}
	}
}

func (l *udpRedirectListener) Accept() (conn net.Conn, err error) {
	var ok bool
	select {
	case conn = <-l.connChan:
	case err, ok = <-l.errChan:
		if !ok {
			err = errors.New("accpet on closed listener")
		}
	}
	return
}

func (l *udpRedirectListener) Addr() net.Addr {
	return l.ln.LocalAddr()
}

func (l *udpRedirectListener) Close() error {
	err := l.ln.Close()
	l.connMap.Range(func(k interface{}, v *udpServerConn) bool {
		v.Close()
		return true
	})

	return err
}

type udpRedirectServerConn struct {
	*udpServerConn
	dstAddr *net.UDPAddr
}

func (c *udpRedirectServerConn) DstAddr() *net.UDPAddr {
	return c.dstAddr
}
