package gost

import (
	"errors"
	"net"
	"sync"
	"time"

	"fmt"

	"github.com/ginuerzh/gosocks5"
	"github.com/go-log/log"
)

type tcpForwardHandler struct {
	raddr   string
	options *HandlerOptions
}

// TCPForwardHandler creates a server Handler for TCP port forwarding server.
// The raddr is the remote address that the server will forward to.
func TCPForwardHandler(raddr string, opts ...HandlerOption) Handler {
	h := &tcpForwardHandler{
		raddr:   raddr,
		options: &HandlerOptions{},
	}
	for _, opt := range opts {
		opt(h.options)
	}
	return h
}

func (h *tcpForwardHandler) Handle(conn net.Conn) {
	defer conn.Close()

	log.Logf("[tcp] %s - %s", conn.RemoteAddr(), h.raddr)
	cc, err := h.options.Chain.Dial(h.raddr)
	if err != nil {
		log.Logf("[tcp] %s -> %s : %s", conn.RemoteAddr(), h.raddr, err)
		return
	}
	defer cc.Close()

	log.Logf("[tcp] %s <-> %s", conn.RemoteAddr(), h.raddr)
	transport(conn, cc)
	log.Logf("[tcp] %s >-< %s", conn.RemoteAddr(), h.raddr)
}

type udpForwardHandler struct {
	raddr   string
	ttl     time.Duration
	options *HandlerOptions
}

// UDPForwardHandler creates a server Handler for UDP port forwarding server.
// The raddr is the remote address that the server will forward to.
func UDPForwardHandler(raddr string, opts ...HandlerOption) Handler {
	h := &udpForwardHandler{
		raddr:   raddr,
		options: &HandlerOptions{},
	}
	for _, opt := range opts {
		opt(h.options)
	}
	return h
}

func (h *udpForwardHandler) Handle(conn net.Conn) {
	defer conn.Close()

	var cc net.Conn
	if h.options.Chain.IsEmpty() {
		raddr, err := net.ResolveUDPAddr("udp", h.raddr)
		if err != nil {
			log.Logf("[udp] %s - %s : %s", conn.LocalAddr(), h.raddr, err)
			return
		}
		cc, err = net.DialUDP("udp", nil, raddr)
		if err != nil {
			log.Logf("[udp] %s - %s : %s", conn.LocalAddr(), h.raddr, err)
			return
		}
	} else {
		var err error
		cc, err = h.getUDPTunnel()
		if err != nil {
			log.Logf("[udp] %s - %s : %s", conn.LocalAddr(), h.raddr, err)
			return
		}
		cc = &udpTunnelConn{Conn: cc, raddr: h.raddr}
	}

	defer cc.Close()

	log.Logf("[udp] %s <-> %s", conn.RemoteAddr(), h.raddr)
	transport(conn, cc)
	log.Logf("[udp] %s >-< %s", conn.RemoteAddr(), h.raddr)
}

func (h *udpForwardHandler) getUDPTunnel() (net.Conn, error) {
	conn, err := h.options.Chain.Conn()
	if err != nil {
		return nil, err
	}
	cc, err := socks5Handshake(conn, h.options.Chain.LastNode().User)
	if err != nil {
		conn.Close()
		return nil, err
	}
	conn = cc

	conn.SetWriteDeadline(time.Now().Add(WriteTimeout))
	if err = gosocks5.NewRequest(CmdUDPTun, nil).Write(conn); err != nil {
		conn.Close()
		return nil, err
	}
	conn.SetWriteDeadline(time.Time{})

	conn.SetReadDeadline(time.Now().Add(ReadTimeout))
	reply, err := gosocks5.ReadReply(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	conn.SetReadDeadline(time.Time{})

	if reply.Rep != gosocks5.Succeeded {
		conn.Close()
		return nil, errors.New("UDP tunnel failure")
	}
	return conn, nil
}

type rtcpForwardHandler struct {
	raddr   string
	options *HandlerOptions
}

// RTCPForwardHandler creates a server Handler for TCP remote port forwarding server.
// The raddr is the remote address that the server will forward to.
func RTCPForwardHandler(raddr string, opts ...HandlerOption) Handler {
	h := &rtcpForwardHandler{
		raddr:   raddr,
		options: &HandlerOptions{},
	}
	for _, opt := range opts {
		opt(h.options)
	}
	return h
}

func (h *rtcpForwardHandler) Handle(conn net.Conn) {
	defer conn.Close()

	cc, err := net.DialTimeout("tcp", h.raddr, DialTimeout)
	if err != nil {
		log.Logf("[rtcp] %s -> %s : %s", conn.LocalAddr(), h.raddr, err)
		return
	}
	defer cc.Close()

	log.Logf("[rtcp] %s <-> %s", conn.LocalAddr(), h.raddr)
	transport(cc, conn)
	log.Logf("[rtcp] %s >-< %s", conn.LocalAddr(), h.raddr)
}

type rudpForwardHandler struct {
	laddr   string
	raddr   string
	options *HandlerOptions
}

// RUDPForwardHandler creates a server Handler for UDP remote port forwarding server.
// The raddr is the remote address that the server will forward to.
func RUDPForwardHandler(laddr, raddr string, opts ...HandlerOption) Handler {
	h := &rudpForwardHandler{
		laddr:   laddr,
		raddr:   raddr,
		options: &HandlerOptions{},
	}
	for _, opt := range opts {
		opt(h.options)
	}
	return h
}

func (h *rudpForwardHandler) Handle(conn net.Conn) {
	defer conn.Close()

	// TODO: handle connection

	/*
		ra, err := net.ResolveUDPAddr("udp", h.raddr)
		if err != nil {
			log.Logf("[rudp] %s - %s : %s", h.laddr, h.raddr, err)
			return
		}

		for {
			dgram, err := gosocks5.ReadUDPDatagram(conn)
			if err != nil {
				log.Logf("[rudp] %s -> %s : %s", h.laddr, h.raddr, err)
				return
			}

			go func() {
				b := make([]byte, mediumBufferSize)

				relay, err := net.DialUDP("udp", nil, ra)
				if err != nil {
					log.Logf("[rudp] %s -> %s : %s", h.laddr, h.raddr, err)
					return
				}
				defer relay.Close()

				if _, err := relay.Write(dgram.Data); err != nil {
					log.Logf("[rudp] %s -> %s : %s", h.laddr, h.raddr, err)
					return
				}
				if Debug {
					log.Logf("[rudp] %s >>> %s length: %d", h.laddr, h.raddr, len(dgram.Data))
				}
				relay.SetReadDeadline(time.Now().Add(ReadTimeout))
				n, err := relay.Read(b)
				if err != nil {
					log.Logf("[rudp] %s <- %s : %s", h.laddr, h.raddr, err)
					return
				}
				relay.SetReadDeadline(time.Time{})
				if Debug {
					log.Logf("[rudp] %s <<< %s length: %d", h.laddr, h.raddr, n)
				}
				conn.SetWriteDeadline(time.Now().Add(WriteTimeout))
				if err := gosocks5.NewUDPDatagram(gosocks5.NewUDPHeader(uint16(n), 0, dgram.Header.Addr), b[:n]).Write(conn); err != nil {
					log.Logf("[rudp] %s <- %s : %s", h.laddr, h.raddr, err)
					return
				}
				conn.SetWriteDeadline(time.Time{})
			}()
		}
	*/
}

type udpForwardListener struct {
	ln        *net.UDPConn
	conns     map[string]*udpServerConn
	connMutex sync.Mutex
	connChan  chan net.Conn
	errChan   chan error
	ttl       time.Duration
}

// UDPForwardListener creates a Listener for UDP port forwarding server.
func UDPForwardListener(addr string, ttl time.Duration) (Listener, error) {
	laddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	ln, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return nil, err
	}
	l := &udpForwardListener{
		ln:       ln,
		conns:    make(map[string]*udpServerConn),
		connChan: make(chan net.Conn, 1024),
		errChan:  make(chan error, 1),
		ttl:      ttl,
	}
	go l.listenLoop()
	return l, nil
}

func (l *udpForwardListener) listenLoop() {
	for {
		b := make([]byte, mediumBufferSize)
		n, raddr, err := l.ln.ReadFromUDP(b)
		if err != nil {
			log.Logf("[udp] peer -> %s : %s", l.Addr(), err)
			l.ln.Close()
			l.errChan <- err
			close(l.errChan)
		}
		if Debug {
			log.Logf("[udp] %s >>> %s : length %d", raddr, l.Addr(), n)
		}
		conn, ok := l.conns[raddr.String()]
		if !ok || conn.Closed() {
			conn = newUDPServerConn(l.ln, raddr, l.ttl)
			l.conns[raddr.String()] = conn

			select {
			case l.connChan <- conn:
			default:
				conn.Close()
				log.Logf("[udp] %s - %s: connection queue is full", raddr, l.Addr())
			}
		}

		select {
		case conn.rChan <- b[:n]:
		default:
			log.Logf("[udp] %s -> %s : write queue is full", raddr, l.Addr())
		}
	}
}

func (l *udpForwardListener) Accept() (conn net.Conn, err error) {
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

func (l *udpForwardListener) Addr() net.Addr {
	return l.ln.LocalAddr()
}

func (l *udpForwardListener) Close() error {
	return l.ln.Close()
}

type udpServerConn struct {
	conn         *net.UDPConn
	raddr        *net.UDPAddr
	rChan, wChan chan []byte
	closed       chan struct{}
	brokenChan   chan struct{}
	closeMutex   sync.Mutex
	ttl          time.Duration
	nopChan      chan int
}

func newUDPServerConn(conn *net.UDPConn, raddr *net.UDPAddr, ttl time.Duration) *udpServerConn {
	c := &udpServerConn{
		conn:       conn,
		raddr:      raddr,
		rChan:      make(chan []byte, 128),
		wChan:      make(chan []byte, 128),
		closed:     make(chan struct{}),
		brokenChan: make(chan struct{}),
		nopChan:    make(chan int),
		ttl:        ttl,
	}
	go c.writeLoop()
	go c.ttlWait()
	return c
}

func (c *udpServerConn) Read(b []byte) (n int, err error) {
	select {
	case bb := <-c.rChan:
		n = copy(b, bb)
		if n != len(bb) {
			err = errors.New("read partial data")
			return
		}
	case <-c.brokenChan:
		err = errors.New("Broken pipe")
	case <-c.closed:
		err = errors.New("read from closed connection")
		return
	}

	select {
	case c.nopChan <- n:
	default:
	}
	return
}

func (c *udpServerConn) Write(b []byte) (n int, err error) {
	if len(b) == 0 {
		return 0, nil
	}
	select {
	case c.wChan <- b:
		n = len(b)
	case <-c.brokenChan:
		err = errors.New("Broken pipe")
	case <-c.closed:
		err = errors.New("write to closed connection")
		return
	}

	select {
	case c.nopChan <- n:
	default:
	}

	return
}

func (c *udpServerConn) Close() error {
	c.closeMutex.Lock()
	defer c.closeMutex.Unlock()

	select {
	case <-c.closed:
		return errors.New("connection is closed")
	default:
		close(c.closed)
	}
	return nil
}

func (c *udpServerConn) Closed() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}

func (c *udpServerConn) writeLoop() {
	for {
		select {
		case b, ok := <-c.wChan:
			if !ok {
				return
			}
			n, err := c.conn.WriteToUDP(b, c.raddr)
			if err != nil {
				log.Logf("[udp] %s <<< %s : %s", c.RemoteAddr(), c.LocalAddr(), err)
				return
			}
			if Debug {
				log.Logf("[udp] %s <<< %s : length %d", c.RemoteAddr(), c.LocalAddr(), n)
			}
		case <-c.brokenChan:
			return
		case <-c.closed:
			return
		}
	}
}

func (c *udpServerConn) ttlWait() {
	timer := time.NewTimer(c.ttl)

	for {
		select {
		case <-c.nopChan:
			timer.Reset(c.ttl)
		case <-timer.C:
			close(c.brokenChan)
			return
		case <-c.closed:
			return
		}
	}
}

func (c *udpServerConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *udpServerConn) RemoteAddr() net.Addr {
	return c.raddr
}

func (c *udpServerConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *udpServerConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *udpServerConn) SetWriteDeadline(t time.Time) error {
	return nil
}

type udpTunnelConn struct {
	raddr string
	net.Conn
}

func (c *udpTunnelConn) Read(b []byte) (n int, err error) {
	dgram, err := gosocks5.ReadUDPDatagram(c.Conn)
	if err != nil {
		return
	}
	n = copy(b, dgram.Data)
	return
}

func (c *udpTunnelConn) Write(b []byte) (n int, err error) {
	addr, err := net.ResolveUDPAddr("udp", c.raddr)
	if err != nil {
		return
	}
	dgram := gosocks5.NewUDPDatagram(gosocks5.NewUDPHeader(uint16(len(b)), 0, toSocksAddr(addr)), b)
	if err = dgram.Write(c.Conn); err != nil {
		return
	}
	return len(b), nil
}

type rtcpForwardListener struct {
	addr   net.Addr
	chain  *Chain
	closed chan struct{}
}

// RTCPForwardListener creates a Listener for TCP remote port forwarding server.
func RTCPForwardListener(addr string, chain *Chain) (Listener, error) {
	laddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, err
	}

	return &rtcpForwardListener{
		addr:   laddr,
		chain:  chain,
		closed: make(chan struct{}),
	}, nil
}

func (l *rtcpForwardListener) Accept() (net.Conn, error) {
	select {
	case <-l.closed:
		return nil, errors.New("closed")
	default:
	}

	var tempDelay time.Duration
	for {
		conn, err := l.accept()
		if err != nil {
			if tempDelay == 0 {
				tempDelay = 1000 * time.Millisecond
			} else {
				tempDelay *= 2
			}
			if max := 6 * time.Second; tempDelay > max {
				tempDelay = max
			}
			log.Logf("[ssh-rtcp] Accept error: %v; retrying in %v", err, tempDelay)
			time.Sleep(tempDelay)
			continue
		}
		return conn, nil
	}
}

func (l *rtcpForwardListener) accept() (conn net.Conn, err error) {
	lastNode := l.chain.LastNode()
	if lastNode.Protocol == "forward" && lastNode.Transport == "ssh" {
		conn, err = l.chain.Dial(l.addr.String())
	} else if lastNode.Protocol == "socks5" {
		cc, er := l.chain.Conn()
		if er != nil {
			return nil, er
		}
		conn, err = l.waitConnectSOCKS5(cc)
		if err != nil {
			cc.Close()
		}
	} else {
		err = errors.New("invalid chain")
	}
	return
}

func (l *rtcpForwardListener) waitConnectSOCKS5(conn net.Conn) (net.Conn, error) {
	conn, err := socks5Handshake(conn, l.chain.LastNode().User)
	if err != nil {
		return nil, err
	}
	req := gosocks5.NewRequest(gosocks5.CmdBind, toSocksAddr(l.addr))
	if err := req.Write(conn); err != nil {
		log.Log("[rtcp] SOCKS5 BIND request: ", err)
		return nil, err
	}

	// first reply, bind status
	conn.SetReadDeadline(time.Now().Add(ReadTimeout))
	rep, err := gosocks5.ReadReply(conn)
	if err != nil {
		log.Log("[rtcp] SOCKS5 BIND reply: ", err)
		return nil, err
	}
	conn.SetReadDeadline(time.Time{})
	if rep.Rep != gosocks5.Succeeded {
		log.Logf("[rtcp] bind on %s failure", l.addr)
		return nil, fmt.Errorf("Bind on %s failure", l.addr.String())
	}
	log.Logf("[rtcp] BIND ON %s OK", rep.Addr)

	// second reply, peer connected
	rep, err = gosocks5.ReadReply(conn)
	if err != nil {
		log.Log("[rtcp]", err)
		return nil, err
	}
	if rep.Rep != gosocks5.Succeeded {
		log.Logf("[rtcp] peer connect failure: %d", rep.Rep)
		return nil, errors.New("peer connect failure")
	}

	log.Logf("[rtcp] PEER %s CONNECTED", rep.Addr)
	return conn, nil
}

func (l *rtcpForwardListener) Addr() net.Addr {
	return l.addr
}

func (l *rtcpForwardListener) Close() error {
	close(l.closed)
	return nil
}

type rudpForwardListener struct {
	addr  net.Addr
	chain *Chain
	close chan struct{}
}

// RUDPForwardListener creates a Listener for UDP remote port forwarding server.
func RUDPForwardListener(addr string, chain *Chain) (Listener, error) {
	laddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}

	return &rudpForwardListener{
		addr:  laddr,
		chain: chain,
		close: make(chan struct{}),
	}, nil
}

func (l *rudpForwardListener) Accept() (net.Conn, error) {
	select {
	case <-l.close:
		return nil, errors.New("closed")
	default:
	}

	conn, err := l.chain.Conn()
	if err != nil {
		return nil, err
	}
	cc, err := l.handshake(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	conn = cc

	return cc, nil
}

func (l *rudpForwardListener) handshake(conn net.Conn) (net.Conn, error) {
	conn, err := socks5Handshake(conn, l.chain.LastNode().User)
	if err != nil {
		return nil, err
	}
	req := gosocks5.NewRequest(CmdUDPTun, toSocksAddr(l.addr))
	if err := req.Write(conn); err != nil {
		log.Log("[rudp] SOCKS5 UDP relay request: ", err)
		return nil, err
	}

	conn.SetReadDeadline(time.Now().Add(ReadTimeout))
	rep, err := gosocks5.ReadReply(conn)
	if err != nil {
		log.Log("[rudp] SOCKS5 UDP relay reply: ", err)
		return nil, err
	}
	conn.SetReadDeadline(time.Time{})
	if rep.Rep != gosocks5.Succeeded {
		log.Logf("[rudp] bind on %s failure: %d", l.addr, rep.Rep)
		return nil, fmt.Errorf("Bind on %s failure", l.addr.String())
	}
	log.Logf("[rudp] BIND ON %s OK", rep.Addr)
	return conn, nil
}

func (l *rudpForwardListener) Addr() net.Addr {
	return l.addr
}

func (l *rudpForwardListener) Close() error {
	close(l.close)
	return nil
}
