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

type tcpDirectForwardHandler struct {
	raddr   string
	options *HandlerOptions
}

// TCPDirectForwardHandler creates a server Handler for TCP port forwarding server.
// The raddr is the remote address that the server will forward to.
func TCPDirectForwardHandler(raddr string, opts ...HandlerOption) Handler {
	h := &tcpDirectForwardHandler{
		raddr:   raddr,
		options: &HandlerOptions{},
	}
	for _, opt := range opts {
		opt(h.options)
	}
	return h
}

func (h *tcpDirectForwardHandler) Handle(conn net.Conn) {
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

type udpDirectForwardHandler struct {
	raddr   string
	options *HandlerOptions
}

// UDPDirectForwardHandler creates a server Handler for UDP port forwarding server.
// The raddr is the remote address that the server will forward to.
func UDPDirectForwardHandler(raddr string, opts ...HandlerOption) Handler {
	h := &udpDirectForwardHandler{
		raddr:   raddr,
		options: &HandlerOptions{},
	}
	for _, opt := range opts {
		opt(h.options)
	}
	return h
}

func (h *udpDirectForwardHandler) Handle(conn net.Conn) {
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
		cc, err = getSOCKS5UDPTunnel(h.options.Chain, nil)
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

type tcpRemoteForwardHandler struct {
	raddr   string
	options *HandlerOptions
}

// TCPRemoteForwardHandler creates a server Handler for TCP remote port forwarding server.
// The raddr is the remote address that the server will forward to.
func TCPRemoteForwardHandler(raddr string, opts ...HandlerOption) Handler {
	h := &tcpRemoteForwardHandler{
		raddr:   raddr,
		options: &HandlerOptions{},
	}
	for _, opt := range opts {
		opt(h.options)
	}
	return h
}

func (h *tcpRemoteForwardHandler) Handle(conn net.Conn) {
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

type udpRemoteForwardHandler struct {
	raddr   string
	options *HandlerOptions
}

// UDPRemoteForwardHandler creates a server Handler for UDP remote port forwarding server.
// The raddr is the remote address that the server will forward to.
func UDPRemoteForwardHandler(raddr string, opts ...HandlerOption) Handler {
	h := &udpRemoteForwardHandler{
		raddr:   raddr,
		options: &HandlerOptions{},
	}
	for _, opt := range opts {
		opt(h.options)
	}
	return h
}

func (h *udpRemoteForwardHandler) Handle(conn net.Conn) {
	defer conn.Close()

	raddr, err := net.ResolveUDPAddr("udp", h.raddr)
	if err != nil {
		log.Logf("[rudp] %s - %s : %s", conn.RemoteAddr(), h.raddr, err)
		return
	}
	cc, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		log.Logf("[rudp] %s - %s : %s", conn.RemoteAddr(), h.raddr, err)
		return
	}

	log.Logf("[rudp] %s <-> %s", conn.RemoteAddr(), h.raddr)
	transport(conn, cc)
	log.Logf("[rudp] %s >-< %s", conn.RemoteAddr(), h.raddr)
}

type udpDirectForwardListener struct {
	ln       net.PacketConn
	conns    map[string]*udpServerConn
	connChan chan net.Conn
	errChan  chan error
	ttl      time.Duration
}

// UDPDirectForwardListener creates a Listener for UDP port forwarding server.
func UDPDirectForwardListener(addr string, ttl time.Duration) (Listener, error) {
	laddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	ln, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return nil, err
	}
	l := &udpDirectForwardListener{
		ln:       ln,
		conns:    make(map[string]*udpServerConn),
		connChan: make(chan net.Conn, 1024),
		errChan:  make(chan error, 1),
		ttl:      ttl,
	}
	go l.listenLoop()
	return l, nil
}

func (l *udpDirectForwardListener) listenLoop() {
	for {
		b := make([]byte, mediumBufferSize)
		n, raddr, err := l.ln.ReadFrom(b)
		if err != nil {
			log.Logf("[udp] peer -> %s : %s", l.Addr(), err)
			l.ln.Close()
			l.errChan <- err
			close(l.errChan)
			return
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
			log.Logf("[udp] %s -> %s : read queue is full", raddr, l.Addr())
		}
	}
}

func (l *udpDirectForwardListener) Accept() (conn net.Conn, err error) {
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

func (l *udpDirectForwardListener) Addr() net.Addr {
	return l.ln.LocalAddr()
}

func (l *udpDirectForwardListener) Close() error {
	return l.ln.Close()
}

type udpServerConn struct {
	conn         net.PacketConn
	raddr        net.Addr
	rChan, wChan chan []byte
	closed       chan struct{}
	brokenChan   chan struct{}
	closeMutex   sync.Mutex
	ttl          time.Duration
	nopChan      chan int
}

func newUDPServerConn(conn net.PacketConn, raddr net.Addr, ttl time.Duration) *udpServerConn {
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
			n, err := c.conn.WriteTo(b, c.raddr)
			if err != nil {
				log.Logf("[udp] %s - %s : %s", c.RemoteAddr(), c.LocalAddr(), err)
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

type tcpRemoteForwardListener struct {
	addr   net.Addr
	chain  *Chain
	ln     net.Listener
	closed chan struct{}
}

// TCPRemoteForwardListener creates a Listener for TCP remote port forwarding server.
func TCPRemoteForwardListener(addr string, chain *Chain) (Listener, error) {
	laddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, err
	}

	return &tcpRemoteForwardListener{
		addr:   laddr,
		chain:  chain,
		closed: make(chan struct{}),
	}, nil
}

func (l *tcpRemoteForwardListener) Accept() (net.Conn, error) {
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
			log.Logf("[rtcp] Accept error: %v; retrying in %v", err, tempDelay)
			time.Sleep(tempDelay)
			continue
		}
		return conn, nil
	}
}

func (l *tcpRemoteForwardListener) accept() (conn net.Conn, err error) {
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
		if l.ln == nil {
			l.ln, err = net.Listen("tcp", l.addr.String())
			if err != nil {
				return
			}
		}
		conn, err = l.ln.Accept()
	}
	return
}

func (l *tcpRemoteForwardListener) waitConnectSOCKS5(conn net.Conn) (net.Conn, error) {
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

func (l *tcpRemoteForwardListener) Addr() net.Addr {
	return l.addr
}

func (l *tcpRemoteForwardListener) Close() error {
	close(l.closed)
	return nil
}

type udpRemoteForwardListener struct {
	addr     *net.UDPAddr
	chain    *Chain
	conns    map[string]*udpServerConn
	connChan chan net.Conn
	errChan  chan error
	ttl      time.Duration
	closed   chan struct{}
}

// UDPRemoteForwardListener creates a Listener for UDP remote port forwarding server.
func UDPRemoteForwardListener(addr string, chain *Chain, ttl time.Duration) (Listener, error) {
	laddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}

	ln := &udpRemoteForwardListener{
		addr:     laddr,
		chain:    chain,
		conns:    make(map[string]*udpServerConn),
		connChan: make(chan net.Conn, 1024),
		errChan:  make(chan error, 1),
		ttl:      ttl,
		closed:   make(chan struct{}),
	}
	go ln.listenLoop()
	return ln, nil
}

func (l *udpRemoteForwardListener) listenLoop() {
	for {
		conn, err := l.connect()
		if err != nil {
			log.Logf("[rudp] %s : %s", l.Addr(), err)
			return
		}

		defer conn.Close()

		for {
			b := make([]byte, mediumBufferSize)
			n, raddr, err := conn.ReadFrom(b)
			if err != nil {
				log.Logf("[rudp] %s : %s", l.Addr(), err)
				break
			}
			if Debug {
				log.Logf("[udp] %s >>> %s : length %d", raddr, l.Addr(), n)
			}
			uc, ok := l.conns[raddr.String()]
			if !ok || uc.Closed() {
				uc = newUDPServerConn(conn, raddr, l.ttl)
				l.conns[raddr.String()] = uc

				select {
				case l.connChan <- uc:
				default:
					uc.Close()
					log.Logf("[rudp] %s - %s: connection queue is full", raddr, l.Addr())
				}
			}

			select {
			case uc.rChan <- b[:n]:
			default:
				log.Logf("[rudp] %s -> %s : write queue is full", raddr, l.Addr())
			}
		}
	}

}

func (l *udpRemoteForwardListener) connect() (conn net.PacketConn, err error) {
	var tempDelay time.Duration

	for {
		select {
		case <-l.closed:
			return nil, errors.New("closed")
		default:
		}

		lastNode := l.chain.LastNode()
		if lastNode.Protocol == "socks5" {
			var cc net.Conn
			cc, err = getSOCKS5UDPTunnel(l.chain, l.addr)
			if err != nil {
				log.Logf("[rudp] %s : %s", l.Addr(), err)
			} else {
				conn = &udpTunnelConn{Conn: cc}
			}
		} else {
			conn, err = net.ListenUDP("udp", l.addr)
		}

		if err != nil {
			if tempDelay == 0 {
				tempDelay = 1000 * time.Millisecond
			} else {
				tempDelay *= 2
			}
			if max := 6 * time.Second; tempDelay > max {
				tempDelay = max
			}
			log.Logf("[rudp] Accept error: %v; retrying in %v", err, tempDelay)
			time.Sleep(tempDelay)
			continue
		}
		return
	}
}

func (l *udpRemoteForwardListener) Accept() (conn net.Conn, err error) {
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

func (l *udpRemoteForwardListener) Addr() net.Addr {
	return l.addr
}

func (l *udpRemoteForwardListener) Close() error {
	close(l.closed)
	return nil
}
