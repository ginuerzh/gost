package gost

import (
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"fmt"

	"github.com/ginuerzh/gosocks5"
	"github.com/go-log/log"
	smux "gopkg.in/xtaci/smux.v1"
)

type forwardConnector struct {
}

// ForwardConnector creates a Connector for data forward client.
func ForwardConnector() Connector {
	return &forwardConnector{}
}

func (c *forwardConnector) Connect(conn net.Conn, addr string, options ...ConnectOption) (net.Conn, error) {
	return conn, nil
}

type tcpDirectForwardHandler struct {
	raddr   string
	group   *NodeGroup
	options *HandlerOptions
}

// TCPDirectForwardHandler creates a server Handler for TCP port forwarding server.
// The raddr is the remote address that the server will forward to.
// NOTE: as of 2.6, remote address can be a comma-separated address list.
func TCPDirectForwardHandler(raddr string, opts ...HandlerOption) Handler {
	h := &tcpDirectForwardHandler{
		raddr: raddr,
		group: NewNodeGroup(),
	}

	if raddr == "" {
		raddr = ":0" // dummy address
	}
	for i, addr := range strings.Split(raddr, ",") {
		if addr == "" {
			continue
		}
		// We treat the remote target server as a node, so we can put them in a group,
		// and perform the node selection for load balancing.
		h.group.AddNode(Node{
			ID:   i + 1,
			Addr: addr,
			Host: addr,
		})
	}
	h.Init(opts...)

	return h
}

func (h *tcpDirectForwardHandler) Init(options ...HandlerOption) {
	if h.options == nil {
		h.options = &HandlerOptions{}
	}

	for _, opt := range options {
		opt(h.options)
	}

	h.group.SetSelector(&defaultSelector{},
		WithStrategy(h.options.Strategy),
		WithFilter(&FailFilter{
			MaxFails:    1,
			FailTimeout: 30 * time.Second,
		}),
	)
}

func (h *tcpDirectForwardHandler) Handle(conn net.Conn) {
	defer conn.Close()

	retries := 1
	if h.options.Chain != nil && h.options.Chain.Retries > 0 {
		retries = h.options.Chain.Retries
	}
	if h.options.Retries > 0 {
		retries = h.options.Retries
	}

	var cc net.Conn
	var node Node
	var err error
	for i := 0; i < retries; i++ {
		node, err = h.group.Next()
		if err != nil {
			log.Logf("[tcp] %s - %s : %s", conn.RemoteAddr(), h.raddr, err)
			return
		}

		log.Logf("[tcp] %s - %s", conn.RemoteAddr(), node.Addr)
		cc, err = h.options.Chain.Dial(node.Addr,
			RetryChainOption(h.options.Retries),
			TimeoutChainOption(h.options.Timeout),
		)
		if err != nil {
			log.Logf("[tcp] %s -> %s : %s", conn.RemoteAddr(), node.Addr, err)
			node.MarkDead()
		} else {
			break
		}
	}
	if err != nil {
		return
	}

	node.ResetDead()
	defer cc.Close()

	log.Logf("[tcp] %s <-> %s", conn.RemoteAddr(), node.Addr)
	transport(conn, cc)
	log.Logf("[tcp] %s >-< %s", conn.RemoteAddr(), node.Addr)
}

type udpDirectForwardHandler struct {
	raddr   string
	group   *NodeGroup
	options *HandlerOptions
}

// UDPDirectForwardHandler creates a server Handler for UDP port forwarding server.
// The raddr is the remote address that the server will forward to.
// NOTE: as of 2.6, remote address can be a comma-separated address list.
func UDPDirectForwardHandler(raddr string, opts ...HandlerOption) Handler {
	h := &udpDirectForwardHandler{
		raddr: raddr,
		group: NewNodeGroup(),
	}

	if raddr == "" {
		raddr = ":0" // dummy address
	}
	for i, addr := range strings.Split(raddr, ",") {
		if addr == "" {
			continue
		}
		// We treat the remote target server as a node, so we can put them in a group,
		// and perform the node selection for load balancing.
		h.group.AddNode(Node{
			ID:   i + 1,
			Addr: addr,
			Host: addr,
		})
	}

	h.Init(opts...)

	return h
}

func (h *udpDirectForwardHandler) Init(options ...HandlerOption) {
	if h.options == nil {
		h.options = &HandlerOptions{}
	}

	for _, opt := range options {
		opt(h.options)
	}

	h.group.SetSelector(&defaultSelector{},
		WithStrategy(h.options.Strategy),
		WithFilter(&FailFilter{
			MaxFails:    1,
			FailTimeout: 30 * time.Second,
		}),
	)
}

func (h *udpDirectForwardHandler) Handle(conn net.Conn) {
	defer conn.Close()

	node, err := h.group.Next()
	if err != nil {
		log.Logf("[udp] %s - %s : %s", conn.RemoteAddr(), h.raddr, err)
		return
	}

	var cc net.Conn
	if h.options.Chain.IsEmpty() {
		raddr, err := net.ResolveUDPAddr("udp", node.Addr)
		if err != nil {
			node.MarkDead()
			log.Logf("[udp] %s - %s : %s", conn.LocalAddr(), node.Addr, err)
			return
		}
		cc, err = net.DialUDP("udp", nil, raddr)
		if err != nil {
			node.MarkDead()
			log.Logf("[udp] %s - %s : %s", conn.LocalAddr(), node.Addr, err)
			return
		}
	} else {
		var err error
		cc, err = getSOCKS5UDPTunnel(h.options.Chain, nil)
		if err != nil {
			log.Logf("[udp] %s - %s : %s", conn.LocalAddr(), node.Addr, err)
			return
		}
		cc = &udpTunnelConn{Conn: cc, raddr: node.Addr}
	}

	defer cc.Close()
	node.ResetDead()

	log.Logf("[udp] %s <-> %s", conn.RemoteAddr(), node.Addr)
	transport(conn, cc)
	log.Logf("[udp] %s >-< %s", conn.RemoteAddr(), node.Addr)
}

type tcpRemoteForwardHandler struct {
	raddr   string
	group   *NodeGroup
	options *HandlerOptions
}

// TCPRemoteForwardHandler creates a server Handler for TCP remote port forwarding server.
// The raddr is the remote address that the server will forward to.
// NOTE: as of 2.6, remote address can be a comma-separated address list.
func TCPRemoteForwardHandler(raddr string, opts ...HandlerOption) Handler {
	h := &tcpRemoteForwardHandler{
		raddr: raddr,
		group: NewNodeGroup(),
	}

	for i, addr := range strings.Split(raddr, ",") {
		if addr == "" {
			continue
		}
		// We treat the remote target server as a node, so we can put them in a group,
		// and perform the node selection for load balancing.
		h.group.AddNode(Node{
			ID:   i + 1,
			Addr: addr,
			Host: addr,
		})
	}
	h.Init(opts...)

	return h
}

func (h *tcpRemoteForwardHandler) Init(options ...HandlerOption) {
	if h.options == nil {
		h.options = &HandlerOptions{}
	}
	for _, opt := range options {
		opt(h.options)
	}

	h.group.SetSelector(&defaultSelector{},
		WithStrategy(h.options.Strategy),
		WithFilter(&FailFilter{
			MaxFails:    1,
			FailTimeout: 30 * time.Second,
		}),
	)
}

func (h *tcpRemoteForwardHandler) Handle(conn net.Conn) {
	defer conn.Close()

	retries := 1
	if h.options.Retries > 0 {
		retries = h.options.Retries
	}

	var cc net.Conn
	var node Node
	var err error
	for i := 0; i < retries; i++ {
		node, err = h.group.Next()
		if err != nil {
			log.Logf("[rtcp] %s - %s : %s", conn.LocalAddr(), h.raddr, err)
			return
		}
		cc, err = net.DialTimeout("tcp", node.Addr, h.options.Timeout)
		if err != nil {
			log.Logf("[rtcp] %s -> %s : %s", conn.LocalAddr(), node.Addr, err)
			node.MarkDead()
		} else {
			break
		}
	}
	if err != nil {
		return
	}

	defer cc.Close()
	node.ResetDead()

	log.Logf("[rtcp] %s <-> %s", conn.LocalAddr(), node.Addr)
	transport(cc, conn)
	log.Logf("[rtcp] %s >-< %s", conn.LocalAddr(), node.Addr)
}

type udpRemoteForwardHandler struct {
	raddr   string
	group   *NodeGroup
	options *HandlerOptions
}

// UDPRemoteForwardHandler creates a server Handler for UDP remote port forwarding server.
// The raddr is the remote address that the server will forward to.
// NOTE: as of 2.6, remote address can be a comma-separated address list.
func UDPRemoteForwardHandler(raddr string, opts ...HandlerOption) Handler {
	h := &udpRemoteForwardHandler{
		raddr: raddr,
		group: NewNodeGroup(),
	}

	for i, addr := range strings.Split(raddr, ",") {
		if addr == "" {
			continue
		}
		// We treat the remote target server as a node, so we can put them in a group,
		// and perform the node selection for load balancing.
		h.group.AddNode(Node{
			ID:   i + 1,
			Addr: addr,
			Host: addr,
		})
	}

	h.Init(opts...)

	return h
}

func (h *udpRemoteForwardHandler) Init(options ...HandlerOption) {
	if h.options == nil {
		h.options = &HandlerOptions{}
	}

	for _, opt := range options {
		opt(h.options)
	}
	h.group.SetSelector(&defaultSelector{},
		WithStrategy(h.options.Strategy),
		WithFilter(&FailFilter{
			MaxFails:    1,
			FailTimeout: 30 * time.Second,
		}),
	)
}

func (h *udpRemoteForwardHandler) Handle(conn net.Conn) {
	defer conn.Close()

	node, err := h.group.Next()
	if err != nil {
		log.Logf("[rudp] %s - %s : %s", conn.RemoteAddr(), h.raddr, err)
		return
	}

	raddr, err := net.ResolveUDPAddr("udp", node.Addr)
	if err != nil {
		node.MarkDead()
		log.Logf("[rudp] %s - %s : %s", conn.RemoteAddr(), node.Addr, err)
		return
	}
	cc, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		node.MarkDead()
		log.Logf("[rudp] %s - %s : %s", conn.RemoteAddr(), node.Addr, err)
		return
	}
	defer cc.Close()
	node.ResetDead()

	log.Logf("[rudp] %s <-> %s", conn.RemoteAddr(), node.Addr)
	transport(conn, cc)
	log.Logf("[rudp] %s >-< %s", conn.RemoteAddr(), node.Addr)
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
			l.Close()
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
	ttl := c.ttl
	if ttl == 0 {
		ttl = defaultTTL
	}
	timer := time.NewTimer(ttl)
	defer timer.Stop()

	for {
		select {
		case <-c.nopChan:
			if !timer.Stop() {
				<-timer.C
			}
			timer.Reset(ttl)
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
	return c.conn.SetDeadline(t)
}

func (c *udpServerConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *udpServerConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

type tcpRemoteForwardListener struct {
	addr       net.Addr
	chain      *Chain
	connChan   chan net.Conn
	ln         net.Listener
	session    *muxSession
	sessionMux sync.Mutex
	closed     chan struct{}
	closeMux   sync.Mutex
	errChan    chan error
}

// TCPRemoteForwardListener creates a Listener for TCP remote port forwarding server.
func TCPRemoteForwardListener(addr string, chain *Chain) (Listener, error) {
	laddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, err
	}

	ln := &tcpRemoteForwardListener{
		addr:     laddr,
		chain:    chain,
		connChan: make(chan net.Conn, 1024),
		closed:   make(chan struct{}),
		errChan:  make(chan error),
	}

	if !ln.isChainValid() {
		ln.ln, err = net.Listen("tcp", ln.addr.String())
		return ln, err
	}

	go ln.listenLoop()

	return ln, err
}

func (l *tcpRemoteForwardListener) isChainValid() bool {
	lastNode := l.chain.LastNode()
	if (lastNode.Protocol == "forward" && lastNode.Transport == "ssh") ||
		lastNode.Protocol == "socks5" {
		return true
	}
	return false
}

func (l *tcpRemoteForwardListener) listenLoop() {
	var tempDelay time.Duration

	for {
		conn, err := l.accept()

		select {
		case <-l.closed:
			if conn != nil {
				conn.Close()
			}
			return
		default:
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
			log.Logf("[rtcp] accept error: %v; retrying in %v", err, tempDelay)
			time.Sleep(tempDelay)
			continue
		}

		tempDelay = 0

		select {
		case l.connChan <- conn:
		default:
			conn.Close()
			log.Logf("[rtcp] %s - %s: connection queue is full", conn.RemoteAddr(), conn.LocalAddr())
		}
	}
}

func (l *tcpRemoteForwardListener) Accept() (conn net.Conn, err error) {
	if l.ln != nil {
		return l.ln.Accept()
	}

	select {
	case conn = <-l.connChan:
	case <-l.closed:
		err = errors.New("closed")
	}

	return
}

func (l *tcpRemoteForwardListener) accept() (conn net.Conn, err error) {
	lastNode := l.chain.LastNode()
	if lastNode.Protocol == "forward" && lastNode.Transport == "ssh" {
		return l.chain.Dial(l.addr.String())
	}

	if lastNode.Protocol == "socks5" {
		if lastNode.GetBool("mbind") {
			return l.muxAccept() // multiplexing support for binding.
		}

		cc, er := l.chain.Conn()
		if er != nil {
			return nil, er
		}
		conn, err = l.waitConnectSOCKS5(cc)
		if err != nil {
			cc.Close()
		}
	}
	return
}

func (l *tcpRemoteForwardListener) muxAccept() (conn net.Conn, err error) {
	session, err := l.getSession()
	if err != nil {
		return nil, err
	}
	cc, err := session.Accept()
	if err != nil {
		session.Close()
		return nil, err
	}

	return cc, nil
}

func (l *tcpRemoteForwardListener) getSession() (s *muxSession, err error) {
	l.sessionMux.Lock()
	defer l.sessionMux.Unlock()

	if l.session != nil && !l.session.IsClosed() {
		return l.session, nil
	}

	conn, err := l.chain.Conn()
	if err != nil {
		return nil, err
	}

	defer func(c net.Conn) {
		if err != nil {
			c.Close()
		}
	}(conn)

	conn.SetDeadline(time.Now().Add(HandshakeTimeout))
	defer conn.SetDeadline(time.Time{})

	conn, err = socks5Handshake(conn, nil, l.chain.LastNode().User)
	if err != nil {
		return nil, err
	}
	req := gosocks5.NewRequest(CmdMuxBind, toSocksAddr(l.addr))
	if err := req.Write(conn); err != nil {
		log.Log("[rtcp] SOCKS5 BIND request: ", err)
		return nil, err
	}

	rep, err := gosocks5.ReadReply(conn)
	if err != nil {
		log.Log("[rtcp] SOCKS5 BIND reply: ", err)
		return nil, err
	}
	if rep.Rep != gosocks5.Succeeded {
		log.Logf("[rtcp] bind on %s failure", l.addr)
		return nil, fmt.Errorf("Bind on %s failure", l.addr.String())
	}
	log.Logf("[rtcp] BIND ON %s OK", rep.Addr)

	// Upgrade connection to multiplex stream.
	session, err := smux.Server(conn, smux.DefaultConfig())
	if err != nil {
		return nil, err
	}
	l.session = &muxSession{
		conn:    conn,
		session: session,
	}

	return l.session, nil
}

func (l *tcpRemoteForwardListener) waitConnectSOCKS5(conn net.Conn) (net.Conn, error) {
	conn, err := socks5Handshake(conn, nil, l.chain.LastNode().User)
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
	if l.ln != nil {
		return l.ln.Addr()
	}
	return l.addr
}

func (l *tcpRemoteForwardListener) Close() error {
	if l.ln != nil {
		return l.ln.Close()
	}

	l.closeMux.Lock()
	defer l.closeMux.Unlock()

	select {
	case <-l.closed:
		return nil
	default:
		close(l.closed)
	}
	return nil
}

type udpRemoteForwardListener struct {
	addr     net.Addr
	chain    *Chain
	conns    map[string]*udpServerConn
	connChan chan net.Conn
	ln       *net.UDPConn
	errChan  chan error
	ttl      time.Duration
	closed   chan struct{}
	closeMux sync.Mutex
	once     sync.Once
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

	err = <-ln.errChan

	return ln, err
}

func (l *udpRemoteForwardListener) isChainValid() bool {
	lastNode := l.chain.LastNode()
	return lastNode.Protocol == "socks5"
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
			var uc *net.UDPConn
			uc, err = net.ListenUDP("udp", l.addr.(*net.UDPAddr))
			if err == nil {
				l.addr = uc.LocalAddr()
				conn = uc
			}
		}

		l.once.Do(func() {
			l.errChan <- err
			close(l.errChan)
		})

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
	select {
	case conn = <-l.connChan:
	case <-l.closed:
		err = errors.New("accpet on closed listener")
	}
	return
}

func (l *udpRemoteForwardListener) Addr() net.Addr {
	return l.addr
}

func (l *udpRemoteForwardListener) Close() error {
	l.closeMux.Lock()
	defer l.closeMux.Unlock()

	select {
	case <-l.closed:
		return nil
	default:
		close(l.closed)
	}

	return nil
}
