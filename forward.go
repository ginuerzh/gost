package gost

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"fmt"

	"github.com/go-gost/gosocks5"
	"github.com/go-log/log"
	smux "github.com/xtaci/smux"
)

type forwardConnector struct {
}

// ForwardConnector creates a Connector for data forward client.
func ForwardConnector() Connector {
	return &forwardConnector{}
}

func (c *forwardConnector) Connect(conn net.Conn, address string, options ...ConnectOption) (net.Conn, error) {
	return c.ConnectContext(context.Background(), conn, "tcp", address, options...)
}

func (c *forwardConnector) ConnectContext(ctx context.Context, conn net.Conn, network, address string, options ...ConnectOption) (net.Conn, error) {
	return conn, nil
}

type baseForwardHandler struct {
	raddr   string
	group   *NodeGroup
	options *HandlerOptions
}

func (h *baseForwardHandler) Init(options ...HandlerOption) {
	if h.options == nil {
		h.options = &HandlerOptions{}
	}

	for _, opt := range options {
		opt(h.options)
	}

	h.group = NewNodeGroup() // reset node group

	h.group.SetSelector(&defaultSelector{},
		WithStrategy(h.options.Strategy),
		WithFilter(&FailFilter{
			MaxFails:    h.options.MaxFails,
			FailTimeout: h.options.FailTimeout,
		}),
	)

	n := 1
	addrs := append(strings.Split(h.raddr, ","), h.options.IPs...)
	for _, addr := range addrs {
		if addr == "" {
			continue
		}

		// We treat the remote target server as a node, so we can put them in a group,
		// and perform the node selection for load balancing.
		h.group.AddNode(Node{
			ID:     n,
			Addr:   addr,
			Host:   addr,
			marker: &failMarker{},
		})

		n++
	}
}

type tcpDirectForwardHandler struct {
	*baseForwardHandler
}

// TCPDirectForwardHandler creates a server Handler for TCP port forwarding server.
// The raddr is the remote address that the server will forward to.
// NOTE: as of 2.6, remote address can be a comma-separated address list.
func TCPDirectForwardHandler(raddr string, opts ...HandlerOption) Handler {
	h := &tcpDirectForwardHandler{
		baseForwardHandler: &baseForwardHandler{
			raddr:   raddr,
			group:   NewNodeGroup(),
			options: &HandlerOptions{},
		},
	}

	for _, opt := range opts {
		opt(h.options)
	}

	return h
}

func (h *tcpDirectForwardHandler) Init(options ...HandlerOption) {
	h.baseForwardHandler.Init(options...)
}

func (h *tcpDirectForwardHandler) Handle(conn net.Conn) {
	defer conn.Close()

	log.Logf("[tcp] %s - %s", conn.RemoteAddr(), conn.LocalAddr())

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
		if len(h.group.Nodes()) > 0 {
			node, err = h.group.Next()
			if err != nil {
				log.Logf("[tcp] %s - %s : %s", conn.RemoteAddr(), conn.LocalAddr(), err)
				return
			}
		}

		cc, err = h.options.Chain.Dial(node.Addr,
			RetryChainOption(h.options.Retries),
			TimeoutChainOption(h.options.Timeout),
		)
		if err != nil {
			log.Logf("[tcp] %s -> %s : %s", conn.RemoteAddr(), conn.LocalAddr(), err)
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

	addr := node.Addr
	if addr == "" {
		addr = conn.LocalAddr().String()
	}
	log.Logf("[tcp] %s <-> %s", conn.RemoteAddr(), addr)
	transport(conn, cc)
	log.Logf("[tcp] %s >-< %s", conn.RemoteAddr(), addr)
}

type udpDirectForwardHandler struct {
	*baseForwardHandler
}

// UDPDirectForwardHandler creates a server Handler for UDP port forwarding server.
// The raddr is the remote address that the server will forward to.
// NOTE: as of 2.6, remote address can be a comma-separated address list.
func UDPDirectForwardHandler(raddr string, opts ...HandlerOption) Handler {
	h := &udpDirectForwardHandler{
		baseForwardHandler: &baseForwardHandler{
			raddr:   raddr,
			group:   NewNodeGroup(),
			options: &HandlerOptions{},
		},
	}

	for _, opt := range opts {
		opt(h.options)
	}

	return h
}

func (h *udpDirectForwardHandler) Init(options ...HandlerOption) {
	h.baseForwardHandler.Init(options...)
}

func (h *udpDirectForwardHandler) Handle(conn net.Conn) {
	defer conn.Close()

	log.Logf("[udp] %s - %s", conn.RemoteAddr(), conn.LocalAddr())

	var node Node
	var err error
	if len(h.group.Nodes()) > 0 {
		node, err = h.group.Next()
		if err != nil {
			log.Logf("[udp] %s - %s : %s", conn.RemoteAddr(), conn.LocalAddr(), err)
			return
		}
	}

	cc, err := h.options.Chain.DialContext(context.Background(), "udp", node.Addr)
	if err != nil {
		node.MarkDead()
		log.Logf("[udp] %s - %s : %s", conn.RemoteAddr(), conn.LocalAddr(), err)
		return
	}
	defer cc.Close()
	node.ResetDead()

	addr := node.Addr
	if addr == "" {
		addr = conn.LocalAddr().String()
	}
	log.Logf("[udp] %s <-> %s", conn.RemoteAddr(), addr)
	transport(conn, cc)
	log.Logf("[udp] %s >-< %s", conn.RemoteAddr(), addr)
}

type tcpRemoteForwardHandler struct {
	*baseForwardHandler
}

// TCPRemoteForwardHandler creates a server Handler for TCP remote port forwarding server.
// The raddr is the remote address that the server will forward to.
// NOTE: as of 2.6, remote address can be a comma-separated address list.
func TCPRemoteForwardHandler(raddr string, opts ...HandlerOption) Handler {
	h := &tcpRemoteForwardHandler{
		baseForwardHandler: &baseForwardHandler{
			raddr:   raddr,
			group:   NewNodeGroup(),
			options: &HandlerOptions{},
		},
	}

	for _, opt := range opts {
		opt(h.options)
	}

	return h
}

func (h *tcpRemoteForwardHandler) Init(options ...HandlerOption) {
	h.baseForwardHandler.Init(options...)
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
		if len(h.group.Nodes()) > 0 {
			node, err = h.group.Next()
			if err != nil {
				log.Logf("[rtcp] %s - %s : %s", conn.LocalAddr(), h.raddr, err)
				return
			}
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
	*baseForwardHandler
}

// UDPRemoteForwardHandler creates a server Handler for UDP remote port forwarding server.
// The raddr is the remote address that the server will forward to.
// NOTE: as of 2.6, remote address can be a comma-separated address list.
func UDPRemoteForwardHandler(raddr string, opts ...HandlerOption) Handler {
	h := &udpRemoteForwardHandler{
		baseForwardHandler: &baseForwardHandler{
			raddr:   raddr,
			group:   NewNodeGroup(),
			options: &HandlerOptions{},
		},
	}

	for _, opt := range opts {
		opt(h.options)
	}

	return h
}

func (h *udpRemoteForwardHandler) Init(options ...HandlerOption) {
	h.baseForwardHandler.Init(options...)
}

func (h *udpRemoteForwardHandler) Handle(conn net.Conn) {
	defer conn.Close()

	var node Node
	var err error
	if len(h.group.Nodes()) > 0 {
		node, err = h.group.Next()
		if err != nil {
			log.Logf("[rudp] %s - %s : %s", conn.RemoteAddr(), h.raddr, err)
			return
		}
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

type tcpRemoteForwardListener struct {
	addr       net.Addr
	chain      *Chain
	connChan   chan net.Conn
	ln         net.Listener
	session    *muxSession
	sessionMux sync.Mutex
	closed     chan struct{}
	closeMux   sync.Mutex
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
	}

	if !ln.isChainValid() {
		ln.ln, err = net.Listen("tcp", ln.addr.String())
		return ln, err
	}

	go ln.listenLoop()

	return ln, err
}

func (l *tcpRemoteForwardListener) isChainValid() bool {
	if l.chain.IsEmpty() {
		return false
	}

	lastNode := l.chain.LastNode()
	if (lastNode.Protocol == "forward" && lastNode.Transport == "ssh") ||
		lastNode.Protocol == "socks5" || lastNode.Protocol == "" {
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

	if l.isChainValid() {
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

	conn, err = socks5Handshake(conn, userSocks5HandshakeOption(l.chain.LastNode().User))
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
	conn, err := socks5Handshake(conn, userSocks5HandshakeOption(l.chain.LastNode().User))
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
	connMap  *udpConnMap
	connChan chan net.Conn
	ln       *net.UDPConn
	ttl      time.Duration
	closed   chan struct{}
	ready    chan struct{}
	once     sync.Once
	closeMux sync.Mutex
	config   *UDPListenConfig
}

// UDPRemoteForwardListener creates a Listener for UDP remote port forwarding server.
func UDPRemoteForwardListener(addr string, chain *Chain, cfg *UDPListenConfig) (Listener, error) {
	laddr, err := net.ResolveUDPAddr("udp", addr)
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

	ln := &udpRemoteForwardListener{
		addr:     laddr,
		chain:    chain,
		connMap:  new(udpConnMap),
		connChan: make(chan net.Conn, backlog),
		ready:    make(chan struct{}),
		closed:   make(chan struct{}),
		config:   cfg,
	}

	go ln.listenLoop()

	<-ln.ready

	return ln, err
}

func (l *udpRemoteForwardListener) isChainValid() bool {
	if l.chain.IsEmpty() {
		return false
	}

	lastNode := l.chain.LastNode()
	return lastNode.Protocol == "socks5" || lastNode.Protocol == ""
}

func (l *udpRemoteForwardListener) listenLoop() {
	for {
		conn, err := l.connect()
		if err != nil {
			log.Logf("[rudp] %s : %s", l.Addr(), err)
			return
		}

		l.once.Do(func() {
			close(l.ready)
		})

		func() {
			defer conn.Close()

			for {
				b := make([]byte, mediumBufferSize)
				n, raddr, err := conn.ReadFrom(b)
				if err != nil {
					log.Logf("[rudp] %s : %s", l.Addr(), err)
					break
				}

				uc, ok := l.connMap.Get(raddr.String())
				if !ok {
					uc = newUDPServerConn(conn, raddr, &udpServerConnConfig{
						ttl:   l.config.TTL,
						qsize: l.config.QueueSize,
						onClose: func() {
							l.connMap.Delete(raddr.String())
							log.Logf("[rudp] %s closed (%d)", raddr, l.connMap.Size())
						},
					})

					select {
					case l.connChan <- uc:
						l.connMap.Set(raddr.String(), uc)
						log.Logf("[rudp] %s -> %s (%d)", raddr, l.Addr(), l.connMap.Size())
					default:
						uc.Close()
						log.Logf("[rudp] %s - %s: connection queue is full (%d)",
							raddr, l.Addr(), cap(l.connChan))
					}
				}

				select {
				case uc.rChan <- b[:n]:
					if Debug {
						log.Logf("[rudp] %s >>> %s : length %d", raddr, l.Addr(), n)
					}
				default:
					log.Logf("[rudp] %s -> %s : recv queue is full", raddr, l.Addr(), cap(uc.rChan))
				}
			}
		}()
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

		if l.isChainValid() {
			var cc net.Conn
			cc, err = getSocks5UDPTunnel(l.chain, l.addr)
			if err != nil {
				log.Logf("[rudp] %s : %s", l.Addr(), err)
			} else {
				conn = cc.(net.PacketConn)
			}
		} else {
			var uc *net.UDPConn
			uc, err = net.ListenUDP("udp", l.addr.(*net.UDPAddr))
			if err == nil {
				l.addr = uc.LocalAddr()
				conn = uc
			}
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
		l.connMap.Range(func(k interface{}, v *udpServerConn) bool {
			v.Close()
			return true
		})
		close(l.closed)
	}

	return nil
}
