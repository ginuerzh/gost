package gost

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/ginuerzh/gosocks4"
	"github.com/ginuerzh/gosocks5"
	"github.com/go-log/log"
	smux "gopkg.in/xtaci/smux.v1"
)

const (
	// MethodTLS is an extended SOCKS5 method for TLS.
	MethodTLS uint8 = 0x80
	// MethodTLSAuth is an extended SOCKS5 method for TLS+AUTH.
	MethodTLSAuth uint8 = 0x82
	// MethodMux is an extended SOCKS5 method for stream multiplexing.
	MethodMux = 0x88
)

const (
	// CmdMuxBind is an extended SOCKS5 request CMD for
	// multiplexing transport with the binding server.
	CmdMuxBind uint8 = 0xF2
	// CmdUDPTun is an extended SOCKS5 request CMD for UDP over TCP.
	CmdUDPTun uint8 = 0xF3
)

type clientSelector struct {
	methods   []uint8
	User      *url.Userinfo
	TLSConfig *tls.Config
}

func (selector *clientSelector) Methods() []uint8 {
	return selector.methods
}

func (selector *clientSelector) AddMethod(methods ...uint8) {
	selector.methods = append(selector.methods, methods...)
}

func (selector *clientSelector) Select(methods ...uint8) (method uint8) {
	return
}

func (selector *clientSelector) OnSelected(method uint8, conn net.Conn) (net.Conn, error) {
	switch method {
	case MethodTLS:
		conn = tls.Client(conn, selector.TLSConfig)

	case gosocks5.MethodUserPass, MethodTLSAuth:
		if method == MethodTLSAuth {
			conn = tls.Client(conn, selector.TLSConfig)
		}

		var username, password string
		if selector.User != nil {
			username = selector.User.Username()
			password, _ = selector.User.Password()
		}

		req := gosocks5.NewUserPassRequest(gosocks5.UserPassVer, username, password)
		if err := req.Write(conn); err != nil {
			log.Log("[socks5]", err)
			return nil, err
		}
		if Debug {
			log.Log("[socks5]", req)
		}
		resp, err := gosocks5.ReadUserPassResponse(conn)
		if err != nil {
			log.Log("[socks5]", err)
			return nil, err
		}
		if Debug {
			log.Log("[socks5]", resp)
		}
		if resp.Status != gosocks5.Succeeded {
			return nil, gosocks5.ErrAuthFailure
		}
	case gosocks5.MethodNoAcceptable:
		return nil, gosocks5.ErrBadMethod
	}

	return conn, nil
}

type serverSelector struct {
	methods []uint8
	// Users     []*url.Userinfo
	Authenticator Authenticator
	TLSConfig     *tls.Config
}

func (selector *serverSelector) Methods() []uint8 {
	return selector.methods
}

func (selector *serverSelector) AddMethod(methods ...uint8) {
	selector.methods = append(selector.methods, methods...)
}

func (selector *serverSelector) Select(methods ...uint8) (method uint8) {
	if Debug {
		log.Logf("[socks5] %d %d %v", gosocks5.Ver5, len(methods), methods)
	}
	method = gosocks5.MethodNoAuth
	for _, m := range methods {
		if m == MethodTLS {
			method = m
			break
		}
	}

	// when Authenticator is set, auth is mandatory
	if selector.Authenticator != nil {
		if method == gosocks5.MethodNoAuth {
			method = gosocks5.MethodUserPass
		}
		if method == MethodTLS {
			method = MethodTLSAuth
		}
	}

	return
}

func (selector *serverSelector) OnSelected(method uint8, conn net.Conn) (net.Conn, error) {
	if Debug {
		log.Logf("[socks5] %d %d", gosocks5.Ver5, method)
	}
	switch method {
	case MethodTLS:
		conn = tls.Server(conn, selector.TLSConfig)

	case gosocks5.MethodUserPass, MethodTLSAuth:
		if method == MethodTLSAuth {
			conn = tls.Server(conn, selector.TLSConfig)
		}

		req, err := gosocks5.ReadUserPassRequest(conn)
		if err != nil {
			log.Logf("[socks5] %s - %s: %s", conn.RemoteAddr(), conn.LocalAddr(), err)
			return nil, err
		}
		if Debug {
			log.Logf("[socks5] %s - %s: %s", conn.RemoteAddr(), conn.LocalAddr(), req.String())
		}

		if selector.Authenticator != nil && !selector.Authenticator.Authenticate(req.Username, req.Password) {
			resp := gosocks5.NewUserPassResponse(gosocks5.UserPassVer, gosocks5.Failure)
			if err := resp.Write(conn); err != nil {
				log.Logf("[socks5] %s - %s: %s", conn.RemoteAddr(), conn.LocalAddr(), err)
				return nil, err
			}
			if Debug {
				log.Logf("[socks5] %s - %s: %s", conn.RemoteAddr(), conn.LocalAddr(), resp)
			}
			log.Logf("[socks5] %s - %s: proxy authentication required", conn.RemoteAddr(), conn.LocalAddr())
			return nil, gosocks5.ErrAuthFailure
		}

		resp := gosocks5.NewUserPassResponse(gosocks5.UserPassVer, gosocks5.Succeeded)
		if err := resp.Write(conn); err != nil {
			log.Logf("[socks5] %s - %s: %s", conn.RemoteAddr(), conn.LocalAddr(), err)
			return nil, err
		}
		if Debug {
			log.Logf("[socks5] %s - %s: %s", conn.RemoteAddr(), conn.LocalAddr(), resp)
		}
	case gosocks5.MethodNoAcceptable:
		return nil, gosocks5.ErrBadMethod
	}

	return conn, nil
}

type socks5Connector struct {
	User *url.Userinfo
}

// SOCKS5Connector creates a connector for SOCKS5 proxy client.
// It accepts an optional auth info for SOCKS5 Username/Password Authentication.
func SOCKS5Connector(user *url.Userinfo) Connector {
	return &socks5Connector{User: user}
}

func (c *socks5Connector) Connect(conn net.Conn, addr string, options ...ConnectOption) (net.Conn, error) {
	opts := &ConnectOptions{}
	for _, option := range options {
		option(opts)
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = ConnectTimeout
	}

	conn.SetDeadline(time.Now().Add(timeout))
	defer conn.SetDeadline(time.Time{})

	user := opts.User
	if user == nil {
		user = c.User
	}
	cc, err := socks5Handshake(conn, opts.Selector, user)
	if err != nil {
		return nil, err
	}
	conn = cc

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	p, _ := strconv.Atoi(port)
	req := gosocks5.NewRequest(gosocks5.CmdConnect, &gosocks5.Addr{
		Type: gosocks5.AddrDomain,
		Host: host,
		Port: uint16(p),
	})
	if err := req.Write(conn); err != nil {
		return nil, err
	}

	if Debug {
		log.Log("[socks5]", req)
	}

	reply, err := gosocks5.ReadReply(conn)
	if err != nil {
		return nil, err
	}

	if Debug {
		log.Log("[socks5]", reply)
	}

	if reply.Rep != gosocks5.Succeeded {
		return nil, errors.New("Service unavailable")
	}

	return conn, nil
}

type socks5BindConnector struct {
	User *url.Userinfo
}

// SOCKS5BindConnector creates a connector for SOCKS5 bind.
// It accepts an optional auth info for SOCKS5 Username/Password Authentication.
func SOCKS5BindConnector(user *url.Userinfo) Connector {
	return &socks5BindConnector{User: user}
}

func (c *socks5BindConnector) Connect(conn net.Conn, addr string, options ...ConnectOption) (net.Conn, error) {
	opts := &ConnectOptions{}
	for _, option := range options {
		option(opts)
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = ConnectTimeout
	}

	conn.SetDeadline(time.Now().Add(timeout))
	defer conn.SetDeadline(time.Time{})

	user := opts.User
	if user == nil {
		user = c.User
	}
	cc, err := socks5Handshake(conn, opts.Selector, user)
	if err != nil {
		return nil, err
	}
	conn = cc

	laddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		log.Log(err)
		return nil, err
	}

	req := gosocks5.NewRequest(gosocks5.CmdBind, &gosocks5.Addr{
		Type: gosocks5.AddrIPv4,
		Host: laddr.IP.String(),
		Port: uint16(laddr.Port),
	})

	if err := req.Write(conn); err != nil {
		return nil, err
	}

	if Debug {
		log.Log("[socks5] bind\n", req)
	}

	reply, err := gosocks5.ReadReply(conn)
	if err != nil {
		return nil, err
	}

	if Debug {
		log.Log("[socks5] bind\n", reply)
	}

	if reply.Rep != gosocks5.Succeeded {
		log.Logf("[socks5] bind on %s failure", addr)
		return nil, fmt.Errorf("SOCKS5 bind on %s failure", addr)
	}
	baddr, err := net.ResolveTCPAddr("tcp", reply.Addr.String())
	if err != nil {
		return nil, err
	}
	log.Logf("[socks5] bind on %s OK", baddr)

	return &socks5BindConn{Conn: conn, laddr: baddr}, nil
}

type socks5MuxBindConnector struct{}

// Socks5MuxBindConnector creates a Connector for SOCKS5 multiplex bind client.
func Socks5MuxBindConnector() Connector {
	return &socks5MuxBindConnector{}
}

// NOTE: the conn must be *muxBindClientConn.
func (c *socks5MuxBindConnector) Connect(conn net.Conn, addr string, options ...ConnectOption) (net.Conn, error) {
	accepter, ok := conn.(Accepter)
	if !ok {
		return nil, errors.New("wrong connection type")
	}

	return accepter.Accept()
}

type socks5MuxBindTransporter struct {
	bindAddr     string
	sessions     map[string]*muxSession // server addr to session mapping
	sessionMutex sync.Mutex
}

// SOCKS5MuxBindTransporter creates a Transporter for SOCKS5 multiplex bind client.
func SOCKS5MuxBindTransporter(bindAddr string) Transporter {
	return &socks5MuxBindTransporter{
		bindAddr: bindAddr,
		sessions: make(map[string]*muxSession),
	}
}

func (tr *socks5MuxBindTransporter) Dial(addr string, options ...DialOption) (conn net.Conn, err error) {
	opts := &DialOptions{}
	for _, option := range options {
		option(opts)
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DialTimeout
	}

	tr.sessionMutex.Lock()
	defer tr.sessionMutex.Unlock()

	session, ok := tr.sessions[addr]
	if session != nil && session.IsClosed() {
		delete(tr.sessions, addr)
		ok = false
	}
	if !ok {
		if opts.Chain == nil {
			conn, err = net.DialTimeout("tcp", addr, timeout)
		} else {
			conn, err = opts.Chain.Dial(addr)
		}
		if err != nil {
			return
		}
		session = &muxSession{conn: conn}
		tr.sessions[addr] = session
	}
	return session.conn, nil
}

func (tr *socks5MuxBindTransporter) Handshake(conn net.Conn, options ...HandshakeOption) (net.Conn, error) {
	opts := &HandshakeOptions{}
	for _, option := range options {
		option(opts)
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = HandshakeTimeout
	}

	tr.sessionMutex.Lock()
	defer tr.sessionMutex.Unlock()

	conn.SetDeadline(time.Now().Add(timeout))
	defer conn.SetDeadline(time.Time{})

	session, ok := tr.sessions[opts.Addr]
	if !ok || session.session == nil {
		s, err := tr.initSession(conn, tr.bindAddr, opts)
		if err != nil {
			conn.Close()
			delete(tr.sessions, opts.Addr)
			return nil, err
		}
		session = s
		tr.sessions[opts.Addr] = session
	}

	return &muxBindClientConn{session: session}, nil
}

func (tr *socks5MuxBindTransporter) initSession(conn net.Conn, addr string, opts *HandshakeOptions) (*muxSession, error) {
	if opts == nil {
		opts = &HandshakeOptions{}
	}

	cc, err := socks5Handshake(conn, nil, opts.User)
	if err != nil {
		return nil, err
	}
	conn = cc

	bindAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, err
	}

	req := gosocks5.NewRequest(CmdMuxBind, &gosocks5.Addr{
		Type: gosocks5.AddrIPv4,
		Host: bindAddr.IP.String(),
		Port: uint16(bindAddr.Port),
	})

	if err = req.Write(conn); err != nil {
		return nil, err
	}

	if Debug {
		log.Log("[socks5] mbind\n", req)
	}

	reply, err := gosocks5.ReadReply(conn)
	if err != nil {
		return nil, err
	}

	if Debug {
		log.Log("[socks5] mbind\n", reply)
	}

	if reply.Rep != gosocks5.Succeeded {
		log.Logf("[socks5] mbind on %s failure", addr)
		return nil, fmt.Errorf("SOCKS5 mbind on %s failure", addr)
	}
	baddr, err := net.ResolveTCPAddr("tcp", reply.Addr.String())
	if err != nil {
		return nil, err
	}
	log.Logf("[socks5] mbind on %s OK", baddr)

	// Upgrade connection to multiplex stream.
	session, err := smux.Server(conn, smux.DefaultConfig())
	if err != nil {
		return nil, err
	}
	return &muxSession{conn: conn, session: session}, nil
}

func (tr *socks5MuxBindTransporter) Multiplex() bool {
	return true
}

type socks5UDPConnector struct {
	User *url.Userinfo
}

// SOCKS5UDPConnector creates a connector for SOCKS5 UDP relay.
// It accepts an optional auth info for SOCKS5 Username/Password Authentication.
func SOCKS5UDPConnector(user *url.Userinfo) Connector {
	return &socks5UDPConnector{User: user}
}

func (c *socks5UDPConnector) Connect(conn net.Conn, addr string, options ...ConnectOption) (net.Conn, error) {
	opts := &ConnectOptions{}
	for _, option := range options {
		option(opts)
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = ConnectTimeout
	}

	conn.SetDeadline(time.Now().Add(timeout))
	defer conn.SetDeadline(time.Time{})

	user := opts.User
	if user == nil {
		user = c.User
	}
	cc, err := socks5Handshake(conn, opts.Selector, user)
	if err != nil {
		return nil, err
	}
	conn = cc

	taddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}

	req := gosocks5.NewRequest(gosocks5.CmdUdp, &gosocks5.Addr{
		Type: gosocks5.AddrIPv4,
	})

	if err := req.Write(conn); err != nil {
		return nil, err
	}

	if Debug {
		log.Log("[socks5] udp\n", req)
	}

	reply, err := gosocks5.ReadReply(conn)
	if err != nil {
		return nil, err
	}

	if Debug {
		log.Log("[socks5] udp\n", reply)
	}

	if reply.Rep != gosocks5.Succeeded {
		log.Logf("[socks5] udp relay failure")
		return nil, fmt.Errorf("SOCKS5 udp relay failure")
	}
	baddr, err := net.ResolveUDPAddr("udp", reply.Addr.String())
	if err != nil {
		return nil, err
	}
	log.Logf("[socks5] udp associate on %s OK", baddr)

	uc, err := net.DialUDP("udp", nil, baddr)
	if err != nil {
		return nil, err
	}
	// log.Logf("udp laddr:%s, raddr:%s", uc.LocalAddr(), uc.RemoteAddr())

	return &socks5UDPConn{UDPConn: uc, taddr: taddr}, nil
}

type socks5UDPTunConnector struct {
	User *url.Userinfo
}

// SOCKS5UDPTunConnector creates a connector for SOCKS5 UDP-over-TCP relay.
// It accepts an optional auth info for SOCKS5 Username/Password Authentication.
func SOCKS5UDPTunConnector(user *url.Userinfo) Connector {
	return &socks5UDPTunConnector{User: user}
}

func (c *socks5UDPTunConnector) Connect(conn net.Conn, addr string, options ...ConnectOption) (net.Conn, error) {
	opts := &ConnectOptions{}
	for _, option := range options {
		option(opts)
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = ConnectTimeout
	}

	conn.SetDeadline(time.Now().Add(timeout))
	defer conn.SetDeadline(time.Time{})

	user := opts.User
	if user == nil {
		user = c.User
	}
	cc, err := socks5Handshake(conn, opts.Selector, user)
	if err != nil {
		return nil, err
	}
	conn = cc

	taddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}

	req := gosocks5.NewRequest(CmdUDPTun, &gosocks5.Addr{
		Type: gosocks5.AddrIPv4,
	})

	if err := req.Write(conn); err != nil {
		return nil, err
	}

	if Debug {
		log.Log("[socks5] udp\n", req)
	}

	reply, err := gosocks5.ReadReply(conn)
	if err != nil {
		return nil, err
	}

	if Debug {
		log.Log("[socks5] udp\n", reply)
	}

	if reply.Rep != gosocks5.Succeeded {
		log.Logf("[socks5] udp relay failure")
		return nil, fmt.Errorf("SOCKS5 udp relay failure")
	}
	baddr, err := net.ResolveUDPAddr("udp", reply.Addr.String())
	if err != nil {
		return nil, err
	}
	log.Logf("[socks5] udp-tun associate on %s OK", baddr)

	return &udpTunnelConn{Conn: conn, raddr: taddr.String()}, nil
}

type socks4Connector struct{}

// SOCKS4Connector creates a Connector for SOCKS4 proxy client.
func SOCKS4Connector() Connector {
	return &socks4Connector{}
}

func (c *socks4Connector) Connect(conn net.Conn, addr string, options ...ConnectOption) (net.Conn, error) {
	opts := &ConnectOptions{}
	for _, option := range options {
		option(opts)
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = ConnectTimeout
	}

	conn.SetDeadline(time.Now().Add(timeout))
	defer conn.SetDeadline(time.Time{})

	taddr, err := net.ResolveTCPAddr("tcp4", addr)
	if err != nil {
		return nil, err
	}
	if len(taddr.IP) == 0 {
		taddr.IP = net.IPv4zero
	}

	req := gosocks4.NewRequest(gosocks4.CmdConnect,
		&gosocks4.Addr{
			Type: gosocks4.AddrIPv4,
			Host: taddr.IP.String(),
			Port: uint16(taddr.Port),
		}, nil,
	)
	if err := req.Write(conn); err != nil {
		return nil, err
	}

	if Debug {
		log.Logf("[socks4] %s", req)
	}

	reply, err := gosocks4.ReadReply(conn)
	if err != nil {
		return nil, err
	}

	if Debug {
		log.Logf("[socks4] %s", reply)
	}

	if reply.Code != gosocks4.Granted {
		return nil, fmt.Errorf("[socks4] %d", reply.Code)
	}

	return conn, nil
}

type socks4aConnector struct{}

// SOCKS4AConnector creates a Connector for SOCKS4A proxy client.
func SOCKS4AConnector() Connector {
	return &socks4aConnector{}
}

func (c *socks4aConnector) Connect(conn net.Conn, addr string, options ...ConnectOption) (net.Conn, error) {
	opts := &ConnectOptions{}
	for _, option := range options {
		option(opts)
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = ConnectTimeout
	}

	conn.SetDeadline(time.Now().Add(timeout))
	defer conn.SetDeadline(time.Time{})

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	p, _ := strconv.Atoi(port)

	req := gosocks4.NewRequest(gosocks4.CmdConnect,
		&gosocks4.Addr{Type: gosocks4.AddrDomain, Host: host, Port: uint16(p)}, nil)
	if err := req.Write(conn); err != nil {
		return nil, err
	}

	if Debug {
		log.Logf("[socks4a] %s", req)
	}

	reply, err := gosocks4.ReadReply(conn)
	if err != nil {
		return nil, err
	}

	if Debug {
		log.Logf("[socks4a] %s", reply)
	}

	if reply.Code != gosocks4.Granted {
		return nil, fmt.Errorf("[socks4a] %d", reply.Code)
	}

	return conn, nil
}

type socks5Handler struct {
	selector *serverSelector
	options  *HandlerOptions
}

// SOCKS5Handler creates a server Handler for SOCKS5 proxy server.
func SOCKS5Handler(opts ...HandlerOption) Handler {
	h := &socks5Handler{}
	h.Init(opts...)

	return h
}

func (h *socks5Handler) Init(options ...HandlerOption) {
	if h.options == nil {
		h.options = &HandlerOptions{}
	}

	for _, opt := range options {
		opt(h.options)
	}

	tlsConfig := h.options.TLSConfig
	if tlsConfig == nil {
		tlsConfig = DefaultTLSConfig
	}
	h.selector = &serverSelector{ // socks5 server selector
		// Users:     h.options.Users,
		Authenticator: h.options.Authenticator,
		TLSConfig:     tlsConfig,
	}
	// methods that socks5 server supported
	h.selector.AddMethod(
		gosocks5.MethodNoAuth,
		gosocks5.MethodUserPass,
		MethodTLS,
		MethodTLSAuth,
	)
}

func (h *socks5Handler) Handle(conn net.Conn) {
	defer conn.Close()

	conn = gosocks5.ServerConn(conn, h.selector)
	req, err := gosocks5.ReadRequest(conn)
	if err != nil {
		log.Logf("[socks5] %s -> %s : %s",
			conn.RemoteAddr(), conn.LocalAddr(), err)
		return
	}

	if Debug {
		log.Logf("[socks5] %s -> %s\n%s",
			conn.RemoteAddr(), conn.LocalAddr(), req)
	}
	switch req.Cmd {
	case gosocks5.CmdConnect:
		h.handleConnect(conn, req)

	case gosocks5.CmdBind:
		h.handleBind(conn, req)

	case gosocks5.CmdUdp:
		h.handleUDPRelay(conn, req)

	case CmdMuxBind:
		h.handleMuxBind(conn, req)

	case CmdUDPTun:
		h.handleUDPTunnel(conn, req)

	default:
		log.Logf("[socks5] %s - %s : Unrecognized request: %d",
			conn.RemoteAddr(), conn.LocalAddr(), req.Cmd)
	}
}

func (h *socks5Handler) handleConnect(conn net.Conn, req *gosocks5.Request) {
	host := req.Addr.String()

	log.Logf("[socks5] %s -> %s -> %s",
		conn.RemoteAddr(), h.options.Node.String(), host)

	if !Can("tcp", host, h.options.Whitelist, h.options.Blacklist) {
		log.Logf("[socks5] %s - %s : Unauthorized to tcp connect to %s",
			conn.RemoteAddr(), conn.LocalAddr(), host)
		rep := gosocks5.NewReply(gosocks5.NotAllowed, nil)
		rep.Write(conn)
		if Debug {
			log.Logf("[socks5] %s <- %s\n%s",
				conn.RemoteAddr(), conn.LocalAddr(), rep)
		}
		return
	}
	if h.options.Bypass.Contains(host) {
		log.Logf("[socks5] %s - %s : Bypass %s",
			conn.RemoteAddr(), conn.LocalAddr(), host)
		rep := gosocks5.NewReply(gosocks5.NotAllowed, nil)
		rep.Write(conn)
		if Debug {
			log.Logf("[socks5] %s <- %s\n%s",
				conn.RemoteAddr(), conn.LocalAddr(), rep)
		}
		return
	}

	retries := 1
	if h.options.Chain != nil && h.options.Chain.Retries > 0 {
		retries = h.options.Chain.Retries
	}
	if h.options.Retries > 0 {
		retries = h.options.Retries
	}

	var err error
	var cc net.Conn
	var route *Chain
	for i := 0; i < retries; i++ {
		route, err = h.options.Chain.selectRouteFor(host)
		if err != nil {
			log.Logf("[socks5] %s -> %s : %s",
				conn.RemoteAddr(), conn.LocalAddr(), err)
			continue
		}

		buf := bytes.Buffer{}
		fmt.Fprintf(&buf, "%s -> %s -> ",
			conn.RemoteAddr(), h.options.Node.String())
		for _, nd := range route.route {
			fmt.Fprintf(&buf, "%d@%s -> ", nd.ID, nd.String())
		}
		fmt.Fprintf(&buf, "%s", host)
		log.Log("[route]", buf.String())

		cc, err = route.Dial(host,
			TimeoutChainOption(h.options.Timeout),
			HostsChainOption(h.options.Hosts),
			ResolverChainOption(h.options.Resolver),
		)
		if err == nil {
			break
		}
		log.Logf("[socks5] %s -> %s : %s",
			conn.RemoteAddr(), conn.LocalAddr(), err)
	}

	if err != nil {
		rep := gosocks5.NewReply(gosocks5.HostUnreachable, nil)
		rep.Write(conn)
		if Debug {
			log.Logf("[socks5] %s <- %s\n%s",
				conn.RemoteAddr(), conn.LocalAddr(), rep)
		}
		return
	}
	defer cc.Close()

	rep := gosocks5.NewReply(gosocks5.Succeeded, nil)
	if err := rep.Write(conn); err != nil {
		log.Logf("[socks5] %s <- %s : %s",
			conn.RemoteAddr(), conn.LocalAddr(), err)
		return
	}
	if Debug {
		log.Logf("[socks5] %s <- %s\n%s",
			conn.RemoteAddr(), conn.LocalAddr(), rep)
	}
	log.Logf("[socks5] %s <-> %s", conn.RemoteAddr(), host)
	transport(conn, cc)
	log.Logf("[socks5] %s >-< %s", conn.RemoteAddr(), host)
}

func (h *socks5Handler) handleBind(conn net.Conn, req *gosocks5.Request) {
	addr := req.Addr.String()

	log.Logf("[socks5-bind] %s -> %s -> %s",
		conn.RemoteAddr(), h.options.Node.String(), addr)

	if h.options.Chain.IsEmpty() {
		if !Can("rtcp", addr, h.options.Whitelist, h.options.Blacklist) {
			log.Logf("[socks5-bind] %s - %s : Unauthorized to tcp bind to %s",
				conn.RemoteAddr(), conn.LocalAddr(), addr)
			return
		}
		h.bindOn(conn, addr)
		return
	}

	cc, err := h.options.Chain.Conn()
	if err != nil {
		log.Logf("[socks5-bind] %s <- %s : %s",
			conn.RemoteAddr(), conn.LocalAddr(), err)
		reply := gosocks5.NewReply(gosocks5.Failure, nil)
		reply.Write(conn)
		if Debug {
			log.Logf("[socks5-bind] %s <- %s\n%s",
				conn.RemoteAddr(), conn.LocalAddr(), reply)
		}
		return
	}

	// forward request
	// note: this type of request forwarding is defined when starting server,
	// so we don't need to authenticate it, as it's as explicit as whitelisting
	defer cc.Close()
	req.Write(cc)
	log.Logf("[socks5-bind] %s <-> %s", conn.RemoteAddr(), addr)
	transport(conn, cc)
	log.Logf("[socks5-bind] %s >-< %s", conn.RemoteAddr(), addr)
}

func (h *socks5Handler) bindOn(conn net.Conn, addr string) {
	bindAddr, _ := net.ResolveTCPAddr("tcp", addr)
	ln, err := net.ListenTCP("tcp", bindAddr) // strict mode: if the port already in use, it will return error
	if err != nil {
		log.Logf("[socks5-bind] %s -> %s : %s",
			conn.RemoteAddr(), conn.LocalAddr(), err)
		gosocks5.NewReply(gosocks5.Failure, nil).Write(conn)
		return
	}

	socksAddr := toSocksAddr(ln.Addr())
	// Issue: may not reachable when host has multi-interface
	socksAddr.Host, _, _ = net.SplitHostPort(conn.LocalAddr().String())
	reply := gosocks5.NewReply(gosocks5.Succeeded, socksAddr)
	if err := reply.Write(conn); err != nil {
		log.Logf("[socks5-bind] %s <- %s : %s",
			conn.RemoteAddr(), conn.LocalAddr(), err)
		ln.Close()
		return
	}
	if Debug {
		log.Logf("[socks5-bind] %s <- %s\n%s",
			conn.RemoteAddr(), conn.LocalAddr(), reply)
	}
	log.Logf("[socks5-bind] %s - %s BIND ON %s OK",
		conn.RemoteAddr(), conn.LocalAddr(), socksAddr)

	var pconn net.Conn
	accept := func() <-chan error {
		errc := make(chan error, 1)

		go func() {
			defer close(errc)
			defer ln.Close()

			c, err := ln.AcceptTCP()
			if err != nil {
				errc <- err
				return
			}
			pconn = c
		}()

		return errc
	}

	pc1, pc2 := net.Pipe()
	pipe := func() <-chan error {
		errc := make(chan error, 1)

		go func() {
			defer close(errc)
			defer pc1.Close()

			errc <- transport(conn, pc1)
		}()

		return errc
	}

	defer pc2.Close()

	for {
		select {
		case err := <-accept():
			if err != nil || pconn == nil {
				log.Logf("[socks5-bind] %s <- %s : %v", conn.RemoteAddr(), addr, err)
				return
			}
			defer pconn.Close()

			reply := gosocks5.NewReply(gosocks5.Succeeded, toSocksAddr(pconn.RemoteAddr()))
			if err := reply.Write(pc2); err != nil {
				log.Logf("[socks5-bind] %s <- %s : %v", conn.RemoteAddr(), addr, err)
			}
			if Debug {
				log.Logf("[socks5-bind] %s <- %s\n%s", conn.RemoteAddr(), addr, reply)
			}
			log.Logf("[socks5-bind] %s <- %s PEER %s ACCEPTED", conn.RemoteAddr(), socksAddr, pconn.RemoteAddr())

			log.Logf("[socks5-bind] %s <-> %s", conn.RemoteAddr(), pconn.RemoteAddr())
			if err = transport(pc2, pconn); err != nil {
				log.Logf("[socks5-bind] %s - %s : %v", conn.RemoteAddr(), pconn.RemoteAddr(), err)
			}
			log.Logf("[socks5-bind] %s >-< %s", conn.RemoteAddr(), pconn.RemoteAddr())
			return
		case err := <-pipe():
			if err != nil {
				log.Logf("[socks5-bind] %s -> %s : %v", conn.RemoteAddr(), addr, err)
			}
			ln.Close()
			return
		}
	}
}

func (h *socks5Handler) handleUDPRelay(conn net.Conn, req *gosocks5.Request) {
	addr := req.Addr.String()
	if !Can("udp", addr, h.options.Whitelist, h.options.Blacklist) {
		log.Logf("[socks5-udp] Unauthorized to udp connect to %s", addr)
		rep := gosocks5.NewReply(gosocks5.NotAllowed, nil)
		rep.Write(conn)
		if Debug {
			log.Logf("[socks5-udp] %s <- %s\n%s", conn.RemoteAddr(), req.Addr, rep)
		}
		return
	}

	relay, err := net.ListenUDP("udp", nil)
	if err != nil {
		log.Logf("[socks5-udp] %s -> %s : %s", conn.RemoteAddr(), conn.LocalAddr(), err)
		reply := gosocks5.NewReply(gosocks5.Failure, nil)
		reply.Write(conn)
		if Debug {
			log.Logf("[socks5-udp] %s <- %s\n%s", conn.RemoteAddr(), conn.LocalAddr(), reply)
		}
		return
	}
	defer relay.Close()

	socksAddr := toSocksAddr(relay.LocalAddr())
	socksAddr.Host, _, _ = net.SplitHostPort(conn.LocalAddr().String()) // replace the IP to the out-going interface's
	reply := gosocks5.NewReply(gosocks5.Succeeded, socksAddr)
	if err := reply.Write(conn); err != nil {
		log.Logf("[socks5-udp] %s <- %s : %s", conn.RemoteAddr(), conn.LocalAddr(), err)
		return
	}
	if Debug {
		log.Logf("[socks5-udp] %s <- %s\n%s", conn.RemoteAddr(), conn.LocalAddr(), reply)
	}
	log.Logf("[socks5-udp] %s - %s BIND ON %s OK", conn.RemoteAddr(), conn.LocalAddr(), socksAddr)

	// serve as standard socks5 udp relay local <-> remote
	if h.options.Chain.IsEmpty() {
		peer, er := net.ListenUDP("udp", nil)
		if er != nil {
			log.Logf("[socks5-udp] %s -> %s : %s", conn.RemoteAddr(), conn.LocalAddr(), er)
			return
		}
		defer peer.Close()

		go h.transportUDP(relay, peer)
		log.Logf("[socks5-udp] %s <-> %s : associated on %s", conn.RemoteAddr(), conn.LocalAddr(), socksAddr)
		if err := h.discardClientData(conn); err != nil {
			log.Logf("[socks5-udp] %s - %s : %s", conn.RemoteAddr(), conn.LocalAddr(), err)
		}
		log.Logf("[socks5-udp] %s >-< %s : associated on %s", conn.RemoteAddr(), conn.LocalAddr(), socksAddr)
		return
	}

	// forward udp local <-> tunnel
	cc, err := h.options.Chain.Conn()
	// connection error
	if err != nil {
		log.Logf("[socks5-udp] %s -> %s : %s", conn.RemoteAddr(), socksAddr, err)
		return
	}
	defer cc.Close()

	cc, err = socks5Handshake(cc, nil, h.options.Chain.LastNode().User)
	if err != nil {
		log.Logf("[socks5-udp] %s -> %s : %s", conn.RemoteAddr(), socksAddr, err)
		return
	}

	cc.SetWriteDeadline(time.Now().Add(WriteTimeout))
	r := gosocks5.NewRequest(CmdUDPTun, nil)
	if err := r.Write(cc); err != nil {
		log.Logf("[socks5-udp] %s -> %s : %s", conn.RemoteAddr(), cc.RemoteAddr(), err)
		return
	}
	cc.SetWriteDeadline(time.Time{})
	if Debug {
		log.Logf("[socks5-udp] %s -> %s\n%s", conn.RemoteAddr(), cc.RemoteAddr(), r)
	}
	cc.SetReadDeadline(time.Now().Add(ReadTimeout))
	reply, err = gosocks5.ReadReply(cc)
	if err != nil {
		log.Logf("[socks5-udp] %s -> %s : %s", conn.RemoteAddr(), cc.RemoteAddr(), err)
		return
	}
	if Debug {
		log.Logf("[socks5-udp] %s <- %s\n%s", conn.RemoteAddr(), cc.RemoteAddr(), reply)
	}

	if reply.Rep != gosocks5.Succeeded {
		log.Logf("[socks5-udp] %s <- %s : udp associate failed", conn.RemoteAddr(), cc.RemoteAddr())
		return
	}
	cc.SetReadDeadline(time.Time{})
	log.Logf("[socks5-udp] %s <-> %s [tun: %s]", conn.RemoteAddr(), socksAddr, reply.Addr)

	go h.tunnelClientUDP(relay, cc)
	log.Logf("[socks5-udp] %s <-> %s", conn.RemoteAddr(), socksAddr)
	if err := h.discardClientData(conn); err != nil {
		log.Logf("[socks5-udp] %s - %s : %s", conn.RemoteAddr(), socksAddr, err)
	}
	log.Logf("[socks5-udp] %s >-< %s", conn.RemoteAddr(), socksAddr)
}

func (h *socks5Handler) discardClientData(conn net.Conn) (err error) {
	b := make([]byte, tinyBufferSize)
	n := 0
	for {
		n, err = conn.Read(b) // discard any data from tcp connection
		if err != nil {
			if err == io.EOF { // disconnect normally
				err = nil
			}
			break // client disconnected
		}
		log.Logf("[socks5-udp] read %d UNEXPECTED TCP data from client", n)
	}
	return
}

func (h *socks5Handler) transportUDP(relay, peer net.PacketConn) (err error) {
	errc := make(chan error, 2)

	var clientAddr net.Addr

	go func() {
		b := mPool.Get().([]byte)
		defer mPool.Put(b)

		for {
			n, laddr, err := relay.ReadFrom(b)
			if err != nil {
				errc <- err
				return
			}
			if clientAddr == nil {
				clientAddr = laddr
			}
			dgram, err := gosocks5.ReadUDPDatagram(bytes.NewReader(b[:n]))
			if err != nil {
				errc <- err
				return
			}

			raddr, err := net.ResolveUDPAddr("udp", dgram.Header.Addr.String())
			if err != nil {
				continue // drop silently
			}
			if h.options.Bypass.Contains(raddr.String()) {
				log.Log("[socks5-udp] [bypass] write to", raddr)
				continue // bypass
			}
			if _, err := peer.WriteTo(dgram.Data, raddr); err != nil {
				errc <- err
				return
			}
			if Debug {
				log.Logf("[socks5-udp] %s >>> %s length: %d", relay.LocalAddr(), raddr, len(dgram.Data))
			}
		}
	}()

	go func() {
		b := mPool.Get().([]byte)
		defer mPool.Put(b)

		for {
			n, raddr, err := peer.ReadFrom(b)
			if err != nil {
				errc <- err
				return
			}
			if clientAddr == nil {
				continue
			}
			if h.options.Bypass.Contains(raddr.String()) {
				log.Log("[socks5-udp] [bypass] read from", raddr)
				continue // bypass
			}
			buf := bytes.Buffer{}
			dgram := gosocks5.NewUDPDatagram(gosocks5.NewUDPHeader(0, 0, toSocksAddr(raddr)), b[:n])
			dgram.Write(&buf)
			if _, err := relay.WriteTo(buf.Bytes(), clientAddr); err != nil {
				errc <- err
				return
			}
			if Debug {
				log.Logf("[socks5-udp] %s <<< %s length: %d", relay.LocalAddr(), raddr, len(dgram.Data))
			}
		}
	}()

	select {
	case err = <-errc:
		//log.Println("w exit", err)
	}

	return
}

func (h *socks5Handler) tunnelClientUDP(uc *net.UDPConn, cc net.Conn) (err error) {
	errc := make(chan error, 2)

	var clientAddr *net.UDPAddr

	go func() {
		b := mPool.Get().([]byte)
		defer mPool.Put(b)

		for {
			n, addr, err := uc.ReadFromUDP(b)
			if err != nil {
				log.Logf("[udp-tun] %s <- %s : %s", cc.RemoteAddr(), addr, err)
				errc <- err
				return
			}

			// glog.V(LDEBUG).Infof("read udp %d, % #x", n, b[:n])
			// pipe from relay to tunnel
			dgram, err := gosocks5.ReadUDPDatagram(bytes.NewReader(b[:n]))
			if err != nil {
				errc <- err
				return
			}
			if clientAddr == nil {
				clientAddr = addr
			}
			raddr := dgram.Header.Addr.String()
			if h.options.Bypass.Contains(raddr) {
				log.Log("[udp-tun] [bypass] write to", raddr)
				continue // bypass
			}
			dgram.Header.Rsv = uint16(len(dgram.Data))
			if err := dgram.Write(cc); err != nil {
				errc <- err
				return
			}
			if Debug {
				log.Logf("[udp-tun] %s >>> %s length: %d", uc.LocalAddr(), dgram.Header.Addr, len(dgram.Data))
			}
		}
	}()

	go func() {
		for {
			dgram, err := gosocks5.ReadUDPDatagram(cc)
			if err != nil {
				log.Logf("[udp-tun] %s -> 0 : %s", cc.RemoteAddr(), err)
				errc <- err
				return
			}

			// pipe from tunnel to relay
			if clientAddr == nil {
				continue
			}
			raddr := dgram.Header.Addr.String()
			if h.options.Bypass.Contains(raddr) {
				log.Log("[udp-tun] [bypass] read from", raddr)
				continue // bypass
			}
			dgram.Header.Rsv = 0

			buf := bytes.Buffer{}
			dgram.Write(&buf)
			if _, err := uc.WriteToUDP(buf.Bytes(), clientAddr); err != nil {
				errc <- err
				return
			}
			if Debug {
				log.Logf("[udp-tun] %s <<< %s length: %d", uc.LocalAddr(), dgram.Header.Addr, len(dgram.Data))
			}
		}
	}()

	select {
	case err = <-errc:
	}

	return
}

func (h *socks5Handler) handleUDPTunnel(conn net.Conn, req *gosocks5.Request) {
	// serve tunnel udp, tunnel <-> remote, handle tunnel udp request
	if h.options.Chain.IsEmpty() {
		addr := req.Addr.String()

		if !Can("rudp", addr, h.options.Whitelist, h.options.Blacklist) {
			log.Logf("[socks5-udp] Unauthorized to udp bind to %s", addr)
			return
		}

		bindAddr, _ := net.ResolveUDPAddr("udp", addr)
		uc, err := net.ListenUDP("udp", bindAddr)
		if err != nil {
			log.Logf("[socks5-udp] %s -> %s : %s", conn.RemoteAddr(), req.Addr, err)
			return
		}
		defer uc.Close()

		socksAddr := toSocksAddr(uc.LocalAddr())
		socksAddr.Host, _, _ = net.SplitHostPort(conn.LocalAddr().String())
		reply := gosocks5.NewReply(gosocks5.Succeeded, socksAddr)
		if err := reply.Write(conn); err != nil {
			log.Logf("[socks5-udp] %s <- %s : %s", conn.RemoteAddr(), socksAddr, err)
			return
		}
		if Debug {
			log.Logf("[socks5-udp] %s <- %s\n%s", conn.RemoteAddr(), socksAddr, reply)
		}
		log.Logf("[socks5-udp] %s <-> %s", conn.RemoteAddr(), socksAddr)
		h.tunnelServerUDP(conn, uc)
		log.Logf("[socks5-udp] %s >-< %s", conn.RemoteAddr(), socksAddr)
		return
	}

	cc, err := h.options.Chain.Conn()
	// connection error
	if err != nil {
		log.Logf("[socks5-udp] %s -> %s : %s", conn.RemoteAddr(), req.Addr, err)
		reply := gosocks5.NewReply(gosocks5.Failure, nil)
		reply.Write(conn)
		log.Logf("[socks5-udp] %s -> %s\n%s", conn.RemoteAddr(), req.Addr, reply)
		return
	}
	defer cc.Close()

	cc, err = socks5Handshake(cc, nil, h.options.Chain.LastNode().User)
	if err != nil {
		log.Logf("[socks5-udp] %s -> %s : %s", conn.RemoteAddr(), req.Addr, err)
		return
	}
	// tunnel <-> tunnel, direct forwarding
	// note: this type of request forwarding is defined when starting server
	// so we don't need to authenticate it, as it's as explicit as whitelisting
	req.Write(cc)

	log.Logf("[socks5-udp] %s <-> %s [tun]", conn.RemoteAddr(), cc.RemoteAddr())
	transport(conn, cc)
	log.Logf("[socks5-udp] %s >-< %s [tun]", conn.RemoteAddr(), cc.RemoteAddr())
}

func (h *socks5Handler) tunnelServerUDP(cc net.Conn, pc net.PacketConn) (err error) {
	errc := make(chan error, 2)

	go func() {
		b := mPool.Get().([]byte)
		defer mPool.Put(b)

		for {
			n, addr, err := pc.ReadFrom(b)
			if err != nil {
				// log.Logf("[udp-tun] %s : %s", cc.RemoteAddr(), err)
				errc <- err
				return
			}
			if h.options.Bypass.Contains(addr.String()) {
				log.Log("[udp-tun] [bypass] read from", addr)
				continue // bypass
			}

			// pipe from peer to tunnel
			dgram := gosocks5.NewUDPDatagram(
				gosocks5.NewUDPHeader(uint16(n), 0, toSocksAddr(addr)), b[:n])
			if err := dgram.Write(cc); err != nil {
				log.Logf("[udp-tun] %s <- %s : %s", cc.RemoteAddr(), dgram.Header.Addr, err)
				errc <- err
				return
			}
			if Debug {
				log.Logf("[udp-tun] %s <<< %s length: %d", cc.RemoteAddr(), dgram.Header.Addr, len(dgram.Data))
			}
		}
	}()

	go func() {
		for {
			dgram, err := gosocks5.ReadUDPDatagram(cc)
			if err != nil {
				// log.Logf("[udp-tun] %s -> 0 : %s", cc.RemoteAddr(), err)
				errc <- err
				return
			}

			// pipe from tunnel to peer
			addr, err := net.ResolveUDPAddr("udp", dgram.Header.Addr.String())
			if err != nil {
				continue // drop silently
			}
			if h.options.Bypass.Contains(addr.String()) {
				log.Log("[udp-tun] [bypass] write to", addr)
				continue // bypass
			}
			if _, err := pc.WriteTo(dgram.Data, addr); err != nil {
				log.Logf("[udp-tun] %s -> %s : %s", cc.RemoteAddr(), addr, err)
				errc <- err
				return
			}
			if Debug {
				log.Logf("[udp-tun] %s >>> %s length: %d", cc.RemoteAddr(), addr, len(dgram.Data))
			}
		}
	}()

	select {
	case err = <-errc:
	}

	return
}

func (h *socks5Handler) handleMuxBind(conn net.Conn, req *gosocks5.Request) {
	if h.options.Chain.IsEmpty() {
		addr := req.Addr.String()
		if !Can("rtcp", addr, h.options.Whitelist, h.options.Blacklist) {
			log.Logf("Unauthorized to tcp mbind to %s", addr)
			return
		}
		h.muxBindOn(conn, addr)
		return
	}

	cc, err := h.options.Chain.Conn()
	if err != nil {
		log.Logf("[socks5] mbind %s <- %s : %s", conn.RemoteAddr(), req.Addr, err)
		reply := gosocks5.NewReply(gosocks5.Failure, nil)
		reply.Write(conn)
		if Debug {
			log.Logf("[socks5] mbind %s <- %s\n%s", conn.RemoteAddr(), req.Addr, reply)
		}
		return
	}

	// forward request
	// note: this type of request forwarding is defined when starting server,
	// so we don't need to authenticate it, as it's as explicit as whitelisting.
	defer cc.Close()
	req.Write(cc)
	log.Logf("[socks5] mbind %s <-> %s", conn.RemoteAddr(), cc.RemoteAddr())
	transport(conn, cc)
	log.Logf("[socks5] mbind %s >-< %s", conn.RemoteAddr(), cc.RemoteAddr())
}

func (h *socks5Handler) muxBindOn(conn net.Conn, addr string) {
	bindAddr, _ := net.ResolveTCPAddr("tcp", addr)
	ln, err := net.ListenTCP("tcp", bindAddr) // strict mode: if the port already in use, it will return error
	if err != nil {
		log.Logf("[socks5] mbind %s -> %s : %s", conn.RemoteAddr(), addr, err)
		gosocks5.NewReply(gosocks5.Failure, nil).Write(conn)
		return
	}
	defer ln.Close()

	socksAddr := toSocksAddr(ln.Addr())
	// Issue: may not reachable when host has multi-interface.
	socksAddr.Host, _, _ = net.SplitHostPort(conn.LocalAddr().String())
	reply := gosocks5.NewReply(gosocks5.Succeeded, socksAddr)
	if err := reply.Write(conn); err != nil {
		log.Logf("[socks5] mbind %s <- %s : %s", conn.RemoteAddr(), addr, err)
		return
	}
	if Debug {
		log.Logf("[socks5] mbind %s <- %s\n%s", conn.RemoteAddr(), addr, reply)
	}
	log.Logf("[socks5] mbind %s - %s BIND ON %s OK", conn.RemoteAddr(), addr, socksAddr)

	// Upgrade connection to multiplex stream.
	s, err := smux.Client(conn, smux.DefaultConfig())
	if err != nil {
		log.Logf("[socks5] mbind %s - %s : %s", conn.RemoteAddr(), socksAddr, err)
		return
	}

	log.Logf("[socks5] mbind %s <-> %s", conn.RemoteAddr(), socksAddr)
	defer log.Logf("[socks5] mbind %s >-< %s", conn.RemoteAddr(), socksAddr)

	session := &muxSession{
		conn:    conn,
		session: s,
	}
	defer session.Close()

	go func() {
		for {
			conn, err := session.Accept()
			if err != nil {
				log.Logf("[socks5] mbind accept : %v", err)
				ln.Close()
				return
			}
			conn.Close() // we do not handle incoming connection.
		}
	}()

	for {
		cc, err := ln.Accept()
		if err != nil {
			log.Logf("[socks5] mbind %s <- %s : %v", conn.RemoteAddr(), socksAddr, err)
			return
		}
		log.Logf("[socks5] mbind %s <- %s : ACCEPT peer %s",
			conn.RemoteAddr(), socksAddr, cc.RemoteAddr())

		go func(c net.Conn) {
			defer c.Close()

			sc, err := session.GetConn()
			if err != nil {
				log.Logf("[socks5] mbind %s <- %s : %s", conn.RemoteAddr(), socksAddr, err)
				return
			}
			defer sc.Close()

			transport(sc, c)
		}(cc)
	}
}

func toSocksAddr(addr net.Addr) *gosocks5.Addr {
	host := "0.0.0.0"
	port := 0
	if addr != nil {
		h, p, _ := net.SplitHostPort(addr.String())
		host = h
		port, _ = strconv.Atoi(p)
	}
	return &gosocks5.Addr{
		Type: gosocks5.AddrIPv4,
		Host: host,
		Port: uint16(port),
	}
}

type socks4Handler struct {
	options *HandlerOptions
}

// SOCKS4Handler creates a server Handler for SOCKS4(A) proxy server.
func SOCKS4Handler(opts ...HandlerOption) Handler {
	h := &socks4Handler{}
	h.Init(opts...)

	return h
}

func (h *socks4Handler) Init(options ...HandlerOption) {
	if h.options == nil {
		h.options = &HandlerOptions{}
	}

	for _, opt := range options {
		opt(h.options)
	}
}

func (h *socks4Handler) Handle(conn net.Conn) {
	defer conn.Close()

	req, err := gosocks4.ReadRequest(conn)
	if err != nil {
		log.Logf("[socks4] %s -> %s : %s",
			conn.RemoteAddr(), conn.LocalAddr(), err)
		return
	}

	if Debug {
		log.Logf("[socks4] %s -> %s\n%s",
			conn.RemoteAddr(), conn.LocalAddr(), req)
	}

	switch req.Cmd {
	case gosocks4.CmdConnect:
		h.handleConnect(conn, req)

	case gosocks4.CmdBind:
		log.Logf("[socks4-bind] %s - %s", conn.RemoteAddr(), req.Addr)
		h.handleBind(conn, req)

	default:
		log.Logf("[socks4] %s - %s : Unrecognized request: %d",
			conn.RemoteAddr(), conn.LocalAddr(), req.Cmd)
	}
}

func (h *socks4Handler) handleConnect(conn net.Conn, req *gosocks4.Request) {
	addr := req.Addr.String()

	log.Logf("[socks4] %s -> %s -> %s",
		conn.RemoteAddr(), h.options.Node.String(), addr)

	if !Can("tcp", addr, h.options.Whitelist, h.options.Blacklist) {
		log.Logf("[socks4] %s - %s : Unauthorized to tcp connect to %s",
			conn.RemoteAddr(), conn.LocalAddr(), addr)
		rep := gosocks4.NewReply(gosocks4.Rejected, nil)
		rep.Write(conn)
		if Debug {
			log.Logf("[socks4] %s <- %s\n%s",
				conn.RemoteAddr(), conn.LocalAddr(), rep)
		}
		return
	}
	if h.options.Bypass.Contains(addr) {
		log.Log("[socks4] %s - %s : Bypass %s",
			conn.RemoteAddr(), conn.LocalAddr(), addr)
		rep := gosocks4.NewReply(gosocks4.Rejected, nil)
		rep.Write(conn)
		if Debug {
			log.Logf("[socks4] %s <- %s\n%s",
				conn.RemoteAddr(), conn.LocalAddr(), rep)
		}
		return
	}

	retries := 1
	if h.options.Chain != nil && h.options.Chain.Retries > 0 {
		retries = h.options.Chain.Retries
	}
	if h.options.Retries > 0 {
		retries = h.options.Retries
	}

	var err error
	var cc net.Conn
	var route *Chain
	for i := 0; i < retries; i++ {
		route, err = h.options.Chain.selectRouteFor(addr)
		if err != nil {
			log.Logf("[socks4] %s -> %s : %s",
				conn.RemoteAddr(), conn.LocalAddr(), err)
			continue
		}

		buf := bytes.Buffer{}
		fmt.Fprintf(&buf, "%s -> %s -> ",
			conn.RemoteAddr(), h.options.Node.String())
		for _, nd := range route.route {
			fmt.Fprintf(&buf, "%d@%s -> ", nd.ID, nd.String())
		}
		fmt.Fprintf(&buf, "%s", addr)
		log.Log("[route]", buf.String())

		cc, err = route.Dial(addr,
			TimeoutChainOption(h.options.Timeout),
			HostsChainOption(h.options.Hosts),
			ResolverChainOption(h.options.Resolver),
		)
		if err == nil {
			break
		}
		log.Logf("[socks4] %s -> %s : %s",
			conn.RemoteAddr(), conn.LocalAddr(), err)
	}

	if err != nil {
		rep := gosocks4.NewReply(gosocks4.Failed, nil)
		rep.Write(conn)
		if Debug {
			log.Logf("[socks4] %s <- %s\n%s",
				conn.RemoteAddr(), conn.LocalAddr(), rep)
		}
		return
	}
	defer cc.Close()

	rep := gosocks4.NewReply(gosocks4.Granted, nil)
	if err := rep.Write(conn); err != nil {
		log.Logf("[socks4] %s <- %s : %s",
			conn.RemoteAddr(), conn.LocalAddr(), err)
		return
	}
	if Debug {
		log.Logf("[socks4] %s <- %s\n%s",
			conn.RemoteAddr(), conn.LocalAddr(), rep)
	}

	log.Logf("[socks4] %s <-> %s", conn.RemoteAddr(), addr)
	transport(conn, cc)
	log.Logf("[socks4] %s >-< %s", conn.RemoteAddr(), addr)
}

func (h *socks4Handler) handleBind(conn net.Conn, req *gosocks4.Request) {
	// TODO: serve socks4 bind
	if h.options.Chain.IsEmpty() {
		reply := gosocks4.NewReply(gosocks4.Rejected, nil)
		reply.Write(conn)
		if Debug {
			log.Logf("[socks4-bind] %s <- %s\n%s", conn.RemoteAddr(), req.Addr, reply)
		}
		return
	}

	cc, err := h.options.Chain.Conn()
	// connection error
	if err != nil && err != ErrEmptyChain {
		log.Logf("[socks4-bind] %s <- %s : %s", conn.RemoteAddr(), req.Addr, err)
		reply := gosocks4.NewReply(gosocks4.Failed, nil)
		reply.Write(conn)
		if Debug {
			log.Logf("[socks4-bind] %s <- %s\n%s", conn.RemoteAddr(), req.Addr, reply)
		}
		return
	}

	defer cc.Close()
	// forward request
	req.Write(cc)

	log.Logf("[socks4-bind] %s <-> %s", conn.RemoteAddr(), cc.RemoteAddr())
	transport(conn, cc)
	log.Logf("[socks4-bind] %s >-< %s", conn.RemoteAddr(), cc.RemoteAddr())
}

func getSOCKS5UDPTunnel(chain *Chain, addr net.Addr) (net.Conn, error) {
	conn, err := chain.Conn()
	if err != nil {
		return nil, err
	}

	conn.SetDeadline(time.Now().Add(HandshakeTimeout))
	defer conn.SetDeadline(time.Time{})

	cc, err := socks5Handshake(conn, nil, chain.LastNode().User)
	if err != nil {
		conn.Close()
		return nil, err
	}
	conn = cc

	req := gosocks5.NewRequest(CmdUDPTun, toSocksAddr(addr))
	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, err
	}
	if Debug {
		log.Log("[socks5]", req)
	}

	reply, err := gosocks5.ReadReply(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}

	if Debug {
		log.Log("[socks5]", reply)
	}

	if reply.Rep != gosocks5.Succeeded {
		conn.Close()
		return nil, errors.New("UDP tunnel failure")
	}
	return conn, nil
}

func socks5Handshake(conn net.Conn, selector gosocks5.Selector, user *url.Userinfo) (net.Conn, error) {
	if selector == nil {
		cs := &clientSelector{
			TLSConfig: &tls.Config{InsecureSkipVerify: true},
			User:      user,
		}
		cs.AddMethod(
			gosocks5.MethodNoAuth,
			gosocks5.MethodUserPass,
			MethodTLS,
		)
		selector = cs
	}

	cc := gosocks5.ClientConn(conn, selector)
	if err := cc.Handleshake(); err != nil {
		return nil, err
	}
	return cc, nil
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

func (c *udpTunnelConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	dgram, err := gosocks5.ReadUDPDatagram(c.Conn)
	if err != nil {
		return
	}
	n = copy(b, dgram.Data)
	addr, err = net.ResolveUDPAddr("udp", dgram.Header.Addr.String())
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

func (c *udpTunnelConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	dgram := gosocks5.NewUDPDatagram(gosocks5.NewUDPHeader(uint16(len(b)), 0, toSocksAddr(addr)), b)
	if err = dgram.Write(c.Conn); err != nil {
		return
	}
	return len(b), nil
}

// socks5BindConn is a connection for SOCKS5 bind client.
type socks5BindConn struct {
	raddr net.Addr
	laddr net.Addr
	net.Conn
	handshaked   bool
	handshakeMux sync.Mutex
}

// Handshake waits for a peer to connect to the bind port.
func (c *socks5BindConn) Handshake() (err error) {
	c.handshakeMux.Lock()
	defer c.handshakeMux.Unlock()

	if c.handshaked {
		return nil
	}

	c.handshaked = true

	rep, err := gosocks5.ReadReply(c.Conn)
	if err != nil {
		return fmt.Errorf("bind: read reply %v", err)
	}
	if rep.Rep != gosocks5.Succeeded {
		return fmt.Errorf("bind: peer connect failure")
	}
	c.raddr, err = net.ResolveTCPAddr("tcp", rep.Addr.String())
	return
}

func (c *socks5BindConn) Read(b []byte) (n int, err error) {
	if err = c.Handshake(); err != nil {
		return
	}
	return c.Conn.Read(b)
}

func (c *socks5BindConn) Write(b []byte) (n int, err error) {
	if err = c.Handshake(); err != nil {
		return
	}
	return c.Conn.Write(b)
}

func (c *socks5BindConn) LocalAddr() net.Addr {
	return c.laddr
}

func (c *socks5BindConn) RemoteAddr() net.Addr {
	return c.raddr
}

type socks5UDPConn struct {
	*net.UDPConn
	taddr net.Addr
}

func (c *socks5UDPConn) Read(b []byte) (n int, err error) {
	n, _, err = c.ReadFrom(b)
	return
}

func (c *socks5UDPConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	data := mPool.Get().([]byte)
	defer mPool.Put(data)

	n, err = c.UDPConn.Read(data)
	if err != nil {
		return
	}
	dg, err := gosocks5.ReadUDPDatagram(bytes.NewReader(data[:n]))
	if err != nil {
		return
	}

	n = copy(b, dg.Data)
	addr, err = net.ResolveUDPAddr("udp", dg.Header.Addr.String())

	return
}

func (c *socks5UDPConn) Write(b []byte) (int, error) {
	return c.WriteTo(b, c.taddr)
}

func (c *socks5UDPConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	adr, err := gosocks5.NewAddr(addr.String())
	if err != nil {
		return 0, err
	}
	h := gosocks5.NewUDPHeader(0, 0, adr)
	dg := gosocks5.NewUDPDatagram(h, b)
	if err = dg.Write(c.UDPConn); err != nil {
		return 0, err
	}
	return len(b), nil
}

// a dummy client conn for multiplex bind used by SOCKS5 multiplex bind client connector
type muxBindClientConn struct {
	nopConn
	session *muxSession
}

func (c *muxBindClientConn) Accept() (net.Conn, error) {
	return c.session.Accept()
}
