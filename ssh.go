package gost

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-log/log"
	"golang.org/x/crypto/ssh"
)

// Applicable SSH Request types for Port Forwarding - RFC 4254 7.X
const (
	DirectForwardRequest       = "direct-tcpip"         // RFC 4254 7.2
	RemoteForwardRequest       = "tcpip-forward"        // RFC 4254 7.1
	ForwardedTCPReturnRequest  = "forwarded-tcpip"      // RFC 4254 7.2
	CancelRemoteForwardRequest = "cancel-tcpip-forward" // RFC 4254 7.1

	GostSSHTunnelRequest = "gost-tunnel" // extended request type for ssh tunnel
)

var (
	errSessionDead = errors.New("session is dead")
)

type sshDirectForwardConnector struct {
}

// SSHDirectForwardConnector creates a Connector for SSH TCP direct port forwarding.
func SSHDirectForwardConnector() Connector {
	return &sshDirectForwardConnector{}
}

func (c *sshDirectForwardConnector) Connect(conn net.Conn, raddr string, options ...ConnectOption) (net.Conn, error) {
	opts := &ConnectOptions{}
	for _, option := range options {
		option(opts)
	}

	cc, ok := conn.(*sshNopConn) // TODO: this is an ugly type assertion, need to find a better solution.
	if !ok {
		return nil, errors.New("ssh: wrong connection type")
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = ConnectTimeout
	}

	cc.session.conn.SetDeadline(time.Now().Add(timeout))
	defer cc.session.conn.SetDeadline(time.Time{})

	conn, err := cc.session.client.Dial("tcp", raddr)
	if err != nil {
		log.Logf("[ssh-tcp] %s -> %s : %s", cc.session.addr, raddr, err)
		return nil, err
	}
	return conn, nil
}

type sshRemoteForwardConnector struct {
}

// SSHRemoteForwardConnector creates a Connector for SSH TCP remote port forwarding.
func SSHRemoteForwardConnector() Connector {
	return &sshRemoteForwardConnector{}
}

func (c *sshRemoteForwardConnector) Connect(conn net.Conn, addr string, options ...ConnectOption) (net.Conn, error) {
	cc, ok := conn.(*sshNopConn) // TODO: this is an ugly type assertion, need to find a better solution.
	if !ok {
		return nil, errors.New("ssh: wrong connection type")
	}

	cc.session.once.Do(func() {
		go func() {
			defer log.Log("ssh-rtcp: session is closed")
			defer close(cc.session.connChan)

			if cc.session == nil || cc.session.client == nil {
				return
			}
			if strings.HasPrefix(addr, ":") {
				addr = "0.0.0.0" + addr
			}
			ln, err := cc.session.client.Listen("tcp", addr)
			if err != nil {
				return
			}
			log.Log("[ssh-rtcp] listening on", ln.Addr())

			for {
				rc, err := ln.Accept()
				if err != nil {
					log.Logf("[ssh-rtcp] %s <-> %s accpet : %s", ln.Addr(), addr, err)
					return
				}
				// log.Log("[ssh-rtcp] accept", rc.LocalAddr(), rc.RemoteAddr())
				select {
				case cc.session.connChan <- rc:
				default:
					rc.Close()
					log.Logf("[ssh-rtcp] %s - %s: connection queue is full", ln.Addr(), addr)
				}
			}
		}()
	})

	sc, ok := <-cc.session.connChan
	if !ok {
		return nil, errors.New("ssh-rtcp: connection is closed")
	}
	return sc, nil
}

type sshForwardTransporter struct {
	sessions     map[string]*sshSession
	sessionMutex sync.Mutex
}

// SSHForwardTransporter creates a Transporter that is used by SSH port forwarding server.
func SSHForwardTransporter() Transporter {
	return &sshForwardTransporter{
		sessions: make(map[string]*sshSession),
	}
}

func (tr *sshForwardTransporter) Dial(addr string, options ...DialOption) (conn net.Conn, err error) {
	opts := &DialOptions{}
	for _, option := range options {
		option(opts)
	}

	tr.sessionMutex.Lock()
	defer tr.sessionMutex.Unlock()

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DialTimeout
	}

	session, ok := tr.sessions[addr]
	if !ok || session.Closed() {
		if opts.Chain == nil {
			conn, err = net.DialTimeout("tcp", addr, timeout)
		} else {
			conn, err = opts.Chain.Dial(addr)
		}
		if err != nil {
			return
		}
		session = &sshSession{
			addr: addr,
			conn: conn,
		}
		tr.sessions[addr] = session
	}

	return session.conn, nil
}

func (tr *sshForwardTransporter) Handshake(conn net.Conn, options ...HandshakeOption) (net.Conn, error) {
	opts := &HandshakeOptions{}
	for _, option := range options {
		option(opts)
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = HandshakeTimeout
	}

	config := ssh.ClientConfig{
		Timeout:         timeout,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	if opts.User != nil {
		config.User = opts.User.Username()
		password, _ := opts.User.Password()
		config.Auth = []ssh.AuthMethod{
			ssh.Password(password),
		}
	}

	tr.sessionMutex.Lock()
	defer tr.sessionMutex.Unlock()

	conn.SetDeadline(time.Now().Add(timeout))
	defer conn.SetDeadline(time.Time{})

	session, ok := tr.sessions[opts.Addr]
	if !ok || session.client == nil {
		sshConn, chans, reqs, err := ssh.NewClientConn(conn, opts.Addr, &config)
		if err != nil {
			conn.Close()
			delete(tr.sessions, opts.Addr)
			return nil, err
		}

		session = &sshSession{
			addr:     opts.Addr,
			conn:     conn,
			client:   ssh.NewClient(sshConn, chans, reqs),
			closed:   make(chan struct{}),
			deaded:   make(chan struct{}),
			connChan: make(chan net.Conn, 1024),
		}
		tr.sessions[opts.Addr] = session
		go session.Ping(opts.Interval, opts.Timeout, opts.Retry)
		go session.waitServer()
		go session.waitClose()
	}
	if session.Closed() {
		delete(tr.sessions, opts.Addr)
		return nil, errSessionDead
	}

	return &sshNopConn{session: session}, nil
}

func (tr *sshForwardTransporter) Multiplex() bool {
	return true
}

type sshTunnelTransporter struct {
	sessions     map[string]*sshSession
	sessionMutex sync.Mutex
}

// SSHTunnelTransporter creates a Transporter that is used by SSH tunnel client.
func SSHTunnelTransporter() Transporter {
	return &sshTunnelTransporter{
		sessions: make(map[string]*sshSession),
	}
}

func (tr *sshTunnelTransporter) Dial(addr string, options ...DialOption) (conn net.Conn, err error) {
	opts := &DialOptions{}
	for _, option := range options {
		option(opts)
	}

	tr.sessionMutex.Lock()
	defer tr.sessionMutex.Unlock()

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DialTimeout
	}

	session, ok := tr.sessions[addr]
	if !ok || session.Closed() {
		if opts.Chain == nil {
			conn, err = net.DialTimeout("tcp", addr, timeout)
		} else {
			conn, err = opts.Chain.Dial(addr)
		}
		if err != nil {
			return
		}
		session = &sshSession{
			addr: addr,
			conn: conn,
		}
		tr.sessions[addr] = session
	}

	return session.conn, nil
}

func (tr *sshTunnelTransporter) Handshake(conn net.Conn, options ...HandshakeOption) (net.Conn, error) {
	opts := &HandshakeOptions{}
	for _, option := range options {
		option(opts)
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = HandshakeTimeout
	}

	config := ssh.ClientConfig{
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	// TODO: support pubkey auth.
	if opts.User != nil {
		config.User = opts.User.Username()
		password, _ := opts.User.Password()
		config.Auth = []ssh.AuthMethod{
			ssh.Password(password),
		}
	}

	tr.sessionMutex.Lock()
	defer tr.sessionMutex.Unlock()

	conn.SetDeadline(time.Now().Add(timeout))
	defer conn.SetDeadline(time.Time{})

	session, ok := tr.sessions[opts.Addr]
	if !ok || session.client == nil {
		sshConn, chans, reqs, err := ssh.NewClientConn(conn, opts.Addr, &config)
		if err != nil {
			conn.Close()
			delete(tr.sessions, opts.Addr)
			return nil, err
		}

		session = &sshSession{
			addr:   opts.Addr,
			conn:   conn,
			client: ssh.NewClient(sshConn, chans, reqs),
			closed: make(chan struct{}),
			deaded: make(chan struct{}),
		}
		tr.sessions[opts.Addr] = session
		go session.Ping(opts.Interval, opts.Timeout, opts.Retry)
		go session.waitServer()
		go session.waitClose()
	}

	if session.Closed() {
		delete(tr.sessions, opts.Addr)
		return nil, errSessionDead
	}

	channel, reqs, err := session.client.OpenChannel(GostSSHTunnelRequest, nil)
	if err != nil {
		return nil, err
	}
	go ssh.DiscardRequests(reqs)
	return &sshConn{channel: channel, conn: conn}, nil
}

func (tr *sshTunnelTransporter) Multiplex() bool {
	return true
}

type sshSession struct {
	addr     string
	conn     net.Conn
	client   *ssh.Client
	closed   chan struct{}
	deaded   chan struct{}
	once     sync.Once
	connChan chan net.Conn
}

func (s *sshSession) Ping(interval, timeout time.Duration, retries int) {
	if interval <= 0 {
		return
	}
	if timeout <= 0 {
		timeout = PingTimeout
	}

	if retries == 0 {
		retries = 1
	}

	defer close(s.deaded)

	log.Logf("[ssh] ping is enabled, interval: %v, timeout: %v, retry: %d", interval, timeout, retries)
	baseCtx := context.Background()
	t := time.NewTicker(interval)
	defer t.Stop()

	count := retries + 1
	for {
		select {
		case <-t.C:
			start := time.Now()
			if Debug {
				log.Log("[ssh] sending ping")
			}
			ctx, cancel := context.WithTimeout(baseCtx, timeout)
			var err error
			select {
			case err = <-s.sendPing():
			case <-ctx.Done():
				err = errors.New("Timeout")
			}
			cancel()
			if err != nil {
				log.Log("[ssh] ping:", err)
				count--
				if count == 0 {
					return
				}
				continue
			}
			if Debug {
				log.Log("[ssh] ping OK, RTT:", time.Since(start))
			}
			count = retries + 1
		case <-s.closed:
			return
		}
	}
}

func (s *sshSession) sendPing() <-chan error {
	ch := make(chan error, 1)
	go func() {
		if _, _, err := s.client.SendRequest("ping", true, nil); err != nil {
			ch <- err
		}
		close(ch)
	}()
	return ch
}

func (s *sshSession) waitServer() error {
	defer close(s.closed)
	return s.client.Wait()
}

func (s *sshSession) waitClose() {
	defer s.client.Close()

	select {
	case <-s.deaded:
	case <-s.closed:
	}
}

func (s *sshSession) Closed() bool {
	select {
	case <-s.deaded:
		return true
	case <-s.closed:
		return true
	default:
	}
	return false
}

type sshForwardHandler struct {
	options *HandlerOptions
	config  *ssh.ServerConfig
}

// SSHForwardHandler creates a server Handler for SSH port forwarding server.
func SSHForwardHandler(opts ...HandlerOption) Handler {
	h := &sshForwardHandler{}
	h.Init(opts...)

	return h
}

func (h *sshForwardHandler) Init(options ...HandlerOption) {
	if h.options == nil {
		h.options = &HandlerOptions{}
	}

	for _, opt := range options {
		opt(h.options)
	}
	h.config = &ssh.ServerConfig{}

	h.config.PasswordCallback = defaultSSHPasswordCallback(h.options.Authenticator)
	if h.options.Authenticator == nil {
		h.config.NoClientAuth = true
	}
	tlsConfig := h.options.TLSConfig
	if tlsConfig == nil {
		tlsConfig = DefaultTLSConfig
	}
	if tlsConfig != nil && len(tlsConfig.Certificates) > 0 {
		signer, err := ssh.NewSignerFromKey(tlsConfig.Certificates[0].PrivateKey)
		if err != nil {
			log.Log("[ssh-forward]", err)
		}
		h.config.AddHostKey(signer)
	}
}

func (h *sshForwardHandler) Handle(conn net.Conn) {
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, h.config)
	if err != nil {
		log.Logf("[ssh-forward] %s -> %s : %s", conn.RemoteAddr(), h.options.Node.Addr, err)
		conn.Close()
		return
	}
	defer sshConn.Close()

	log.Logf("[ssh-forward] %s <-> %s", conn.RemoteAddr(), h.options.Node.Addr)
	h.handleForward(sshConn, chans, reqs)
	log.Logf("[ssh-forward] %s >-< %s", conn.RemoteAddr(), h.options.Node.Addr)
}

func (h *sshForwardHandler) handleForward(conn ssh.Conn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request) {
	quit := make(chan struct{})
	defer close(quit) // quit signal

	go func() {
		for req := range reqs {
			switch req.Type {
			case RemoteForwardRequest:
				go h.tcpipForwardRequest(conn, req, quit)
			default:
				// log.Log("[ssh] unknown request type:", req.Type, req.WantReply)
				if req.WantReply {
					req.Reply(false, nil)
				}
			}
		}
	}()

	go func() {
		for newChannel := range chans {
			// Check the type of channel
			t := newChannel.ChannelType()
			switch t {
			case DirectForwardRequest:
				channel, requests, err := newChannel.Accept()
				if err != nil {
					log.Log("[ssh] Could not accept channel:", err)
					continue
				}
				p := directForward{}
				ssh.Unmarshal(newChannel.ExtraData(), &p)

				if p.Host1 == "<nil>" {
					p.Host1 = ""
				}

				go ssh.DiscardRequests(requests)
				go h.directPortForwardChannel(channel, fmt.Sprintf("%s:%d", p.Host1, p.Port1))
			default:
				log.Log("[ssh] Unknown channel type:", t)
				newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", t))
			}
		}
	}()

	conn.Wait()
}

func (h *sshForwardHandler) directPortForwardChannel(channel ssh.Channel, raddr string) {
	defer channel.Close()

	log.Logf("[ssh-tcp] %s - %s", h.options.Node.Addr, raddr)

	if !Can("tcp", raddr, h.options.Whitelist, h.options.Blacklist) {
		log.Logf("[ssh-tcp] Unauthorized to tcp connect to %s", raddr)
		return
	}

	if h.options.Bypass.Contains(raddr) {
		log.Logf("[ssh-tcp] [bypass] %s", raddr)
		return
	}

	conn, err := h.options.Chain.Dial(raddr,
		RetryChainOption(h.options.Retries),
		TimeoutChainOption(h.options.Timeout),
		HostsChainOption(h.options.Hosts),
		ResolverChainOption(h.options.Resolver),
	)
	if err != nil {
		log.Logf("[ssh-tcp] %s - %s : %s", h.options.Node.Addr, raddr, err)
		return
	}
	defer conn.Close()

	log.Logf("[ssh-tcp] %s <-> %s", h.options.Node.Addr, raddr)
	transport(conn, channel)
	log.Logf("[ssh-tcp] %s >-< %s", h.options.Node.Addr, raddr)
}

// tcpipForward is structure for RFC 4254 7.1 "tcpip-forward" request
type tcpipForward struct {
	Host string
	Port uint32
}

func (h *sshForwardHandler) tcpipForwardRequest(sshConn ssh.Conn, req *ssh.Request, quit <-chan struct{}) {
	t := tcpipForward{}
	ssh.Unmarshal(req.Payload, &t)

	addr := fmt.Sprintf("%s:%d", t.Host, t.Port)

	if !Can("rtcp", addr, h.options.Whitelist, h.options.Blacklist) {
		log.Logf("[ssh-rtcp] Unauthorized to tcp bind to %s", addr)
		req.Reply(false, nil)
		return
	}

	ln, err := net.Listen("tcp", addr) //tie to the client connection
	if err != nil {
		log.Log("[ssh-rtcp]", err)
		req.Reply(false, nil)
		return
	}
	defer ln.Close()

	log.Log("[ssh-rtcp] listening on tcp", ln.Addr())

	replyFunc := func() error {
		if t.Port == 0 && req.WantReply { // Client sent port 0. let them know which port is actually being used
			_, port, err := getHostPortFromAddr(ln.Addr())
			if err != nil {
				return err
			}
			var b [4]byte
			binary.BigEndian.PutUint32(b[:], uint32(port))
			t.Port = uint32(port)
			return req.Reply(true, b[:])
		}
		return req.Reply(true, nil)
	}
	if err := replyFunc(); err != nil {
		log.Log("[ssh-rtcp]", err)
		return
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil { // Unable to accept new connection - listener is likely closed
				return
			}

			go func(conn net.Conn) {
				defer conn.Close()

				p := directForward{}
				var err error

				var portnum int
				p.Host1 = t.Host
				p.Port1 = t.Port
				p.Host2, portnum, err = getHostPortFromAddr(conn.RemoteAddr())
				if err != nil {
					return
				}

				p.Port2 = uint32(portnum)
				ch, reqs, err := sshConn.OpenChannel(ForwardedTCPReturnRequest, ssh.Marshal(p))
				if err != nil {
					log.Log("[ssh-rtcp] open forwarded channel:", err)
					return
				}
				defer ch.Close()
				go ssh.DiscardRequests(reqs)

				log.Logf("[ssh-rtcp] %s <-> %s", conn.RemoteAddr(), conn.LocalAddr())
				transport(ch, conn)
				log.Logf("[ssh-rtcp] %s >-< %s", conn.RemoteAddr(), conn.LocalAddr())
			}(conn)
		}
	}()

	<-quit
}

// SSHConfig holds the SSH tunnel server config
type SSHConfig struct {
	Authenticator Authenticator
	TLSConfig     *tls.Config
}

type sshTunnelListener struct {
	net.Listener
	config   *ssh.ServerConfig
	connChan chan net.Conn
	errChan  chan error
}

// SSHTunnelListener creates a Listener for SSH tunnel server.
func SSHTunnelListener(addr string, config *SSHConfig) (Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	if config == nil {
		config = &SSHConfig{}
	}

	sshConfig := &ssh.ServerConfig{}
	sshConfig.PasswordCallback = defaultSSHPasswordCallback(config.Authenticator)
	if config.Authenticator == nil {
		sshConfig.NoClientAuth = true
	}
	tlsConfig := config.TLSConfig
	if tlsConfig == nil {
		tlsConfig = DefaultTLSConfig
	}

	signer, err := ssh.NewSignerFromKey(tlsConfig.Certificates[0].PrivateKey)
	if err != nil {
		ln.Close()
		return nil, err

	}
	sshConfig.AddHostKey(signer)

	l := &sshTunnelListener{
		Listener: tcpKeepAliveListener{ln.(*net.TCPListener)},
		config:   sshConfig,
		connChan: make(chan net.Conn, 1024),
		errChan:  make(chan error, 1),
	}

	go l.listenLoop()

	return l, nil
}

func (l *sshTunnelListener) listenLoop() {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			log.Log("[ssh] accept:", err)
			l.errChan <- err
			close(l.errChan)
			return
		}
		go l.serveConn(conn)
	}
}

func (l *sshTunnelListener) serveConn(conn net.Conn) {
	sc, chans, reqs, err := ssh.NewServerConn(conn, l.config)
	if err != nil {
		log.Logf("[ssh] %s -> %s : %s", conn.RemoteAddr(), conn.LocalAddr(), err)
		conn.Close()
		return
	}
	defer sc.Close()

	go ssh.DiscardRequests(reqs)
	go func() {
		for newChannel := range chans {
			// Check the type of channel
			t := newChannel.ChannelType()
			switch t {
			case GostSSHTunnelRequest:
				channel, requests, err := newChannel.Accept()
				if err != nil {
					log.Log("[ssh] Could not accept channel:", err)
					continue
				}
				go ssh.DiscardRequests(requests)
				cc := &sshConn{conn: conn, channel: channel}
				select {
				case l.connChan <- cc:
				default:
					cc.Close()
					log.Logf("[ssh] %s - %s: connection queue is full", conn.RemoteAddr(), l.Addr())
				}

			default:
				log.Log("[ssh] Unknown channel type:", t)
				newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", t))
			}
		}
	}()

	log.Logf("[ssh] %s <-> %s", conn.RemoteAddr(), conn.LocalAddr())
	sc.Wait()
	log.Logf("[ssh] %s >-< %s", conn.RemoteAddr(), conn.LocalAddr())
}

func (l *sshTunnelListener) Accept() (conn net.Conn, err error) {
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

// directForward is structure for RFC 4254 7.2 - can be used for "forwarded-tcpip" and "direct-tcpip"
type directForward struct {
	Host1 string
	Port1 uint32
	Host2 string
	Port2 uint32
}

func (p directForward) String() string {
	return fmt.Sprintf("%s:%d -> %s:%d", p.Host2, p.Port2, p.Host1, p.Port1)
}

func getHostPortFromAddr(addr net.Addr) (host string, port int, err error) {
	host, portString, err := net.SplitHostPort(addr.String())
	if err != nil {
		return
	}
	port, err = strconv.Atoi(portString)
	return
}

// PasswordCallbackFunc is a callback function used by SSH server.
type PasswordCallbackFunc func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error)

func defaultSSHPasswordCallback(au Authenticator) PasswordCallbackFunc {
	return func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		if au.Authenticate(conn.User(), string(password)) {
			return nil, nil
		}
		log.Logf("[ssh] %s -> %s : password rejected for %s", conn.RemoteAddr(), conn.LocalAddr(), conn.User())
		return nil, fmt.Errorf("password rejected for %s", conn.User())
	}
}

type sshNopConn struct {
	session *sshSession
}

func (c *sshNopConn) Read(b []byte) (n int, err error) {
	return 0, &net.OpError{Op: "read", Net: "ssh", Source: nil, Addr: nil, Err: errors.New("read not supported")}
}

func (c *sshNopConn) Write(b []byte) (n int, err error) {
	return 0, &net.OpError{Op: "write", Net: "ssh", Source: nil, Addr: nil, Err: errors.New("write not supported")}
}

func (c *sshNopConn) Close() error {
	return nil
}

func (c *sshNopConn) LocalAddr() net.Addr {
	return &net.TCPAddr{
		IP:   net.IPv4zero,
		Port: 0,
	}
}

func (c *sshNopConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{
		IP:   net.IPv4zero,
		Port: 0,
	}
}

func (c *sshNopConn) SetDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "ssh", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

func (c *sshNopConn) SetReadDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "ssh", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

func (c *sshNopConn) SetWriteDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "ssh", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

type sshConn struct {
	channel ssh.Channel
	conn    net.Conn
}

func (c *sshConn) Read(b []byte) (n int, err error) {
	return c.channel.Read(b)
}

func (c *sshConn) Write(b []byte) (n int, err error) {
	return c.channel.Write(b)
}

func (c *sshConn) Close() error {
	return c.channel.Close()
}

func (c *sshConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *sshConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *sshConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *sshConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *sshConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}
