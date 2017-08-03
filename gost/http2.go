package gost

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-log/log"
	"golang.org/x/net/http2"
)

type http2Connector struct {
	User *url.Userinfo
}

// HTTP2Connector creates a Connector for HTTP2 proxy client.
// It accepts an optional auth info for HTTP Basic Authentication.
func HTTP2Connector(user *url.Userinfo) Connector {
	return &http2Connector{User: user}
}

func (c *http2Connector) Connect(conn net.Conn, addr string) (net.Conn, error) {
	cc, ok := conn.(*http2ClientConn)
	if !ok {
		return nil, errors.New("wrong connection type")
	}

	pr, pw := io.Pipe()
	req := &http.Request{
		Method:        http.MethodConnect,
		URL:           &url.URL{Scheme: "https", Host: addr},
		Header:        make(http.Header),
		Proto:         "HTTP/2.0",
		ProtoMajor:    2,
		ProtoMinor:    0,
		Body:          pr,
		Host:          addr,
		ContentLength: -1,
	}
	// req.Header.Set("Gost-Target", addr) // Flag header to indicate the address that server connected to
	if c.User != nil {
		req.Header.Set("Proxy-Authorization",
			"Basic "+base64.StdEncoding.EncodeToString([]byte(c.User.String())))
	}
	if Debug {
		dump, _ := httputil.DumpRequest(req, false)
		log.Log("[http2]", string(dump))
	}
	resp, err := cc.client.Do(req)
	if err != nil {
		return nil, err
	}
	if Debug {
		dump, _ := httputil.DumpResponse(resp, false)
		log.Log("[http2]", string(dump))
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, errors.New(resp.Status)
	}
	hc := &http2Conn{
		r:      resp.Body,
		w:      pw,
		closed: make(chan struct{}),
	}
	hc.remoteAddr, _ = net.ResolveTCPAddr("tcp", addr)
	hc.localAddr, _ = net.ResolveTCPAddr("tcp", cc.addr)

	return hc, nil
}

type http2Transporter struct {
	clients     map[string]*http.Client
	clientMutex sync.Mutex
	tlsConfig   *tls.Config
}

// HTTP2Transporter creates a Transporter that is used by HTTP2 h2 proxy client.
func HTTP2Transporter(config *tls.Config) Transporter {
	if config == nil {
		config = &tls.Config{InsecureSkipVerify: true}
	}
	return &http2Transporter{
		clients:   make(map[string]*http.Client),
		tlsConfig: config,
	}
}

func (tr *http2Transporter) Dial(addr string, options ...DialOption) (net.Conn, error) {
	opts := &DialOptions{}
	for _, option := range options {
		option(opts)
	}

	tr.clientMutex.Lock()
	client, ok := tr.clients[addr]
	if !ok {
		transport := http2.Transport{
			TLSClientConfig: tr.tlsConfig,
			DialTLS: func(network, adr string, cfg *tls.Config) (net.Conn, error) {
				conn, err := opts.Chain.Dial(addr)
				if err != nil {
					return nil, err
				}
				return wrapTLSClient(conn, cfg)
			},
		}
		client = &http.Client{
			Transport: &transport,
			Timeout:   opts.Timeout,
		}
		tr.clients[addr] = client
	}
	tr.clientMutex.Unlock()

	return &http2ClientConn{
		addr:   addr,
		client: client,
	}, nil
}

func (tr *http2Transporter) Handshake(conn net.Conn, options ...HandshakeOption) (net.Conn, error) {
	return conn, nil
}

func (tr *http2Transporter) Multiplex() bool {
	return true
}

type h2Transporter struct {
	clients     map[string]*http.Client
	clientMutex sync.Mutex
	tlsConfig   *tls.Config
}

// H2Transporter creates a Transporter that is used by HTTP2 h2 tunnel client.
func H2Transporter(config *tls.Config) Transporter {
	if config == nil {
		config = &tls.Config{InsecureSkipVerify: true}
	}
	return &h2Transporter{
		clients:   make(map[string]*http.Client),
		tlsConfig: config,
	}
}

// H2CTransporter creates a Transporter that is used by HTTP2 h2c tunnel client.
func H2CTransporter() Transporter {
	return &h2Transporter{
		clients: make(map[string]*http.Client),
	}
}

func (tr *h2Transporter) Dial(addr string, options ...DialOption) (net.Conn, error) {
	opts := &DialOptions{}
	for _, option := range options {
		option(opts)
	}

	tr.clientMutex.Lock()
	client, ok := tr.clients[addr]
	if !ok {
		transport := http2.Transport{
			TLSClientConfig: tr.tlsConfig,
			DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
				conn, err := opts.Chain.Dial(addr)
				if err != nil {
					return nil, err
				}
				if tr.tlsConfig == nil {
					return conn, nil
				}
				return wrapTLSClient(conn, cfg)
			},
		}
		client = &http.Client{
			Transport: &transport,
			Timeout:   opts.Timeout,
		}
		tr.clients[addr] = client
	}
	tr.clientMutex.Unlock()

	pr, pw := io.Pipe()
	req := &http.Request{
		Method:        http.MethodConnect,
		URL:           &url.URL{Scheme: "https", Host: addr},
		Header:        make(http.Header),
		Proto:         "HTTP/2.0",
		ProtoMajor:    2,
		ProtoMinor:    0,
		Body:          pr,
		Host:          addr,
		ContentLength: -1,
	}
	if Debug {
		dump, _ := httputil.DumpRequest(req, false)
		log.Log("[http2]", string(dump))
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if Debug {
		dump, _ := httputil.DumpResponse(resp, false)
		log.Log("[http2]", string(dump))
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, errors.New(resp.Status)
	}
	conn := &http2Conn{
		r:      resp.Body,
		w:      pw,
		closed: make(chan struct{}),
	}
	conn.remoteAddr, _ = net.ResolveTCPAddr("tcp", addr)
	conn.localAddr = &net.TCPAddr{IP: net.IPv4zero, Port: 0}
	return conn, nil
}

func (tr *h2Transporter) Handshake(conn net.Conn, options ...HandshakeOption) (net.Conn, error) {
	opts := &HandshakeOptions{}
	for _, option := range options {
		option(opts)
	}
	return conn, nil
}

func (tr *h2Transporter) Multiplex() bool {
	return true
}

type http2Handler struct {
	options *HandlerOptions
}

// HTTP2Handler creates a server Handler for HTTP2 proxy server.
func HTTP2Handler(opts ...HandlerOption) Handler {
	h := &http2Handler{
		options: new(HandlerOptions),
	}
	for _, opt := range opts {
		opt(h.options)
	}

	return h
}

func (h *http2Handler) Handle(conn net.Conn) {
	defer conn.Close()

	h2c, ok := conn.(*http2ServerConn)
	if !ok {
		log.Log("[http2] wrong connection type")
		return
	}

	h.roundTrip(h2c.w, h2c.r)
}

func (h *http2Handler) roundTrip(w http.ResponseWriter, r *http.Request) {
	target := r.Header.Get("Gost-Target")
	if target == "" {
		target = r.Host
	}
	if !strings.Contains(target, ":") {
		target += ":80"
	}

	if Debug {
		log.Logf("[http2] %s %s - %s %s", r.Method, r.RemoteAddr, target, r.Proto)
		dump, _ := httputil.DumpRequest(r, false)
		log.Log("[http2]", string(dump))
	}

	w.Header().Set("Proxy-Agent", "gost/"+Version)

	if !Can("tcp", target, h.options.Whitelist, h.options.Blacklist) {
		log.Logf("[http2] Unauthorized to tcp connect to %s", target)
		w.WriteHeader(http.StatusForbidden)
		return
	}

	u, p, _ := basicProxyAuth(r.Header.Get("Proxy-Authorization"))
	if !authenticate(u, p, h.options.Users...) {
		log.Logf("[http2] %s <- %s : proxy authentication required", r.RemoteAddr, target)
		w.Header().Set("Proxy-Authenticate", "Basic realm=\"gost\"")
		w.WriteHeader(http.StatusProxyAuthRequired)
		return
	}

	r.Header.Del("Proxy-Authorization")
	r.Header.Del("Proxy-Connection")

	cc, err := h.options.Chain.Dial(target)
	if err != nil {
		log.Logf("[http2] %s -> %s : %s", r.RemoteAddr, target, err)
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	defer cc.Close()

	if r.Method == http.MethodConnect {
		w.WriteHeader(http.StatusOK)
		if fw, ok := w.(http.Flusher); ok {
			fw.Flush()
		}

		// compatible with HTTP1.x
		if hj, ok := w.(http.Hijacker); ok && r.ProtoMajor == 1 {
			// we take over the underly connection
			conn, _, err := hj.Hijack()
			if err != nil {
				log.Logf("[http2] %s -> %s : %s", r.RemoteAddr, target, err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			defer conn.Close()

			log.Logf("[http2] %s <-> %s : downgrade to HTTP/1.1", r.RemoteAddr, target)
			transport(conn, cc)
			log.Logf("[http2] %s >-< %s", r.RemoteAddr, target)
			return
		}

		log.Logf("[http2] %s <-> %s", r.RemoteAddr, target)
		errc := make(chan error, 2)
		go func() {
			_, err := io.Copy(cc, r.Body)
			errc <- err
		}()
		go func() {
			_, err := io.Copy(flushWriter{w}, cc)
			errc <- err
		}()

		select {
		case <-errc:
			// glog.V(LWARNING).Infoln("exit", err)
		}
		log.Logf("[http2] %s >-< %s", r.RemoteAddr, target)
		return
	}

	log.Logf("[http2] %s <-> %s", r.RemoteAddr, target)
	if err = r.Write(cc); err != nil {
		log.Logf("[http2] %s -> %s : %s", r.RemoteAddr, target, err)
		return
	}

	resp, err := http.ReadResponse(bufio.NewReader(cc), r)
	if err != nil {
		log.Logf("[http2] %s -> %s : %s", r.RemoteAddr, target, err)
		return
	}
	defer resp.Body.Close()

	for k, v := range resp.Header {
		for _, vv := range v {
			w.Header().Add(k, vv)
		}
	}
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(flushWriter{w}, resp.Body); err != nil {
		log.Logf("[http2] %s <- %s : %s", r.RemoteAddr, target, err)
	}
	log.Logf("[http2] %s >-< %s", r.RemoteAddr, target)
}

type http2Listener struct {
	server   *http.Server
	connChan chan *http2ServerConn
	errChan  chan error
}

// HTTP2Listener creates a Listener for HTTP2 proxy server.
func HTTP2Listener(addr string, config *tls.Config) (Listener, error) {
	l := &http2Listener{
		connChan: make(chan *http2ServerConn, 1024),
		errChan:  make(chan error, 1),
	}
	server := &http.Server{
		Addr:      addr,
		Handler:   http.HandlerFunc(l.handleFunc),
		TLSConfig: config,
	}
	if err := http2.ConfigureServer(server, nil); err != nil {
		return nil, err
	}
	l.server = server
	go server.ListenAndServeTLS("", "")

	return l, nil
}

func (l *http2Listener) handleFunc(w http.ResponseWriter, r *http.Request) {
	conn := &http2ServerConn{
		r:      r,
		w:      w,
		closed: make(chan struct{}),
	}
	select {
	case l.connChan <- conn:
	default:
		log.Logf("[http2] %s - %s: connection queue is full", r.RemoteAddr, l.server.Addr)
		return
	}

	<-conn.closed
}

func (l *http2Listener) Accept() (conn net.Conn, err error) {
	select {
	case conn = <-l.connChan:
	case err = <-l.errChan:
		if err == nil {
			err = errors.New("accpet on closed listener")
		}
	}
	return
}

func (l *http2Listener) Addr() net.Addr {
	addr, _ := net.ResolveTCPAddr("tcp", l.server.Addr)
	return addr
}

func (l *http2Listener) Close() (err error) {
	select {
	case <-l.errChan:
	default:
		err = l.server.Close()
		l.errChan <- err
		close(l.errChan)
	}
	return nil
}

type h2Listener struct {
	net.Listener
	server    *http2.Server
	tlsConfig *tls.Config
	connChan  chan net.Conn
	errChan   chan error
}

// H2Listener creates a Listener for HTTP2 h2 tunnel server.
func H2Listener(addr string, config *tls.Config) (Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	l := &h2Listener{
		Listener: ln,
		server: &http2.Server{
			// MaxConcurrentStreams:         1000,
			PermitProhibitedCipherSuites: true,
			IdleTimeout:                  5 * time.Minute,
		},
		tlsConfig: config,
		connChan:  make(chan net.Conn, 1024),
		errChan:   make(chan error, 1),
	}
	go l.listenLoop()

	return l, nil
}

// H2CListener creates a Listener for HTTP2 h2c tunnel server.
func H2CListener(addr string) (Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	l := &h2Listener{
		Listener: ln,
		server:   &http2.Server{
		// MaxConcurrentStreams:         1000,
		},
		connChan: make(chan net.Conn, 1024),
		errChan:  make(chan error, 1),
	}
	go l.listenLoop()

	return l, nil
}

func (l *h2Listener) listenLoop() {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			log.Log("[http2] accept:", err)
			l.errChan <- err
			close(l.errChan)
			return
		}
		go l.handleLoop(conn)
	}
}

func (l *h2Listener) handleLoop(conn net.Conn) {
	if l.tlsConfig != nil {
		conn = tls.Server(conn, l.tlsConfig)
	}

	if tc, ok := conn.(*tls.Conn); ok {
		// NOTE: HTTP2 server will check the TLS version,
		// so we must ensure that the TLS connection is handshake completed.
		if err := tc.Handshake(); err != nil {
			log.Logf("[http2] %s - %s : %s", conn.RemoteAddr(), conn.LocalAddr(), err)
			return
		}
	}

	opt := http2.ServeConnOpts{
		Handler: http.HandlerFunc(l.handleFunc),
	}
	l.server.ServeConn(conn, &opt)
}

func (l *h2Listener) handleFunc(w http.ResponseWriter, r *http.Request) {
	log.Logf("[http2] %s %s - %s %s", r.Method, r.RemoteAddr, r.Host, r.Proto)
	if Debug {
		dump, _ := httputil.DumpRequest(r, false)
		log.Log("[http2]", string(dump))
	}
	w.Header().Set("Proxy-Agent", "gost/"+Version)
	conn, err := l.upgrade(w, r)
	if err != nil {
		log.Logf("[http2] %s %s - %s %s", r.Method, r.RemoteAddr, r.Host, r.Proto)
		return
	}
	select {
	case l.connChan <- conn:
	default:
		conn.Close()
		log.Logf("[http2] %s - %s: connection queue is full", conn.RemoteAddr(), conn.LocalAddr())
	}

	<-conn.closed // NOTE: we need to wait for streaming end, or the connection will be closed
}

func (l *h2Listener) upgrade(w http.ResponseWriter, r *http.Request) (*http2Conn, error) {
	if r.Method != http.MethodConnect {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return nil, errors.New("Method not allowed")
	}
	w.WriteHeader(http.StatusOK)
	if fw, ok := w.(http.Flusher); ok {
		fw.Flush() // write header to client
	}

	remoteAddr, _ := net.ResolveTCPAddr("tcp", r.RemoteAddr)
	if remoteAddr == nil {
		remoteAddr = &net.TCPAddr{
			IP:   net.IPv4zero,
			Port: 0,
		}
	}
	conn := &http2Conn{
		r:          r.Body,
		w:          flushWriter{w},
		localAddr:  l.Listener.Addr(),
		remoteAddr: remoteAddr,
		closed:     make(chan struct{}),
	}
	return conn, nil
}

func (l *h2Listener) Accept() (conn net.Conn, err error) {
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

// HTTP2 connection, wrapped up just like a net.Conn
type http2Conn struct {
	r          io.Reader
	w          io.Writer
	remoteAddr net.Addr
	localAddr  net.Addr
	closed     chan struct{}
}

func (c *http2Conn) Read(b []byte) (n int, err error) {
	return c.r.Read(b)
}

func (c *http2Conn) Write(b []byte) (n int, err error) {
	return c.w.Write(b)
}

func (c *http2Conn) Close() (err error) {
	select {
	case <-c.closed:
		return
	default:
		close(c.closed)
	}
	if rc, ok := c.r.(io.Closer); ok {
		err = rc.Close()
	}
	if w, ok := c.w.(io.Closer); ok {
		err = w.Close()
	}
	return
}

func (c *http2Conn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *http2Conn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *http2Conn) SetDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "http2", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

func (c *http2Conn) SetReadDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "http2", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

func (c *http2Conn) SetWriteDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "http2", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

// a dummy HTTP2 server conn used by HTTP2 handler
type http2ServerConn struct {
	r      *http.Request
	w      http.ResponseWriter
	closed chan struct{}
}

func (c *http2ServerConn) Read(b []byte) (n int, err error) {
	return 0, &net.OpError{Op: "read", Net: "http2", Source: nil, Addr: nil, Err: errors.New("read not supported")}
}

func (c *http2ServerConn) Write(b []byte) (n int, err error) {
	return 0, &net.OpError{Op: "write", Net: "http2", Source: nil, Addr: nil, Err: errors.New("write not supported")}
}

func (c *http2ServerConn) Close() error {
	select {
	case <-c.closed:
	default:
		close(c.closed)
	}
	return nil
}

func (c *http2ServerConn) LocalAddr() net.Addr {
	addr, _ := net.ResolveTCPAddr("tcp", c.r.Host)
	return addr
}

func (c *http2ServerConn) RemoteAddr() net.Addr {
	addr, _ := net.ResolveTCPAddr("tcp", c.r.RemoteAddr)
	return addr
}

func (c *http2ServerConn) SetDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "http2", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

func (c *http2ServerConn) SetReadDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "http2", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

func (c *http2ServerConn) SetWriteDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "http2", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

// a dummy HTTP2 client conn used by HTTP2 client connector
type http2ClientConn struct {
	addr   string
	client *http.Client
}

func (c *http2ClientConn) Read(b []byte) (n int, err error) {
	return 0, &net.OpError{Op: "read", Net: "http2", Source: nil, Addr: nil, Err: errors.New("read not supported")}
}

func (c *http2ClientConn) Write(b []byte) (n int, err error) {
	return 0, &net.OpError{Op: "write", Net: "http2", Source: nil, Addr: nil, Err: errors.New("write not supported")}
}

func (c *http2ClientConn) Close() error {
	return nil
}

func (c *http2ClientConn) LocalAddr() net.Addr {
	return nil
}

func (c *http2ClientConn) RemoteAddr() net.Addr {
	return nil
}

func (c *http2ClientConn) SetDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "http2", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

func (c *http2ClientConn) SetReadDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "http2", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

func (c *http2ClientConn) SetWriteDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "http2", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

type flushWriter struct {
	w io.Writer
}

func (fw flushWriter) Write(p []byte) (n int, err error) {
	defer func() {
		if r := recover(); r != nil {
			if s, ok := r.(string); ok {
				err = errors.New(s)
				log.Log("[http2]", err)
				return
			}
			err = r.(error)
		}
	}()

	n, err = fw.w.Write(p)
	if err != nil {
		// log.Log("flush writer:", err)
		return
	}
	if f, ok := fw.w.(http.Flusher); ok {
		f.Flush()
	}
	return
}
