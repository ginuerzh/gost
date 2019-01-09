package gost

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
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

func (c *http2Connector) Connect(conn net.Conn, addr string, options ...ConnectOption) (net.Conn, error) {
	opts := &ConnectOptions{}
	for _, option := range options {
		option(opts)
	}

	cc, ok := conn.(*http2ClientConn)
	if !ok {
		return nil, errors.New("wrong connection type")
	}

	pr, pw := io.Pipe()
	req := &http.Request{
		Method:        http.MethodConnect,
		URL:           &url.URL{Scheme: "https", Host: cc.addr},
		Header:        make(http.Header),
		Proto:         "HTTP/2.0",
		ProtoMajor:    2,
		ProtoMinor:    0,
		Body:          pr,
		Host:          cc.addr,
		ContentLength: -1,
	}
	// TODO: use the standard CONNECT method.
	req.Header.Set("Gost-Target", addr)

	user := opts.User
	if user == nil {
		user = c.User
	}

	if user != nil {
		u := user.Username()
		p, _ := user.Password()
		req.Header.Set("Proxy-Authorization",
			"Basic "+base64.StdEncoding.EncodeToString([]byte(u+":"+p)))
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
	defer tr.clientMutex.Unlock()

	client, ok := tr.clients[addr]
	if !ok {
		// NOTE: due to the dummy connection, HTTP2 node in a proxy chain can not be marked as dead.
		// There is no real connection to the HTTP2 server at this moment.
		// So we should try to connect the server.
		conn, err := opts.Chain.Dial(addr)
		if err != nil {

			return nil, err
		}
		conn.Close()

		timeout := opts.Timeout
		if timeout <= 0 {
			timeout = DialTimeout
		}
		transport := http2.Transport{
			TLSClientConfig: tr.tlsConfig,
			DialTLS: func(network, adr string, cfg *tls.Config) (net.Conn, error) {
				conn, err := opts.Chain.Dial(adr)
				if err != nil {
					return nil, err
				}
				return wrapTLSClient(conn, cfg, timeout)
			},
		}
		client = &http.Client{
			Transport: &transport,
			// Timeout:   timeout,
		}
		tr.clients[addr] = client
	}

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
		timeout := opts.Timeout
		if timeout <= 0 {
			timeout = DialTimeout
		}

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
				return wrapTLSClient(conn, cfg, timeout)
			},
		}
		client = &http.Client{
			Transport: &transport,
			// Timeout:   timeout,
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
	h := &http2Handler{}
	h.Init(opts...)

	return h
}

func (h *http2Handler) Init(options ...HandlerOption) {
	if h.options == nil {
		h.options = &HandlerOptions{}
	}
	for _, opt := range options {
		opt(h.options)
	}
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
	host := r.Header.Get("Gost-Target")
	if host == "" {
		host = r.Host
	}

	if _, port, _ := net.SplitHostPort(host); port == "" {
		host = net.JoinHostPort(host, "80")
	}

	laddr := h.options.Addr
	u, _, _ := basicProxyAuth(r.Header.Get("Proxy-Authorization"))
	if u != "" {
		u += "@"
	}
	log.Logf("[http2] %s%s -> %s -> %s",
		u, r.RemoteAddr, h.options.Node.String(), host)

	if Debug {
		dump, _ := httputil.DumpRequest(r, false)
		log.Logf("[http2] %s - %s\n%s", r.RemoteAddr, laddr, string(dump))
	}

	w.Header().Set("Proxy-Agent", "gost/"+Version)

	if !Can("tcp", host, h.options.Whitelist, h.options.Blacklist) {
		log.Logf("[http2] %s - %s : Unauthorized to tcp connect to %s",
			r.RemoteAddr, laddr, host)
		w.WriteHeader(http.StatusForbidden)
		return
	}

	if h.options.Bypass.Contains(host) {
		log.Logf("[http2] %s - %s bypass %s",
			r.RemoteAddr, laddr, host)
		w.WriteHeader(http.StatusForbidden)
		return
	}

	resp := &http.Response{
		ProtoMajor: 2,
		ProtoMinor: 0,
		Header:     http.Header{},
		Body:       ioutil.NopCloser(bytes.NewReader([]byte{})),
	}

	if !h.authenticate(w, r, resp) {
		return
	}

	// delete the proxy related headers.
	r.Header.Del("Proxy-Authorization")
	r.Header.Del("Proxy-Connection")

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
			log.Logf("[http2] %s -> %s : %s",
				r.RemoteAddr, laddr, err)
			continue
		}

		buf := bytes.Buffer{}
		fmt.Fprintf(&buf, "%s -> %s -> ",
			r.RemoteAddr, h.options.Node.String())
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
		log.Logf("[http2] %s -> %s : %s", r.RemoteAddr, laddr, err)
	}

	if err != nil {
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
				log.Logf("[http2] %s -> %s : %s",
					r.RemoteAddr, laddr, err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			defer conn.Close()

			log.Logf("[http2] %s <-> %s : downgrade to HTTP/1.1", r.RemoteAddr, host)
			transport(conn, cc)
			log.Logf("[http2] %s >-< %s", r.RemoteAddr, host)
			return
		}

		log.Logf("[http2] %s <-> %s", r.RemoteAddr, host)
		transport(&readWriter{r: r.Body, w: flushWriter{w}}, cc)
		log.Logf("[http2] %s >-< %s", r.RemoteAddr, host)
		return
	}

	log.Logf("[http2] %s <-> %s", r.RemoteAddr, host)
	if err := h.forwardRequest(w, r, cc); err != nil {
		log.Logf("[http2] %s - %s : %s", r.RemoteAddr, host, err)
	}
	log.Logf("[http2] %s >-< %s", r.RemoteAddr, host)
}

func (h *http2Handler) authenticate(w http.ResponseWriter, r *http.Request, resp *http.Response) (ok bool) {
	laddr := h.options.Addr
	u, p, _ := basicProxyAuth(r.Header.Get("Proxy-Authorization"))
	if Debug && (u != "" || p != "") {
		log.Logf("[http2] %s - %s : Authorization '%s' '%s'", r.RemoteAddr, laddr, u, p)
	}
	if h.options.Authenticator == nil || h.options.Authenticator.Authenticate(u, p) {
		return true
	}

	// probing resistance is enabled
	if ss := strings.SplitN(h.options.ProbeResist, ":", 2); len(ss) == 2 {
		switch ss[0] {
		case "code":
			resp.StatusCode, _ = strconv.Atoi(ss[1])
		case "web":
			url := ss[1]
			if !strings.HasPrefix(url, "http") {
				url = "http://" + url
			}
			if r, err := http.Get(url); err == nil {
				resp = r
			}
		case "host":
			cc, err := net.Dial("tcp", ss[1])
			if err == nil {
				defer cc.Close()
				log.Logf("[http2] %s <-> %s : forward to %s", r.RemoteAddr, laddr, ss[1])
				if err := h.forwardRequest(w, r, cc); err != nil {
					log.Logf("[http2] %s - %s : %s", r.RemoteAddr, laddr, err)
				}
				log.Logf("[http2] %s >-< %s : forward to %s", r.RemoteAddr, laddr, ss[1])
				return
			}
		case "file":
			f, _ := os.Open(ss[1])
			if f != nil {
				resp.StatusCode = http.StatusOK
				if finfo, _ := f.Stat(); finfo != nil {
					resp.ContentLength = finfo.Size()
				}
				resp.Body = f
			}
		}
	}

	if resp.StatusCode == 0 {
		log.Logf("[http2] %s <- %s : proxy authentication required", r.RemoteAddr, laddr)
		resp.StatusCode = http.StatusProxyAuthRequired
		resp.Header.Add("Proxy-Authenticate", "Basic realm=\"gost\"")
	} else {
		w.Header().Del("Proxy-Agent")
		resp.Header = http.Header{}
		resp.Header.Set("Server", "nginx/1.14.1")
		resp.Header.Set("Date", time.Now().Format(http.TimeFormat))
		if resp.ContentLength > 0 {
			resp.Header.Set("Content-Type", "text/html")
		}
		if resp.StatusCode == http.StatusOK {
			resp.Header.Set("Connection", "keep-alive")
		}
	}

	if Debug {
		dump, _ := httputil.DumpResponse(resp, false)
		log.Logf("[http2] %s <- %s\n%s", r.RemoteAddr, laddr, string(dump))
	}

	h.writeResponse(w, resp)
	resp.Body.Close()

	return
}

func (h *http2Handler) forwardRequest(w http.ResponseWriter, r *http.Request, rw io.ReadWriter) (err error) {
	if err = r.Write(rw); err != nil {
		return
	}

	resp, err := http.ReadResponse(bufio.NewReader(rw), r)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	return h.writeResponse(w, resp)
}

func (h *http2Handler) writeResponse(w http.ResponseWriter, resp *http.Response) error {
	for k, v := range resp.Header {
		for _, vv := range v {
			w.Header().Add(k, vv)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, err := io.Copy(flushWriter{w}, resp.Body)
	return err
}

type http2Listener struct {
	server   *http.Server
	connChan chan *http2ServerConn
	addr     net.Addr
	errChan  chan error
}

// HTTP2Listener creates a Listener for HTTP2 proxy server.
func HTTP2Listener(addr string, config *tls.Config) (Listener, error) {
	l := &http2Listener{
		connChan: make(chan *http2ServerConn, 1024),
		errChan:  make(chan error, 1),
	}
	if config == nil {
		config = DefaultTLSConfig
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

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	l.addr = ln.Addr()

	ln = tls.NewListener(tcpKeepAliveListener{ln.(*net.TCPListener)}, config)
	go func() {
		err := server.Serve(ln)
		if err != nil {
			log.Log("[http2]", err)
		}
	}()

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
	return l.addr
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
	if config == nil {
		config = DefaultTLSConfig
	}

	l := &h2Listener{
		Listener: tcpKeepAliveListener{ln.(*net.TCPListener)},
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
		Listener: tcpKeepAliveListener{ln.(*net.TCPListener)},
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
	nopConn
	addr   string
	client *http.Client
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
