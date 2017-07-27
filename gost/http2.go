package gost

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"io/ioutil"
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
	cc, ok := conn.(*http2DummyConn)
	if !ok {
		return nil, errors.New("wrong connection type")
	}

	pr, pw := io.Pipe()
	u := &url.URL{
		Host: addr,
	}
	req, err := http.NewRequest("CONNECT", u.String(), ioutil.NopCloser(pr))
	if err != nil {
		log.Logf("[http2] %s - %s : %s", cc.raddr, addr, err)
		return nil, err
	}
	if c.User != nil {
		req.Header.Set("Proxy-Authorization",
			"Basic "+base64.StdEncoding.EncodeToString([]byte(c.User.String())))
	}
	req.ProtoMajor = 2
	req.ProtoMinor = 0

	if Debug {
		dump, _ := httputil.DumpRequest(req, false)
		log.Log("[http2]", string(dump))
	}
	resp, err := cc.conn.RoundTrip(req)
	if err != nil {
		log.Logf("[http2] %s - %s : %s", cc.raddr, addr, err)
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
	hc := &http2Conn{r: resp.Body, w: pw}
	hc.remoteAddr, _ = net.ResolveTCPAddr("tcp", cc.raddr)
	return hc, nil
}

type http2Transporter struct {
	tlsConfig    *tls.Config
	tr           *http2.Transport
	chain        *Chain
	sessions     map[string]*http2Session
	sessionMutex sync.Mutex
	pingInterval time.Duration
}

// HTTP2Transporter creates a Transporter that is used by HTTP2 proxy client.
//
// Optional chain is a proxy chain that can be used to establish a connection with the HTTP2 server.
//
// Optional config is a TLS config for TLS handshake, if is nil, will use h2c mode.
//
// Optional ping is the ping interval, if is zero, ping will not be enabled.
func HTTP2Transporter(chain *Chain, config *tls.Config, ping time.Duration) Transporter {
	return &http2Transporter{
		tlsConfig:    config,
		tr:           new(http2.Transport),
		chain:        chain,
		pingInterval: ping,
		sessions:     make(map[string]*http2Session),
	}
}

func (tr *http2Transporter) Dial(addr string, options ...DialOption) (net.Conn, error) {
	tr.sessionMutex.Lock()
	defer tr.sessionMutex.Unlock()

	session, ok := tr.sessions[addr]
	if !ok {
		conn, err := tr.chain.Dial(addr)
		if err != nil {
			return nil, err
		}

		if tr.tlsConfig != nil {
			tc := tls.Client(conn, tr.tlsConfig)
			if err := tc.Handshake(); err != nil {
				return nil, err
			}
			conn = tc
		}
		cc, err := tr.tr.NewClientConn(conn)
		if err != nil {
			return nil, err
		}
		session = newHTTP2Session(conn, cc, tr.pingInterval)
		tr.sessions[addr] = session
	}

	if !session.Healthy() {
		session.Close()
		delete(tr.sessions, addr) // TODO: we could re-connect to the addr automatically.
		return nil, errors.New("connection is dead")
	}

	return &http2DummyConn{
		raddr: addr,
		conn:  session.clientConn,
	}, nil
}

func (tr *http2Transporter) Handshake(conn net.Conn, options ...HandshakeOption) (net.Conn, error) {
	return conn, nil
}

func (tr *http2Transporter) Multiplex() bool {
	return true
}

type http2Handler struct {
	server  *http2.Server
	options *HandlerOptions
}

// HTTP2Handler creates a server Handler for HTTP2 proxy server.
func HTTP2Handler(opts ...HandlerOption) Handler {
	h := &http2Handler{
		server:  new(http2.Server),
		options: new(HandlerOptions),
	}
	for _, opt := range opts {
		opt(h.options)
	}
	return h
}

func (h *http2Handler) Handle(conn net.Conn) {
	defer conn.Close()

	if tc, ok := conn.(*tls.Conn); ok {
		// NOTE: HTTP2 server will check the TLS version,
		// so we must ensure that the TLS connection is handshake completed.
		if err := tc.Handshake(); err != nil {
			log.Logf("[http2] %s - %s : %s", conn.RemoteAddr(), conn.LocalAddr(), err)
			return
		}
	}

	opt := http2.ServeConnOpts{
		Handler: http.HandlerFunc(h.handleFunc),
	}
	h.server.ServeConn(conn, &opt)
}

func (h *http2Handler) handleFunc(w http.ResponseWriter, r *http.Request) {
	target := r.Header.Get("Gost-Target") // compitable with old version
	if target == "" {
		target = r.Host
	}
	if !strings.Contains(target, ":") {
		target += ":80"
	}

	log.Logf("[http2] %s %s - %s %s", r.Method, r.RemoteAddr, target, r.Proto)
	if Debug {
		dump, _ := httputil.DumpRequest(r, false)
		log.Log("[http2]", string(dump))
	}

	w.Header().Set("Proxy-Agent", "gost/"+Version)

	//! if !s.Base.Node.Can("tcp", target) {
	//! 	glog.Errorf("Unauthorized to tcp connect to %s", target)
	//! 	return
	//! }

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

	log.Logf("[http2] %s <-> %s", r.RemoteAddr, target)

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

			log.Logf("[http2] %s -> %s : downgrade to HTTP/1.1", r.RemoteAddr, target)
			transport(conn, cc)
			log.Logf("[http2] %s >-< %s", r.RemoteAddr, target)
			return
		}

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
	ln net.Listener
}

// HTTP2Listener creates a Listener for server using HTTP2 as transport.
func HTTP2Listener(addr string, config *tls.Config) (Listener, error) {
	var ln net.Listener
	var err error

	if config != nil {
		ln, err = tls.Listen("tcp", addr, config)
	} else {
		ln, err = net.Listen("tcp", addr)
	}
	if err != nil {
		return nil, err
	}
	return ln, err
	//return &http2Listener{ln: ln}, nil
}

type http2Session struct {
	conn       net.Conn
	clientConn *http2.ClientConn
	closeChan  chan struct{}
	pingChan   chan struct{}
}

func newHTTP2Session(conn net.Conn, clientConn *http2.ClientConn, interval time.Duration) *http2Session {
	session := &http2Session{
		conn:       conn,
		clientConn: clientConn,
		closeChan:  make(chan struct{}),
	}
	if interval > 0 {
		session.pingChan = make(chan struct{})
		go session.Ping(interval)
	}
	return session
}

func (s *http2Session) Ping(interval time.Duration) {
	if interval <= 0 {
		return
	}

	defer close(s.pingChan)
	log.Log("[http2] ping is enabled, interval:", interval)

	baseCtx := context.Background()
	t := time.NewTicker(interval)
	retries := PingRetries
	for {
		select {
		case <-t.C:
			if Debug {
				log.Log("[http2] sending ping")
			}
			if !s.clientConn.CanTakeNewRequest() {
				log.Logf("[http2] connection is dead")
				return
			}
			ctx, cancel := context.WithTimeout(baseCtx, PingTimeout)
			if err := s.clientConn.Ping(ctx); err != nil {
				log.Logf("[http2] ping: %s", err)
				if retries > 0 {
					retries--
					log.Log("[http2] retry ping")
					cancel()
					continue
				}

				cancel()
				return
			}

			if Debug {
				log.Log("[http2] ping OK")
			}
			cancel()
			retries = PingRetries

		case <-s.closeChan:
			return
		}
	}
}

func (s *http2Session) Healthy() bool {
	select {
	case <-s.pingChan:
		return false
	default:
	}
	return s.clientConn.CanTakeNewRequest()
}

func (s *http2Session) Close() error {
	select {
	case <-s.closeChan:
	default:
		close(s.closeChan)
	}
	return nil
}

// HTTP2 connection, wrapped up just like a net.Conn
type http2Conn struct {
	r          io.Reader
	w          io.Writer
	remoteAddr net.Addr
	localAddr  net.Addr
}

func (c *http2Conn) Read(b []byte) (n int, err error) {
	return c.r.Read(b)
}

func (c *http2Conn) Write(b []byte) (n int, err error) {
	return c.w.Write(b)
}

func (c *http2Conn) Close() (err error) {
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

// Dummy HTTP2 connection.
type http2DummyConn struct {
	raddr string
	conn  *http2.ClientConn
}

func (c *http2DummyConn) Read(b []byte) (n int, err error) {
	return 0, &net.OpError{Op: "read", Net: "http2", Source: nil, Addr: nil, Err: errors.New("read not supported")}
}

func (c *http2DummyConn) Write(b []byte) (n int, err error) {
	return 0, &net.OpError{Op: "write", Net: "http2", Source: nil, Addr: nil, Err: errors.New("write not supported")}
}

func (c *http2DummyConn) Close() error {
	return nil
}

func (c *http2DummyConn) LocalAddr() net.Addr {
	return nil
}

func (c *http2DummyConn) RemoteAddr() net.Addr {
	return nil
}

func (c *http2DummyConn) SetDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "http2", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

func (c *http2DummyConn) SetReadDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "http2", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

func (c *http2DummyConn) SetWriteDeadline(t time.Time) error {
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
