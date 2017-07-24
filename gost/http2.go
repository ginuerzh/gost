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
		return nil, errors.New("conn must be a conn wrapper")
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
	conns        map[string]*http2.ClientConn
	connMutex    sync.Mutex
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
		conns:        make(map[string]*http2.ClientConn),
	}
}

func (tr *http2Transporter) Dial(addr string) (net.Conn, error) {
	tr.connMutex.Lock()
	conn, ok := tr.conns[addr]

	if !ok {
		cc, err := tr.chain.Dial(addr)
		if err != nil {
			tr.connMutex.Unlock()
			return nil, err
		}

		if tr.tlsConfig != nil {
			tc := tls.Client(cc, tr.tlsConfig)
			if err := tc.Handshake(); err != nil {
				tr.connMutex.Unlock()
				return nil, err
			}
			cc = tc
		}
		conn, err = tr.tr.NewClientConn(cc)
		if err != nil {
			tr.connMutex.Unlock()
			return nil, err
		}
		tr.conns[addr] = conn
		go tr.ping(tr.pingInterval, addr, conn)
	}
	tr.connMutex.Unlock()

	if !conn.CanTakeNewRequest() {
		tr.connMutex.Lock()
		delete(tr.conns, addr) // TODO: we could re-connect to the addr automatically.
		tr.connMutex.Unlock()
		return nil, errors.New("connection is dead")
	}

	return &http2DummyConn{
		raddr: addr,
		conn:  conn,
	}, nil
}

func (tr *http2Transporter) ping(interval time.Duration, addr string, conn *http2.ClientConn) {
	if interval <= 0 {
		return
	}
	log.Log("[http2] ping is enabled, interval:", interval)

	baseCtx := context.Background()
	t := time.NewTicker(interval)
	retries := PingRetries
	for {
		select {
		case <-t.C:
			if !conn.CanTakeNewRequest() {
				return
			}
			ctx, cancel := context.WithTimeout(baseCtx, PingTimeout)
			if err := conn.Ping(ctx); err != nil {
				log.Logf("[http2] ping: %s", err)
				if retries > 0 {
					retries--
					log.Log("[http2] retry ping")
					cancel()
					continue
				}

				// connection is dead, remove it.
				tr.connMutex.Lock()
				delete(tr.conns, addr)
				tr.connMutex.Unlock()

				cancel()
				return
			}

			cancel()
			retries = PingRetries
		}
	}
}

func (tr *http2Transporter) Handshake(conn net.Conn) (net.Conn, error) {
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
		server: new(http2.Server),
		options: &HandlerOptions{
			Chain: new(Chain),
		},
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
