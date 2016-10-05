package gost

import (
	"bufio"
	"crypto/tls"
	"github.com/golang/glog"
	"golang.org/x/net/http2"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	//"encoding/base64"
	//"strings"
	"errors"
	"time"
)

type HttpServer struct {
	conn net.Conn
	Base *ProxyServer
}

func NewHttpServer(conn net.Conn, base *ProxyServer) *HttpServer {
	return &HttpServer{
		conn: conn,
		Base: base,
	}
}

// Default HTTP server handler
func (s *HttpServer) HandleRequest(req *http.Request) {
	glog.V(LINFO).Infof("[http] %s %s - %s %s", req.Method, s.conn.RemoteAddr(), req.Host, req.Proto)

	if glog.V(LDEBUG) {
		dump, _ := httputil.DumpRequest(req, false)
		glog.Infoln(string(dump))
	}

	if req.Method == "PRI" && req.ProtoMajor == 2 {
		glog.V(LWARNING).Infof("[http] %s <- %s : Not an HTTP2 server", s.conn.RemoteAddr(), req.Host)
		resp := "HTTP/1.1 400 Bad Request\r\n" +
			"Proxy-Agent: gost/" + Version + "\r\n\r\n"
		s.conn.Write([]byte(resp))
		return
	}

	var username, password string
	if s.Base.Node.User != nil {
		username = s.Base.Node.User.Username()
		password, _ = s.Base.Node.User.Password()
	}

	u, p, _ := basicProxyAuth(req.Header.Get("Proxy-Authorization"))
	req.Header.Del("Proxy-Authorization")
	if (username != "" && u != username) || (password != "" && p != password) {
		glog.V(LWARNING).Infof("[http] %s <- %s : proxy authentication required", s.conn.RemoteAddr(), req.Host)
		resp := "HTTP/1.1 407 Proxy Authentication Required\r\n" +
			"Proxy-Authenticate: Basic realm=\"gost\"\r\n" +
			"Proxy-Agent: gost/" + Version + "\r\n\r\n"
		s.conn.Write([]byte(resp))
		return
	}

	// TODO: forward http request
	/*
		if len(forwardArgs) > 0 {
			last := forwardArgs[len(forwardArgs)-1]
			if last.Protocol == "http" || last.Protocol == "" {
				forwardHttpRequest(req, conn, arg)
				return
			}
		}
	*/

	c, err := s.Base.Chain.Dial(req.Host)
	if err != nil {
		glog.V(LWARNING).Infof("[http] %s -> %s : %s", s.conn.RemoteAddr(), req.Host, err)

		b := []byte("HTTP/1.1 503 Service unavailable\r\n" +
			"Proxy-Agent: gost/" + Version + "\r\n\r\n")
		glog.V(LDEBUG).Infof("[http] %s <- %s\n%s", s.conn.RemoteAddr(), req.Host, string(b))
		s.conn.Write(b)
		return
	}
	defer c.Close()

	if req.Method == http.MethodConnect {
		b := []byte("HTTP/1.1 200 Connection established\r\n" +
			"Proxy-Agent: gost/" + Version + "\r\n\r\n")
		glog.V(LDEBUG).Infof("[http] %s <- %s\n%s", s.conn.RemoteAddr(), req.Host, string(b))
		s.conn.Write(b)
	} else {
		req.Header.Del("Proxy-Connection")
		req.Header.Set("Connection", "Keep-Alive")

		if err = req.Write(c); err != nil {
			glog.V(LWARNING).Infof("[http] %s -> %s : %s", s.conn.RemoteAddr(), req.Host, err)
			return
		}
	}

	glog.V(LINFO).Infof("[http] %s <-> %s", s.conn.RemoteAddr(), req.Host)
	s.Base.transport(s.conn, c)
	glog.V(LINFO).Infof("[http] %s >-< %s", s.conn.RemoteAddr(), req.Host)
}

type Http2Server struct {
	Base      *ProxyServer
	Handler   http.Handler
	TLSConfig *tls.Config
}

func NewHttp2Server(base *ProxyServer) *Http2Server {
	return &Http2Server{Base: base}
}

func (s *Http2Server) ListenAndServeTLS(config *tls.Config) error {
	srv := http.Server{
		Addr:      s.Base.Node.Addr,
		Handler:   s.Handler,
		TLSConfig: config,
	}
	if srv.Handler == nil {
		srv.Handler = http.HandlerFunc(s.HandleRequest)
	}
	http2.ConfigureServer(&srv, nil)
	return srv.ListenAndServeTLS("", "")
}

// Default HTTP2 server handler
func (s *Http2Server) HandleRequest(w http.ResponseWriter, req *http.Request) {
	target := req.Header.Get("Gost-Target")
	if target == "" {
		target = req.Host
	}
	glog.V(LINFO).Infof("[http2] %s %s - %s %s", req.Method, req.RemoteAddr, target, req.Proto)
	if glog.V(LDEBUG) {
		dump, _ := httputil.DumpRequest(req, false)
		glog.Infoln(string(dump))
	}

	w.Header().Set("Proxy-Agent", "gost/"+Version)

	// HTTP2 as transport
	if req.Header.Get("Proxy-Switch") == "gost" {
		conn, err := s.Upgrade(w, req)
		if err != nil {
			glog.V(LINFO).Infof("[http2] %s -> %s : %s", req.RemoteAddr, target, err)
			return
		}
		glog.V(LINFO).Infof("[http2] %s - %s : switch to HTTP2 transport mode OK", req.RemoteAddr, target)
		s.Base.handleConn(conn)
		return
	}

	var username, password string
	if s.Base.Node.User != nil {
		username = s.Base.Node.User.Username()
		password, _ = s.Base.Node.User.Password()
	}

	u, p, _ := basicProxyAuth(req.Header.Get("Proxy-Authorization"))
	req.Header.Del("Proxy-Authorization")
	if (username != "" && u != username) || (password != "" && p != password) {
		glog.V(LWARNING).Infof("[http2] %s <- %s : proxy authentication required", req.RemoteAddr, target)
		w.WriteHeader(http.StatusProxyAuthRequired)
		return
	}

	c, err := s.Base.Chain.Dial(target)
	if err != nil {
		glog.V(LWARNING).Infof("[http2] %s -> %s : %s", req.RemoteAddr, target, err)
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	defer c.Close()

	glog.V(LINFO).Infof("[http2] %s <-> %s", req.RemoteAddr, target)

	if req.Method == http.MethodConnect {
		w.WriteHeader(http.StatusOK)
		if fw, ok := w.(http.Flusher); ok {
			fw.Flush()
		}

		// compatible with HTTP1.x
		if hj, ok := w.(http.Hijacker); ok && req.ProtoMajor == 1 {
			// we take over the underly connection
			conn, _, err := hj.Hijack()
			if err != nil {
				glog.V(LWARNING).Infof("[http2] %s -> %s : %s", req.RemoteAddr, target, err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			defer conn.Close()

			s.Base.transport(conn, c)
			return
		}

		errc := make(chan error, 2)

		go func() {
			_, err := io.Copy(c, req.Body)
			errc <- err
		}()
		go func() {
			_, err := io.Copy(flushWriter{w}, c)
			errc <- err
		}()

		select {
		case <-errc:
			// glog.V(LWARNING).Infoln("exit", err)
		}
		glog.V(LINFO).Infof("[http2] %s >-< %s", req.RemoteAddr, target)
		return
	}

	req.Header.Set("Connection", "Keep-Alive")
	if err = req.Write(c); err != nil {
		glog.V(LWARNING).Infof("[http2] %s -> %s : %s", req.RemoteAddr, target, err)
		return
	}

	resp, err := http.ReadResponse(bufio.NewReader(c), req)
	if err != nil {
		glog.V(LWARNING).Infoln(err)
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
		glog.V(LWARNING).Infof("[http2] %s <- %s : %s", req.RemoteAddr, target, err)
	}

	glog.V(LINFO).Infof("[http2] %s >-< %s", req.RemoteAddr, target)
}

// Upgrade upgrade an HTTP2 request to a bidirectional connection that preparing for tunneling other protocol, just like a websocket connection.
func (s *Http2Server) Upgrade(w http.ResponseWriter, r *http.Request) (net.Conn, error) {
	w.Header().Set("Proxy-Agent", "gost/"+Version)

	if r.Method != http.MethodConnect {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return nil, errors.New("Method not allowed")
	}

	w.WriteHeader(http.StatusOK)

	if fw, ok := w.(http.Flusher); ok {
		fw.Flush()
	}

	conn := &http2Conn{r: r.Body, w: flushWriter{w}}
	conn.remoteAddr, _ = net.ResolveTCPAddr("tcp", r.RemoteAddr)
	conn.localAddr, _ = net.ResolveTCPAddr("tcp", r.Host)
	return conn, nil
}

// HTTP2 client connection, wrapped up just like a net.Conn
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

func (c *http2Conn) Close() error {
	if rc, ok := c.r.(io.ReadCloser); ok {
		return rc.Close()
	}
	return nil
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

type flushWriter struct {
	w io.Writer
}

func (fw flushWriter) Write(p []byte) (n int, err error) {
	n, err = fw.w.Write(p)
	if err != nil {
		glog.V(LWARNING).Infoln("flush writer:", err)
		return
	}
	if f, ok := fw.w.(http.Flusher); ok {
		f.Flush()
	}
	return
}
