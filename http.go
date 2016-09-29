package main

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"github.com/golang/glog"
	"golang.org/x/net/http2"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"
)

var (
	http2Client *http.Client
)

func handleHttpRequest(req *http.Request, conn net.Conn, arg Args) {
	glog.V(LINFO).Infof("[http] %s %s - %s %s", req.Method, conn.RemoteAddr(), req.Host, req.Proto)

	if glog.V(LDEBUG) {
		dump, _ := httputil.DumpRequest(req, false)
		glog.Infoln(string(dump))
	}

	var username, password string
	if arg.User != nil {
		username = arg.User.Username()
		password, _ = arg.User.Password()
	}

	u, p, _ := basicAuth(req.Header.Get("Proxy-Authorization"))
	req.Header.Del("Proxy-Authorization")
	if (username != "" && u != username) || (password != "" && p != password) {
		resp := "HTTP/1.1 407 Proxy Authentication Required\r\n" +
			"Proxy-Authenticate: Basic realm=\"gost\"\r\n" +
			"Proxy-Agent: gost/" + Version + "\r\n\r\n"

		if _, err := conn.Write([]byte(resp)); err != nil {
			glog.V(LWARNING).Infof("[http] %s <- %s : %s", conn.RemoteAddr(), req.Host, err)
		}
		glog.V(LDEBUG).Infof("[http] %s <- %s\n%s", conn.RemoteAddr(), req.Host, resp)

		glog.V(LWARNING).Infof("[http] %s <- %s : proxy authentication required", conn.RemoteAddr(), req.Host)
		return
	}

	if len(forwardArgs) > 0 {
		last := forwardArgs[len(forwardArgs)-1]
		if last.Protocol == "http" || last.Protocol == "" {
			forwardHttpRequest(req, conn, arg)
			return
		}
	}

	c, err := connect(req.Host, "http")
	if err != nil {
		glog.V(LWARNING).Infof("[http] %s -> %s : %s", conn.RemoteAddr(), req.Host, err)

		b := []byte("HTTP/1.1 503 Service unavailable\r\n" +
			"Proxy-Agent: gost/" + Version + "\r\n\r\n")
		glog.V(LDEBUG).Infof("[http] %s <- %s\n%s", conn.RemoteAddr(), req.Host, string(b))
		conn.Write(b)
		return
	}
	defer c.Close()

	if req.Method == http.MethodConnect {
		b := []byte("HTTP/1.1 200 Connection established\r\n" +
			"Proxy-Agent: gost/" + Version + "\r\n\r\n")
		glog.V(LDEBUG).Infof("[http] %s <- %s\n%s", conn.RemoteAddr(), req.Host, string(b))
		conn.Write(b)
	} else {
		req.Header.Del("Proxy-Connection")
		req.Header.Set("Connection", "Keep-Alive")

		if err = req.Write(c); err != nil {
			glog.V(LWARNING).Infof("[http] %s -> %s : %s", conn.RemoteAddr(), req.Host, err)
			return
		}
	}

	glog.V(LINFO).Infof("[http] %s <-> %s", conn.RemoteAddr(), req.Host)
	Transport(conn, c)
	glog.V(LINFO).Infof("[http] %s >-< %s", conn.RemoteAddr(), req.Host)
}

func forwardHttpRequest(req *http.Request, conn net.Conn, arg Args) {
	last := forwardArgs[len(forwardArgs)-1]
	c, _, err := forwardChain(forwardArgs...)
	if err != nil {
		glog.V(LWARNING).Infof("[http] %s -> %s : %s", conn.RemoteAddr(), last.Addr, err)

		b := []byte("HTTP/1.1 503 Service unavailable\r\n" +
			"Proxy-Agent: gost/" + Version + "\r\n\r\n")
		glog.V(LDEBUG).Infof("[http] %s <- %s\n%s", conn.RemoteAddr(), last.Addr, string(b))
		conn.Write(b)
		return
	}
	defer c.Close()

	if last.User != nil {
		req.Header.Set("Proxy-Authorization",
			"Basic "+base64.StdEncoding.EncodeToString([]byte(last.User.String())))
	}

	if err = req.Write(c); err != nil {
		glog.V(LWARNING).Infof("[http] %s -> %s : %s", conn.RemoteAddr(), req.Host, err)
		return
	}
	glog.V(LINFO).Infof("[http] %s <-> %s", conn.RemoteAddr(), req.Host)
	Transport(conn, c)
	glog.V(LINFO).Infof("[http] %s >-< %s", conn.RemoteAddr(), req.Host)
	return
}

type Http2ClientConn struct {
	r          io.Reader
	w          io.Writer
	localAddr  net.Addr
	remoteAddr net.Addr
}

func (c *Http2ClientConn) Read(b []byte) (n int, err error) {
	return c.r.Read(b)
}

func (c *Http2ClientConn) Write(b []byte) (n int, err error) {
	return c.w.Write(b)
}

func (c *Http2ClientConn) Close() error {
	if rc, ok := c.r.(io.ReadCloser); ok {
		return rc.Close()
	}
	return nil
}

func (c *Http2ClientConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *Http2ClientConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *Http2ClientConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *Http2ClientConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *Http2ClientConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// init http2 client with target http2 proxy server addr, and forward chain chain
func initHttp2Client(host string, chain ...Args) {
	tr := http2.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
			// replace the default dialer with our forward chain.
			conn, err := connectWithChain(host, chain...)
			if err != nil {
				return conn, err
			}
			return tls.Client(conn, cfg), nil
		},
	}
	http2Client = &http.Client{Transport: &tr}
}

func handlerHttp2Request(w http.ResponseWriter, req *http.Request) {
	target := req.Header.Get("gost-target-addr")
	if target == "" {
		target = req.Host
	}

	glog.V(LINFO).Infof("[http2] %s %s - %s %s", req.Method, req.RemoteAddr, target, req.Proto)
	if glog.V(LDEBUG) {
		dump, _ := httputil.DumpRequest(req, false)
		glog.Infoln(string(dump))
	}

	c, err := connect(target, req.Header.Get("gost-prot"))
	if err != nil {
		glog.V(LWARNING).Infof("[http2] %s -> %s : %s", req.RemoteAddr, target, err)
		w.Header().Set("Proxy-Agent", "gost/"+Version)
		w.WriteHeader(http.StatusServiceUnavailable)
		if fw, ok := w.(http.Flusher); ok {
			fw.Flush()
		}
		return
	}
	defer c.Close()

	glog.V(LINFO).Infof("[http2] %s <-> %s", req.RemoteAddr, target)
	errc := make(chan error, 2)

	if req.Method == http.MethodConnect {
		w.Header().Set("Proxy-Agent", "gost/"+Version)
		w.WriteHeader(http.StatusOK)
		if fw, ok := w.(http.Flusher); ok {
			fw.Flush()
		}

		// compatible with HTTP 1.x
		if hj, ok := w.(http.Hijacker); ok && req.ProtoMajor == 1 {
			// we take over the underly connection
			conn, _, err := hj.Hijack()
			if err != nil {
				glog.V(LWARNING).Infof("[http2] %s -> %s : %s", req.RemoteAddr, target, err)
				return
			}
			defer conn.Close()

			go Pipe(conn, c, errc)
			go Pipe(c, conn, errc)
		} else {
			go Pipe(req.Body, c, errc)
			go Pipe(c, flushWriter{w}, errc)
		}

		select {
		case <-errc:
			// glog.V(LWARNING).Infoln("exit", err)
		}
	} else {
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
		if fw, ok := w.(http.Flusher); ok {
			fw.Flush()
		}
		if _, err := io.Copy(flushWriter{w}, resp.Body); err != nil {
			glog.V(LWARNING).Infof("[http2] %s <- %s : %s", req.RemoteAddr, target, err)
		}
	}

	glog.V(LINFO).Infof("[http2] %s >-< %s", req.RemoteAddr, target)
}

//func processSocks5OverHttp2()

func handleHttp2Transport(w http.ResponseWriter, req *http.Request) {
	glog.V(LINFO).Infof("[http2] %s - %s", req.RemoteAddr, req.Host)
	if glog.V(LDEBUG) {
		dump, _ := httputil.DumpRequest(req, false)
		glog.Infoln(string(dump))
	}
}

func basicAuth(authInfo string) (username, password string, ok bool) {
	if authInfo == "" {
		return
	}

	if !strings.HasPrefix(authInfo, "Basic ") {
		return
	}
	c, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(authInfo, "Basic "))
	if err != nil {
		return
	}
	cs := string(c)
	s := strings.IndexByte(cs, ':')
	if s < 0 {
		return
	}

	return cs[:s], cs[s+1:], true
}

type flushWriter struct {
	w io.Writer
}

func (fw flushWriter) Write(p []byte) (n int, err error) {
	n, err = fw.w.Write(p)
	if err != nil {
		glog.V(LWARNING).Infoln("flush writer:", err)
	}
	if f, ok := fw.w.(http.Flusher); ok {
		f.Flush()
	}
	return
}
