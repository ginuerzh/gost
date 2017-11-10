// obfs4 connection wrappers

package gost

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"

	"github.com/go-log/log"

	pt "git.torproject.org/pluggable-transports/goptlib.git"
	"git.torproject.org/pluggable-transports/obfs4.git/transports/base"
	"git.torproject.org/pluggable-transports/obfs4.git/transports/obfs4"
)

type obfsHTTPTransporter struct {
	tcpTransporter
}

// ObfsHTTPTransporter creates a Transporter that is used by HTTP obfuscating tunnel client.
func ObfsHTTPTransporter() Transporter {
	return &obfsHTTPTransporter{}
}

func (tr *obfsHTTPTransporter) Handshake(conn net.Conn, options ...HandshakeOption) (net.Conn, error) {
	opts := &HandshakeOptions{}
	for _, option := range options {
		option(opts)
	}
	return &obfsHTTPConn{Conn: conn, host: opts.Host}, nil
}

type obfsHTTPListener struct {
	net.Listener
}

// ObfsHTTPListener creates a Listener for HTTP obfuscating tunnel server.
func ObfsHTTPListener(addr string) (Listener, error) {
	laddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, err
	}
	ln, err := net.ListenTCP("tcp", laddr)
	if err != nil {
		return nil, err
	}
	return &obfsHTTPListener{Listener: tcpKeepAliveListener{ln}}, nil
}

func (l *obfsHTTPListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	return &obfsHTTPConn{Conn: conn, isServer: true}, nil
}

type obfsHTTPConn struct {
	net.Conn
	host           string
	request        *http.Request
	response       *http.Response
	rbuf           []byte
	wbuf           []byte
	isServer       bool
	handshaked     bool
	handshakeMutex sync.Mutex
}

func (c *obfsHTTPConn) Handshake() (err error) {
	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()

	if c.handshaked {
		return nil
	}

	if c.isServer {
		err = c.serverHandshake()
	} else {
		err = c.clientHandshake()
	}
	if err != nil {
		return
	}

	c.handshaked = true
	return nil
}

func (c *obfsHTTPConn) serverHandshake() (err error) {
	br := bufio.NewReader(c.Conn)
	c.request, err = http.ReadRequest(br)
	if err != nil {
		return
	}
	if Debug {
		dump, _ := httputil.DumpRequest(c.request, false)
		log.Logf("[ohttp] %s -> %s\n%s", c.Conn.RemoteAddr(), c.Conn.LocalAddr(), string(dump))
	}

	if br.Buffered() > 0 {
		c.rbuf, err = br.Peek(br.Buffered())
	} else {
		c.rbuf, err = ioutil.ReadAll(c.request.Body)
	}

	if err != nil {
		log.Logf("[ohttp] %s -> %s : %v", c.Conn.RemoteAddr(), c.Conn.LocalAddr(), err)
		return
	}

	b := bytes.Buffer{}
	if c.request.Header.Get("Upgrade") == "websocket" {
		b.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
		b.WriteString("Server: nginx/1.10.0\r\n")
		b.WriteString("Date: " + time.Now().Format(time.RFC1123) + "\r\n")
		b.WriteString("Connection: Upgrade\r\n")
		b.WriteString("Upgrade: websocket\r\n")
		b.WriteString(fmt.Sprintf("Sec-WebSocket-Accept: %s\r\n", computeAcceptKey(c.request.Header.Get("Sec-WebSocket-Key"))))
		b.WriteString("\r\n")
	} else {
		b.WriteString("HTTP/1.1 200 OK\r\n")
		b.WriteString("Server: nginx/1.10.0\r\n")
		b.WriteString("Date: " + time.Now().Format(time.RFC1123) + "\r\n")
		b.WriteString("Content-Type: application/octet-stream\r\n")
		b.WriteString("Connection: keep-alive\r\n")
		b.WriteString("Cache-Control: private, no-cache, no-store, proxy-revalidate, no-transform\r\n")
		b.WriteString("Pragma: no-cache\r\n")
		b.WriteString("\r\n")
	}
	if Debug {
		log.Logf("[ohttp] %s <- %s\n%s", c.Conn.RemoteAddr(), c.Conn.LocalAddr(), b.String())
	}
	_, err = b.WriteTo(c.Conn)
	return
}

func (c *obfsHTTPConn) clientHandshake() (err error) {
	r := c.request
	if r == nil {
		r = &http.Request{
			Method:     http.MethodGet,
			ProtoMajor: 1,
			ProtoMinor: 1,
			URL:        &url.URL{Scheme: "http", Host: c.host},
			Header:     make(http.Header),
		}
		r.Header.Set("Connection", "keep-alive")
		r.Header.Set("Upgrade", "websocket")
		r.Header.Set("User-Agent", DefaultUserAgent)
		if len(c.wbuf) > 0 {
			log.Log("write buf", len(c.wbuf))
			r.Body = ioutil.NopCloser(bytes.NewReader(c.wbuf))
			r.ContentLength = int64(len(c.wbuf))
		}
	}
	if err = r.Write(c.Conn); err != nil {
		return
	}
	if Debug {
		dump, _ := httputil.DumpRequest(r, false)
		log.Logf("[ohttp] %s -> %s\n%s", c.Conn.LocalAddr(), c.Conn.RemoteAddr(), string(dump))
	}
	var resp *http.Response
	resp, err = http.ReadResponse(bufio.NewReader(c.Conn), r)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if Debug {
		dump, _ := httputil.DumpResponse(resp, false)
		log.Logf("[ohttp] %s <- %s\n%s", c.Conn.LocalAddr(), c.Conn.RemoteAddr(), string(dump))
	}
	return nil
}

func (c *obfsHTTPConn) Read(b []byte) (n int, err error) {
	if err = c.Handshake(); err != nil {
		return
	}
	if len(c.rbuf) > 0 {
		n = copy(b, c.rbuf)
		c.rbuf = c.rbuf[n:]
		return
	}
	return c.Conn.Read(b)
}

func (c *obfsHTTPConn) Write(b []byte) (n int, err error) {
	handshaked := c.handshaked
	c.wbuf = b
	if err = c.Handshake(); err != nil {
		return
	}
	if !handshaked {
		n = len(c.wbuf)
		return
	}
	return c.Conn.Write(b)
}

type obfs4Context struct {
	cf    base.ClientFactory
	cargs interface{} // type obfs4ClientArgs
	sf    base.ServerFactory
	sargs *pt.Args
}

var obfs4Map = make(map[string]obfs4Context)

// Obfs4Init initializes the obfs client or server based on isServeNode
func Obfs4Init(node Node, isServeNode bool) error {
	if _, ok := obfs4Map[node.Addr]; ok {
		return fmt.Errorf("obfs4 context already inited")
	}

	t := new(obfs4.Transport)

	stateDir := node.Values.Get("state-dir")
	if stateDir == "" {
		stateDir = "."
	}

	ptArgs := pt.Args(node.Values)

	if !isServeNode {
		cf, err := t.ClientFactory(stateDir)
		if err != nil {
			return err
		}

		cargs, err := cf.ParseArgs(&ptArgs)
		if err != nil {
			return err
		}

		obfs4Map[node.Addr] = obfs4Context{cf: cf, cargs: cargs}
	} else {
		sf, err := t.ServerFactory(stateDir, &ptArgs)
		if err != nil {
			return err
		}

		sargs := sf.Args()

		obfs4Map[node.Addr] = obfs4Context{sf: sf, sargs: sargs}

		log.Log("[obfs4] server inited:", obfs4ServerURL(node))
	}

	return nil
}

func obfs4GetContext(addr string) (obfs4Context, error) {
	ctx, ok := obfs4Map[addr]
	if !ok {
		return obfs4Context{}, fmt.Errorf("obfs4 context not inited")
	}
	return ctx, nil
}

func obfs4ServerURL(node Node) string {
	ctx, err := obfs4GetContext(node.Addr)
	if err != nil {
		return ""
	}

	values := (*url.Values)(ctx.sargs)
	query := values.Encode()
	return fmt.Sprintf(
		"%s+%s://%s/?%s", //obfs4-cert=%s&iat-mode=%s",
		node.Protocol,
		node.Transport,
		node.Addr,
		query,
	)
}

func obfs4ClientConn(addr string, conn net.Conn) (net.Conn, error) {
	ctx, err := obfs4GetContext(addr)
	if err != nil {
		return nil, err
	}

	pseudoDial := func(a, b string) (net.Conn, error) { return conn, nil }
	return ctx.cf.Dial("tcp", "", pseudoDial, ctx.cargs)
}

func obfs4ServerConn(addr string, conn net.Conn) (net.Conn, error) {
	ctx, err := obfs4GetContext(addr)
	if err != nil {
		return nil, err
	}

	return ctx.sf.WrapConn(conn)
}

type obfs4Transporter struct {
	tcpTransporter
}

// Obfs4Transporter creates a Transporter that is used by obfs4 client.
func Obfs4Transporter() Transporter {
	return &obfs4Transporter{}
}

func (tr *obfs4Transporter) Handshake(conn net.Conn, options ...HandshakeOption) (net.Conn, error) {
	opts := &HandshakeOptions{}
	for _, option := range options {
		option(opts)
	}
	return obfs4ClientConn(opts.Addr, conn)
}

type obfs4Listener struct {
	addr string
	net.Listener
}

// Obfs4Listener creates a Listener for obfs4 server.
func Obfs4Listener(addr string) (Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	l := &obfs4Listener{
		addr:     addr,
		Listener: ln,
	}
	return l, nil
}

func (l *obfs4Listener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	cc, err := obfs4ServerConn(l.addr, conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return cc, nil
}
