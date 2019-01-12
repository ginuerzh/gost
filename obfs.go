// obfs4 connection wrappers

package gost

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
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
	rbuf           bytes.Buffer
	wbuf           bytes.Buffer
	isServer       bool
	headerDrained  bool
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
	r, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if Debug {
		dump, _ := httputil.DumpRequest(r, false)
		log.Logf("[ohttp] %s -> %s\n%s", c.RemoteAddr(), c.LocalAddr(), string(dump))
	}

	if r.ContentLength > 0 {
		_, err = io.Copy(&c.rbuf, r.Body)
	} else {
		var b []byte
		b, err = br.Peek(br.Buffered())
		if len(b) > 0 {
			_, err = c.rbuf.Write(b)
		}
	}
	if err != nil {
		log.Logf("[ohttp] %s -> %s : %v", c.Conn.RemoteAddr(), c.Conn.LocalAddr(), err)
		return
	}

	b := bytes.Buffer{}

	if r.Method != http.MethodGet || r.Header.Get("Upgrade") != "websocket" {
		b.WriteString("HTTP/1.1 503 Service Unavailable\r\n")
		b.WriteString("Content-Length: 0\r\n")
		b.WriteString("Date: " + time.Now().Format(time.RFC1123) + "\r\n")
		b.WriteString("\r\n")

		if Debug {
			log.Logf("[ohttp] %s <- %s\n%s", c.RemoteAddr(), c.LocalAddr(), b.String())
		}

		b.WriteTo(c.Conn)
		return errors.New("bad request")
	}

	b.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
	b.WriteString("Server: nginx/1.10.0\r\n")
	b.WriteString("Date: " + time.Now().Format(time.RFC1123) + "\r\n")
	b.WriteString("Connection: Upgrade\r\n")
	b.WriteString("Upgrade: websocket\r\n")
	b.WriteString(fmt.Sprintf("Sec-WebSocket-Accept: %s\r\n", computeAcceptKey(r.Header.Get("Sec-WebSocket-Key"))))
	b.WriteString("\r\n")

	if Debug {
		log.Logf("[ohttp] %s <- %s\n%s", c.RemoteAddr(), c.LocalAddr(), b.String())
	}

	if c.rbuf.Len() > 0 {
		c.wbuf = b // cache the response header if there are extra data in the request body.
		return
	}

	_, err = b.WriteTo(c.Conn)
	return
}

func (c *obfsHTTPConn) clientHandshake() (err error) {
	r := &http.Request{
		Method:     http.MethodGet,
		ProtoMajor: 1,
		ProtoMinor: 1,
		URL:        &url.URL{Scheme: "http", Host: c.host},
		Header:     make(http.Header),
	}
	r.Header.Set("User-Agent", DefaultUserAgent)
	r.Header.Set("Connection", "Upgrade")
	r.Header.Set("Upgrade", "websocket")
	key, _ := generateChallengeKey()
	r.Header.Set("Sec-WebSocket-Key", key)

	// cache the request header
	if err = r.Write(&c.wbuf); err != nil {
		return
	}

	if Debug {
		dump, _ := httputil.DumpRequest(r, false)
		log.Logf("[ohttp] %s -> %s\n%s", c.LocalAddr(), c.RemoteAddr(), string(dump))
	}

	return nil
}

func (c *obfsHTTPConn) Read(b []byte) (n int, err error) {
	if err = c.Handshake(); err != nil {
		return
	}

	if !c.isServer {
		if err = c.drainHeader(); err != nil {
			return
		}
	}

	if c.rbuf.Len() > 0 {
		return c.rbuf.Read(b)
	}
	return c.Conn.Read(b)
}

func (c *obfsHTTPConn) drainHeader() (err error) {
	if c.headerDrained {
		return
	}
	c.headerDrained = true

	br := bufio.NewReader(c.Conn)
	// drain and discard the response header
	var line string
	var buf bytes.Buffer
	for {
		line, err = br.ReadString('\n')
		if err != nil {
			return
		}
		buf.WriteString(line)
		if line == "\r\n" {
			break
		}
	}

	if Debug {
		log.Logf("[ohttp] %s <- %s\n%s", c.LocalAddr(), c.RemoteAddr(), buf.String())
	}
	// cache the extra data for next read.
	var b []byte
	b, err = br.Peek(br.Buffered())
	if len(b) > 0 {
		_, err = c.rbuf.Write(b)
	}
	return
}

func (c *obfsHTTPConn) Write(b []byte) (n int, err error) {
	if err = c.Handshake(); err != nil {
		return
	}
	if c.wbuf.Len() > 0 {
		c.wbuf.Write(b) // append the data to the cached header
		_, err = c.wbuf.WriteTo(c.Conn)
		n = len(b) // exclude the header length
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

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = HandshakeTimeout
	}
	conn.SetDeadline(time.Now().Add(timeout))
	defer conn.SetDeadline(time.Time{})

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
		Listener: tcpKeepAliveListener{ln.(*net.TCPListener)},
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
