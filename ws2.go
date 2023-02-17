package gost

import (
	"crypto/tls"

	"net"
	"net/http"
	"net/http/httputil"
	"time"

	"net/url"

	"github.com/go-log/log"
	"github.com/gorilla/websocket"
)

const (
	defaultWSPath2 = "/ws"
)

// // WSOptions describes the options for websocket.
type WSOptions2 struct {
	ReadBufferSize    int
	WriteBufferSize   int
	HandshakeTimeout  time.Duration
	EnableCompression bool
	UserAgent         string
	Path              string
}

type wsTransporter2 struct {
	tcpTransporter
	options *WSOptions
}

// WSTransporter creates a Transporter that is used by websocket proxy client.
func WSTransporter2(opts *WSOptions) Transporter {
	return &wsTransporter{
		options: opts,
	}
}

func (tr *wsTransporter2) Handshake(conn net.Conn, options ...HandshakeOption) (net.Conn, error) {
	opts := &HandshakeOptions{}
	for _, option := range options {
		option(opts)
	}
	wsOptions := tr.options
	if opts.WSOptions != nil {
		wsOptions = opts.WSOptions
	}
	if wsOptions == nil {
		wsOptions = &WSOptions{}
	}

	path := wsOptions.Path
	if path == "" {
		path = defaultWSPath
	}
	url := url.URL{Scheme: "ws", Host: opts.Host, Path: path}
	return websocketClientConn2(url.String(), conn, nil, wsOptions)
}

type wsListener2 struct {
	addr     net.Addr
	upgrader *websocket.Upgrader
	srv      *http.Server
	connChan chan net.Conn
	errChan  chan error
}

// WSListener creates a Listener for websocket proxy server.
func WSListener2(ln net.Listener, options *WSOptions) (Listener, error) {

	if options == nil {
		options = &WSOptions{}
	}
	l := &wsListener2{
		upgrader: &websocket.Upgrader{
			ReadBufferSize:    options.ReadBufferSize,
			WriteBufferSize:   options.WriteBufferSize,
			CheckOrigin:       func(r *http.Request) bool { return true },
			EnableCompression: options.EnableCompression,
		},
		connChan: make(chan net.Conn, 1024),
		errChan:  make(chan error, 1),
	}

	path := options.Path
	if path == "" {
		path = defaultWSPath2
	}
	mux := http.NewServeMux()
	mux.Handle(path, http.HandlerFunc(l.upgrade))
	l.srv = &http.Server{
		Addr:              ":18000",
		Handler:           mux,
		ReadHeaderTimeout: 30 * time.Second,
	}

	l.addr = ln.Addr()

	go func() {
		err := l.srv.Serve(ln)
		if err != nil {
			l.errChan <- err
		}
		close(l.errChan)
	}()
	select {
	case err := <-l.errChan:
		return nil, err
	default:
	}

	return l, nil
}

func (l *wsListener2) upgrade(w http.ResponseWriter, r *http.Request) {
	log.Logf("[ws] %s -> %s", r.RemoteAddr, l.addr)
	if Debug {
		dump, _ := httputil.DumpRequest(r, false)
		log.Log(string(dump))
	}
	conn, err := l.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Logf("[ws] %s - %s : %s", r.RemoteAddr, l.addr, err)
		return
	}
	select {
	case l.connChan <- websocketServerConn2(conn):
	default:
		conn.Close()
		log.Logf("[ws] %s - %s: connection queue is full", r.RemoteAddr, l.addr)
	}
}

func (l *wsListener2) Accept() (conn net.Conn, err error) {
	select {
	case conn = <-l.connChan:
	case err = <-l.errChan:
	}
	return
}

func (l *wsListener2) Close() error {
	return l.srv.Close()
}

func (l *wsListener2) Addr() net.Addr {
	return l.addr
}

// TODO: due to the concurrency control in the websocket.Conn,
// a data race may be met when using with multiplexing.
// See: https://godoc.org/gopkg.in/gorilla/websocket.v1#hdr-Concurrency
type websocketConn2 struct {
	conn *websocket.Conn
	rb   []byte
}

func websocketClientConn2(url string, conn net.Conn, tlsConfig *tls.Config, options *WSOptions) (net.Conn, error) {
	if options == nil {
		options = &WSOptions{}
	}

	timeout := options.HandshakeTimeout
	if timeout <= 0 {
		timeout = HandshakeTimeout
	}

	dialer := websocket.Dialer{
		ReadBufferSize:    options.ReadBufferSize,
		WriteBufferSize:   options.WriteBufferSize,
		TLSClientConfig:   tlsConfig,
		HandshakeTimeout:  timeout,
		EnableCompression: options.EnableCompression,
		NetDial: func(net, addr string) (net.Conn, error) {
			return conn, nil
		},
	}
	header := http.Header{}
	header.Set("User-Agent", DefaultUserAgent)
	if options.UserAgent != "" {
		header.Set("User-Agent", options.UserAgent)
	}
	c, resp, err := dialer.Dial(url, header)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()
	return &websocketConn{conn: c}, nil
}

func websocketServerConn2(conn *websocket.Conn) net.Conn {
	// conn.EnableWriteCompression(true)
	return &websocketConn{
		conn: conn,
	}
}

func (c *websocketConn2) Read(b []byte) (n int, err error) {
	if len(c.rb) == 0 {
		_, c.rb, err = c.conn.ReadMessage()
	}
	n = copy(b, c.rb)
	c.rb = c.rb[n:]
	return
}

func (c *websocketConn2) Write(b []byte) (n int, err error) {
	err = c.conn.WriteMessage(websocket.BinaryMessage, b)
	n = len(b)
	return
}

func (c *websocketConn2) Close() error {
	return c.conn.Close()
}

func (c *websocketConn2) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *websocketConn2) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *websocketConn2) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}
func (c *websocketConn2) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *websocketConn2) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}
