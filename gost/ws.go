package gost

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httputil"
	"time"

	"net/url"

	"github.com/go-log/log"
	"gopkg.in/gorilla/websocket.v1"
)

// WSOptions describes the options for websocket.
type WSOptions struct {
	ReadBufferSize    int
	WriteBufferSize   int
	HandshakeTimeout  time.Duration
	EnableCompression bool
	TLSConfig         *tls.Config
}

type websocketConn struct {
	conn *websocket.Conn
	rb   []byte
}

func websocketClientConn(url string, conn net.Conn, tlsConfig *tls.Config, options *WSOptions) (net.Conn, error) {
	if options == nil {
		options = &WSOptions{}
	}
	dialer := websocket.Dialer{
		ReadBufferSize:    options.ReadBufferSize,
		WriteBufferSize:   options.WriteBufferSize,
		TLSClientConfig:   tlsConfig,
		HandshakeTimeout:  options.HandshakeTimeout,
		EnableCompression: options.EnableCompression,
		NetDial: func(net, addr string) (net.Conn, error) {
			return conn, nil
		},
	}
	c, resp, err := dialer.Dial(url, nil)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()
	return &websocketConn{conn: c}, nil
}

func websocketServerConn(conn *websocket.Conn) net.Conn {
	// conn.EnableWriteCompression(true)
	return &websocketConn{
		conn: conn,
	}
}

func (c *websocketConn) Read(b []byte) (n int, err error) {
	if len(c.rb) == 0 {
		_, c.rb, err = c.conn.ReadMessage()
	}
	n = copy(b, c.rb)
	c.rb = c.rb[n:]
	return
}

func (c *websocketConn) Write(b []byte) (n int, err error) {
	err = c.conn.WriteMessage(websocket.BinaryMessage, b)
	n = len(b)
	return
}

func (c *websocketConn) Close() error {
	return c.conn.Close()
}

func (c *websocketConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *websocketConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *websocketConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}
func (c *websocketConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *websocketConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

type wsTransporter struct {
	options *WSOptions
}

// WSTransporter creates a Transporter that is used by websocket proxy client.
func WSTransporter(opts *WSOptions) Transporter {
	return &wsTransporter{
		options: opts,
	}
}

func (tr *wsTransporter) Dial(addr string, options ...DialOption) (net.Conn, error) {
	return net.Dial("tcp", addr)
}

func (tr *wsTransporter) Handshake(conn net.Conn, options ...HandshakeOption) (net.Conn, error) {
	opts := &HandshakeOptions{}
	for _, option := range options {
		option(opts)
	}
	wsOptions := tr.options
	if opts.WSOptions != nil {
		wsOptions = opts.WSOptions
	}
	url := url.URL{Scheme: "ws", Host: opts.Addr, Path: "/ws"}
	return websocketClientConn(url.String(), conn, nil, wsOptions)
}

func (tr *wsTransporter) Multiplex() bool {
	return false
}

type wssTransporter struct {
	options *WSOptions
}

// WSSTransporter creates a Transporter that is used by websocket secure proxy client.
func WSSTransporter(opts *WSOptions) Transporter {
	return &wssTransporter{
		options: opts,
	}
}

func (tr *wssTransporter) Dial(addr string, options ...DialOption) (net.Conn, error) {
	return net.Dial("tcp", addr)
}

func (tr *wssTransporter) Handshake(conn net.Conn, options ...HandshakeOption) (net.Conn, error) {
	opts := &HandshakeOptions{}
	for _, option := range options {
		option(opts)
	}
	wsOptions := tr.options
	if opts.WSOptions != nil {
		wsOptions = opts.WSOptions
	}
	if opts.TLSConfig == nil {
		opts.TLSConfig = &tls.Config{InsecureSkipVerify: true}
	}
	url := url.URL{Scheme: "wss", Host: opts.Addr, Path: "/ws"}
	return websocketClientConn(url.String(), conn, opts.TLSConfig, wsOptions)
}

func (tr *wssTransporter) Multiplex() bool {
	return false
}

type wsListener struct {
	addr     net.Addr
	upgrader *websocket.Upgrader
	srv      *http.Server
	connChan chan net.Conn
	errChan  chan error
}

// WSListener creates a Listener for websocket proxy server.
func WSListener(addr string, options *WSOptions) (Listener, error) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, err
	}
	if options == nil {
		options = &WSOptions{}
	}
	l := &wsListener{
		addr: tcpAddr,
		upgrader: &websocket.Upgrader{
			ReadBufferSize:    options.ReadBufferSize,
			WriteBufferSize:   options.WriteBufferSize,
			CheckOrigin:       func(r *http.Request) bool { return true },
			EnableCompression: options.EnableCompression,
		},
		connChan: make(chan net.Conn, 128),
		errChan:  make(chan error, 1),
	}

	mux := http.NewServeMux()
	mux.Handle("/ws", http.HandlerFunc(l.upgrade))
	l.srv = &http.Server{Addr: addr, Handler: mux}

	ln, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		return nil, err
	}

	go func() {
		err := l.srv.Serve(tcpKeepAliveListener{ln})
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

func (l *wsListener) upgrade(w http.ResponseWriter, r *http.Request) {
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
	case l.connChan <- websocketServerConn(conn):
	default:
		log.Logf("[ws] %s - %s: connection queue is full", r.RemoteAddr, l.addr)
	}
}

func (l *wsListener) Accept() (conn net.Conn, err error) {
	select {
	case conn = <-l.connChan:
	case err = <-l.errChan:
	}
	return
}

func (l *wsListener) Close() error {
	return l.srv.Close()
}

func (l *wsListener) Addr() net.Addr {
	return l.addr
}

type wssListener struct {
	*wsListener
}

// WSSListener creates a Listener for websocket secure proxy server.
func WSSListener(addr string, options *WSOptions) (Listener, error) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, err
	}
	if options == nil {
		options = &WSOptions{}
	}
	l := &wssListener{
		wsListener: &wsListener{
			addr: tcpAddr,
			upgrader: &websocket.Upgrader{
				ReadBufferSize:    options.ReadBufferSize,
				WriteBufferSize:   options.WriteBufferSize,
				CheckOrigin:       func(r *http.Request) bool { return true },
				EnableCompression: options.EnableCompression,
			},
			connChan: make(chan net.Conn, 128),
			errChan:  make(chan error, 1),
		},
	}

	mux := http.NewServeMux()
	mux.Handle("/ws", http.HandlerFunc(l.upgrade))
	l.srv = &http.Server{
		Addr:      addr,
		TLSConfig: options.TLSConfig,
		Handler:   mux,
	}

	ln, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		return nil, err
	}

	go func() {
		err := l.srv.Serve(tls.NewListener(tcpKeepAliveListener{ln}, options.TLSConfig))
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
