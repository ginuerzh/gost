package gost

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"sync"
	"time"

	"net/url"

	"github.com/go-log/log"
	"gopkg.in/gorilla/websocket.v1"
	smux "gopkg.in/xtaci/smux.v1"
)

const (
	defaultWSPath = "/ws"
)

// WSOptions describes the options for websocket.
type WSOptions struct {
	ReadBufferSize    int
	WriteBufferSize   int
	HandshakeTimeout  time.Duration
	EnableCompression bool
	UserAgent         string
	Path              string
}

type wsTransporter struct {
	tcpTransporter
	options *WSOptions
}

// WSTransporter creates a Transporter that is used by websocket proxy client.
func WSTransporter(opts *WSOptions) Transporter {
	return &wsTransporter{
		options: opts,
	}
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
	if wsOptions == nil {
		wsOptions = &WSOptions{}
	}

	path := wsOptions.Path
	if path == "" {
		path = defaultWSPath
	}
	url := url.URL{Scheme: "ws", Host: opts.Host, Path: path}
	return websocketClientConn(url.String(), conn, nil, wsOptions)
}

type mwsTransporter struct {
	tcpTransporter
	options      *WSOptions
	sessions     map[string]*muxSession
	sessionMutex sync.Mutex
}

// MWSTransporter creates a Transporter that is used by multiplex-websocket proxy client.
func MWSTransporter(opts *WSOptions) Transporter {
	return &mwsTransporter{
		options:  opts,
		sessions: make(map[string]*muxSession),
	}
}

func (tr *mwsTransporter) Dial(addr string, options ...DialOption) (conn net.Conn, err error) {
	opts := &DialOptions{}
	for _, option := range options {
		option(opts)
	}

	tr.sessionMutex.Lock()
	defer tr.sessionMutex.Unlock()

	session, ok := tr.sessions[addr]
	if session != nil && session.IsClosed() {
		delete(tr.sessions, addr)
		ok = false
	}
	if !ok {
		timeout := opts.Timeout
		if timeout <= 0 {
			timeout = DialTimeout
		}

		if opts.Chain == nil {
			conn, err = net.DialTimeout("tcp", addr, timeout)
		} else {
			conn, err = opts.Chain.Dial(addr)
		}
		if err != nil {
			return
		}
		session = &muxSession{conn: conn}
		tr.sessions[addr] = session
	}
	return session.conn, nil
}

func (tr *mwsTransporter) Handshake(conn net.Conn, options ...HandshakeOption) (net.Conn, error) {
	opts := &HandshakeOptions{}
	for _, option := range options {
		option(opts)
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = HandshakeTimeout
	}

	tr.sessionMutex.Lock()
	defer tr.sessionMutex.Unlock()

	conn.SetDeadline(time.Now().Add(timeout))
	defer conn.SetDeadline(time.Time{})

	session, ok := tr.sessions[opts.Addr]
	if !ok || session.session == nil {
		s, err := tr.initSession(opts.Addr, conn, opts)
		if err != nil {
			conn.Close()
			delete(tr.sessions, opts.Addr)
			return nil, err
		}
		session = s
		tr.sessions[opts.Addr] = session
	}

	cc, err := session.GetConn()
	if err != nil {
		session.Close()
		delete(tr.sessions, opts.Addr)
		return nil, err
	}
	return cc, nil
}

func (tr *mwsTransporter) initSession(addr string, conn net.Conn, opts *HandshakeOptions) (*muxSession, error) {
	if opts == nil {
		opts = &HandshakeOptions{}
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
	conn, err := websocketClientConn(url.String(), conn, nil, wsOptions)
	if err != nil {
		return nil, err
	}
	// stream multiplex
	smuxConfig := smux.DefaultConfig()
	session, err := smux.Client(conn, smuxConfig)
	if err != nil {
		return nil, err
	}
	return &muxSession{conn: conn, session: session}, nil
}

func (tr *mwsTransporter) Multiplex() bool {
	return true
}

type wssTransporter struct {
	tcpTransporter
	options *WSOptions
}

// WSSTransporter creates a Transporter that is used by websocket secure proxy client.
func WSSTransporter(opts *WSOptions) Transporter {
	return &wssTransporter{
		options: opts,
	}
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
	if wsOptions == nil {
		wsOptions = &WSOptions{}
	}

	if opts.TLSConfig == nil {
		opts.TLSConfig = &tls.Config{InsecureSkipVerify: true}
	}
	path := wsOptions.Path
	if path == "" {
		path = defaultWSPath
	}
	url := url.URL{Scheme: "wss", Host: opts.Host, Path: path}
	return websocketClientConn(url.String(), conn, opts.TLSConfig, wsOptions)
}

type mwssTransporter struct {
	tcpTransporter
	options      *WSOptions
	sessions     map[string]*muxSession
	sessionMutex sync.Mutex
}

// MWSSTransporter creates a Transporter that is used by multiplex-websocket secure proxy client.
func MWSSTransporter(opts *WSOptions) Transporter {
	return &mwssTransporter{
		options:  opts,
		sessions: make(map[string]*muxSession),
	}
}

func (tr *mwssTransporter) Dial(addr string, options ...DialOption) (conn net.Conn, err error) {
	opts := &DialOptions{}
	for _, option := range options {
		option(opts)
	}

	tr.sessionMutex.Lock()
	defer tr.sessionMutex.Unlock()

	session, ok := tr.sessions[addr]
	if session != nil && session.IsClosed() {
		delete(tr.sessions, addr)
		ok = false
	}
	if !ok {
		timeout := opts.Timeout
		if timeout <= 0 {
			timeout = DialTimeout
		}

		if opts.Chain == nil {
			conn, err = net.DialTimeout("tcp", addr, timeout)
		} else {
			conn, err = opts.Chain.Dial(addr)
		}
		if err != nil {
			return
		}
		session = &muxSession{conn: conn}
		tr.sessions[addr] = session
	}
	return session.conn, nil
}

func (tr *mwssTransporter) Handshake(conn net.Conn, options ...HandshakeOption) (net.Conn, error) {
	opts := &HandshakeOptions{}
	for _, option := range options {
		option(opts)
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = HandshakeTimeout
	}

	tr.sessionMutex.Lock()
	defer tr.sessionMutex.Unlock()

	conn.SetDeadline(time.Now().Add(timeout))
	defer conn.SetDeadline(time.Time{})

	session, ok := tr.sessions[opts.Addr]
	if !ok || session.session == nil {
		s, err := tr.initSession(opts.Addr, conn, opts)
		if err != nil {
			conn.Close()
			delete(tr.sessions, opts.Addr)
			return nil, err
		}
		session = s
		tr.sessions[opts.Addr] = session
	}
	cc, err := session.GetConn()
	if err != nil {
		session.Close()
		delete(tr.sessions, opts.Addr)
		return nil, err
	}
	return cc, nil
}

func (tr *mwssTransporter) initSession(addr string, conn net.Conn, opts *HandshakeOptions) (*muxSession, error) {
	if opts == nil {
		opts = &HandshakeOptions{}
	}
	wsOptions := tr.options
	if opts.WSOptions != nil {
		wsOptions = opts.WSOptions
	}
	if wsOptions == nil {
		wsOptions = &WSOptions{}
	}

	tlsConfig := opts.TLSConfig
	if tlsConfig == nil {
		tlsConfig = &tls.Config{InsecureSkipVerify: true}
	}
	path := wsOptions.Path
	if path == "" {
		path = defaultWSPath
	}
	url := url.URL{Scheme: "wss", Host: opts.Host, Path: path}
	conn, err := websocketClientConn(url.String(), conn, tlsConfig, wsOptions)
	if err != nil {
		return nil, err
	}
	// stream multiplex
	smuxConfig := smux.DefaultConfig()
	session, err := smux.Client(conn, smuxConfig)
	if err != nil {
		return nil, err
	}
	return &muxSession{conn: conn, session: session}, nil
}

func (tr *mwssTransporter) Multiplex() bool {
	return true
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
		path = defaultWSPath
	}
	mux := http.NewServeMux()
	mux.Handle(path, http.HandlerFunc(l.upgrade))
	l.srv = &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 30 * time.Second,
	}

	ln, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		return nil, err
	}
	l.addr = ln.Addr()

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
		conn.Close()
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

type mwsListener struct {
	addr     net.Addr
	upgrader *websocket.Upgrader
	srv      *http.Server
	connChan chan net.Conn
	errChan  chan error
}

// MWSListener creates a Listener for multiplex-websocket proxy server.
func MWSListener(addr string, options *WSOptions) (Listener, error) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, err
	}
	if options == nil {
		options = &WSOptions{}
	}
	l := &mwsListener{
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
		path = defaultWSPath
	}

	mux := http.NewServeMux()
	mux.Handle(path, http.HandlerFunc(l.upgrade))
	l.srv = &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 30 * time.Second,
	}

	ln, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		return nil, err
	}
	l.addr = ln.Addr()

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

func (l *mwsListener) upgrade(w http.ResponseWriter, r *http.Request) {
	log.Logf("[mws] %s -> %s", r.RemoteAddr, l.addr)
	if Debug {
		dump, _ := httputil.DumpRequest(r, false)
		log.Log(string(dump))
	}
	conn, err := l.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Logf("[mws] %s - %s : %s", r.RemoteAddr, l.addr, err)
		return
	}

	l.mux(websocketServerConn(conn))
}

func (l *mwsListener) mux(conn net.Conn) {
	smuxConfig := smux.DefaultConfig()
	mux, err := smux.Server(conn, smuxConfig)
	if err != nil {
		log.Logf("[mws] %s - %s : %s", conn.RemoteAddr(), l.Addr(), err)
		return
	}
	defer mux.Close()

	log.Logf("[mws] %s <-> %s", conn.RemoteAddr(), l.Addr())
	defer log.Logf("[mws] %s >-< %s", conn.RemoteAddr(), l.Addr())

	for {
		stream, err := mux.AcceptStream()
		if err != nil {
			log.Log("[mws] accept stream:", err)
			return
		}

		cc := &muxStreamConn{Conn: conn, stream: stream}
		select {
		case l.connChan <- cc:
		default:
			cc.Close()
			log.Logf("[mws] %s - %s: connection queue is full", conn.RemoteAddr(), conn.LocalAddr())
		}
	}
}

func (l *mwsListener) Accept() (conn net.Conn, err error) {
	select {
	case conn = <-l.connChan:
	case err = <-l.errChan:
	}
	return
}

func (l *mwsListener) Close() error {
	return l.srv.Close()
}

func (l *mwsListener) Addr() net.Addr {
	return l.addr
}

type wssListener struct {
	*wsListener
}

// WSSListener creates a Listener for websocket secure proxy server.
func WSSListener(addr string, tlsConfig *tls.Config, options *WSOptions) (Listener, error) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, err
	}
	if options == nil {
		options = &WSOptions{}
	}
	l := &wssListener{
		wsListener: &wsListener{
			upgrader: &websocket.Upgrader{
				ReadBufferSize:    options.ReadBufferSize,
				WriteBufferSize:   options.WriteBufferSize,
				CheckOrigin:       func(r *http.Request) bool { return true },
				EnableCompression: options.EnableCompression,
			},
			connChan: make(chan net.Conn, 1024),
			errChan:  make(chan error, 1),
		},
	}

	if tlsConfig == nil {
		tlsConfig = DefaultTLSConfig
	}

	path := options.Path
	if path == "" {
		path = defaultWSPath
	}

	mux := http.NewServeMux()
	mux.Handle(path, http.HandlerFunc(l.upgrade))
	l.srv = &http.Server{
		Addr:              addr,
		TLSConfig:         tlsConfig,
		Handler:           mux,
		ReadHeaderTimeout: 30 * time.Second,
	}

	ln, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		return nil, err
	}
	l.addr = ln.Addr()

	go func() {
		err := l.srv.Serve(tls.NewListener(tcpKeepAliveListener{ln}, tlsConfig))
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

type mwssListener struct {
	*mwsListener
}

// MWSSListener creates a Listener for multiplex-websocket secure proxy server.
func MWSSListener(addr string, tlsConfig *tls.Config, options *WSOptions) (Listener, error) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, err
	}
	if options == nil {
		options = &WSOptions{}
	}
	l := &mwssListener{
		mwsListener: &mwsListener{
			upgrader: &websocket.Upgrader{
				ReadBufferSize:    options.ReadBufferSize,
				WriteBufferSize:   options.WriteBufferSize,
				CheckOrigin:       func(r *http.Request) bool { return true },
				EnableCompression: options.EnableCompression,
			},
			connChan: make(chan net.Conn, 1024),
			errChan:  make(chan error, 1),
		},
	}

	if tlsConfig == nil {
		tlsConfig = DefaultTLSConfig
	}

	path := options.Path
	if path == "" {
		path = defaultWSPath
	}

	mux := http.NewServeMux()
	mux.Handle(path, http.HandlerFunc(l.upgrade))
	l.srv = &http.Server{
		Addr:              addr,
		TLSConfig:         tlsConfig,
		Handler:           mux,
		ReadHeaderTimeout: 30 * time.Second,
	}

	ln, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		return nil, err
	}
	l.addr = ln.Addr()

	go func() {
		err := l.srv.Serve(tls.NewListener(tcpKeepAliveListener{ln}, tlsConfig))
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

var keyGUID = []byte("258EAFA5-E914-47DA-95CA-C5AB0DC85B11")

func computeAcceptKey(challengeKey string) string {
	h := sha1.New()
	h.Write([]byte(challengeKey))
	h.Write(keyGUID)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func generateChallengeKey() (string, error) {
	p := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, p); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(p), nil
}

// TODO: due to the concurrency control in the websocket.Conn,
// a data race may be met when using with multiplexing.
// See: https://godoc.org/gopkg.in/gorilla/websocket.v1#hdr-Concurrency
type websocketConn struct {
	conn *websocket.Conn
	rb   []byte
}

func websocketClientConn(url string, conn net.Conn, tlsConfig *tls.Config, options *WSOptions) (net.Conn, error) {
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
