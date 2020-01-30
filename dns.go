package gost

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-log/log"
	"github.com/miekg/dns"
)

var (
	defaultResolver Resolver
)

func init() {
	defaultResolver = NewResolver(
		DefaultResolverTimeout,
		NameServer{
			Addr:     "127.0.0.1:53",
			Protocol: "udp",
		})
	defaultResolver.Init()
}

type dnsHandler struct {
	options *HandlerOptions
}

// DNSHandler creates a Handler for DNS server.
func DNSHandler(raddr string, opts ...HandlerOption) Handler {
	h := &dnsHandler{}

	for _, opt := range opts {
		opt(h.options)
	}
	return h
}

func (h *dnsHandler) Init(opts ...HandlerOption) {
	if h.options == nil {
		h.options = &HandlerOptions{}
	}

	for _, opt := range opts {
		opt(h.options)
	}
}

func (h *dnsHandler) Handle(conn net.Conn) {
	defer conn.Close()

	b := mPool.Get().([]byte)
	defer mPool.Put(b)

	n, err := conn.Read(b)
	if err != nil {
		log.Logf("[dns] %s - %s: %v", conn.RemoteAddr(), conn.LocalAddr(), err)
	}

	mq := &dns.Msg{}
	if err = mq.Unpack(b[:n]); err != nil {
		log.Logf("[dns] %s - %s request unpack: %v", conn.RemoteAddr(), conn.LocalAddr(), err)
		return
	}
	log.Logf("[dns] %s -> %s: %s", conn.RemoteAddr(), conn.LocalAddr(), h.dumpMsgHeader(mq))
	if Debug {
		log.Logf("[dns] %s >>> %s: %s", conn.RemoteAddr(), conn.LocalAddr(), mq.String())
	}

	start := time.Now()

	resolver := h.options.Resolver
	if resolver == nil {
		resolver = defaultResolver
	}
	reply, err := resolver.Exchange(context.Background(), b[:n])
	if err != nil {
		log.Logf("[dns] %s - %s exchange: %v", conn.RemoteAddr(), conn.LocalAddr(), err)
		return
	}

	rtt := time.Since(start)

	mr := &dns.Msg{}
	if err = mr.Unpack(reply); err != nil {
		log.Logf("[dns] %s - %s reply unpack: %v", conn.RemoteAddr(), conn.LocalAddr(), err)
		return
	}
	log.Logf("[dns] %s <- %s: %s [%s]",
		conn.RemoteAddr(), conn.LocalAddr(), h.dumpMsgHeader(mr), rtt)
	if Debug {
		log.Logf("[dns] %s <<< %s: %s", conn.RemoteAddr(), conn.LocalAddr(), mr.String())
	}

	if _, err = conn.Write(reply); err != nil {
		log.Logf("[dns] %s - %s reply unpack: %v", conn.RemoteAddr(), conn.LocalAddr(), err)
	}
}

func (h *dnsHandler) dumpMsgHeader(m *dns.Msg) string {
	buf := new(bytes.Buffer)
	buf.WriteString(m.MsgHdr.String() + " ")
	buf.WriteString("QUERY: " + strconv.Itoa(len(m.Question)) + ", ")
	buf.WriteString("ANSWER: " + strconv.Itoa(len(m.Answer)) + ", ")
	buf.WriteString("AUTHORITY: " + strconv.Itoa(len(m.Ns)) + ", ")
	buf.WriteString("ADDITIONAL: " + strconv.Itoa(len(m.Extra)))
	return buf.String()
}

// DNSOptions is options for DNS Listener.
type DNSOptions struct {
	Mode         string
	UDPSize      int
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	TLSConfig    *tls.Config
}

type dnsListener struct {
	addr     net.Addr
	server   dnsServer
	connChan chan net.Conn
	errc     chan error
}

// DNSListener creates a Listener for DNS proxy server.
func DNSListener(addr string, options *DNSOptions) (Listener, error) {
	if options == nil {
		options = &DNSOptions{}
	}

	tlsConfig := options.TLSConfig
	if tlsConfig == nil {
		tlsConfig = DefaultTLSConfig
	}

	ln := &dnsListener{
		connChan: make(chan net.Conn, 128),
		errc:     make(chan error, 1),
	}

	var srv dnsServer
	var err error
	switch strings.ToLower(options.Mode) {
	case "tcp":
		srv = &dns.Server{
			Net:          "tcp",
			Addr:         addr,
			Handler:      ln,
			ReadTimeout:  options.ReadTimeout,
			WriteTimeout: options.WriteTimeout,
		}
	case "tls":
		srv = &dns.Server{
			Net:          "tcp-tls",
			Addr:         addr,
			Handler:      ln,
			TLSConfig:    tlsConfig,
			ReadTimeout:  options.ReadTimeout,
			WriteTimeout: options.WriteTimeout,
		}
	case "https":
		srv = &dohServer{
			addr:      addr,
			tlsConfig: tlsConfig,
			server: &http.Server{
				Handler:      ln,
				ReadTimeout:  options.ReadTimeout,
				WriteTimeout: options.WriteTimeout,
			},
		}

	default:
		ln.addr, err = net.ResolveTCPAddr("tcp", addr)
		srv = &dns.Server{
			Net:          "udp",
			Addr:         addr,
			Handler:      ln,
			UDPSize:      options.UDPSize,
			ReadTimeout:  options.ReadTimeout,
			WriteTimeout: options.WriteTimeout,
		}
	}
	if err != nil {
		return nil, err
	}

	if ln.addr == nil {
		ln.addr, err = net.ResolveTCPAddr("tcp", addr)
		if err != nil {
			return nil, err
		}
	}

	ln.server = srv

	go func() {
		if err := ln.server.ListenAndServe(); err != nil {
			ln.errc <- err
			return
		}
	}()

	select {
	case err := <-ln.errc:
		return nil, err
	default:
	}

	return ln, nil
}

func (l *dnsListener) serve(w dnsResponseWriter, mq []byte) (err error) {
	conn := newDNSServerConn(l.addr, w.RemoteAddr())
	conn.mq <- mq

	select {
	case l.connChan <- conn:
	default:
		return errors.New("connection queue is full")
	}

	select {
	case mr := <-conn.mr:
		_, err = w.Write(mr)
	case <-conn.cclose:
		err = io.EOF
	}
	return
}

func (l *dnsListener) ServeDNS(w dns.ResponseWriter, m *dns.Msg) {
	b, err := m.Pack()
	if err != nil {
		log.Logf("[dns] %s: %v", l.addr, err)
		return
	}
	if err := l.serve(w, b); err != nil {
		log.Logf("[dns] %s: %v", l.addr, err)
	}
}

// Based on https://github.com/semihalev/sdns
func (l *dnsListener) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var buf []byte
	var err error
	switch r.Method {
	case http.MethodGet:
		buf, err = base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
		if len(buf) == 0 || err != nil {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
	case http.MethodPost:
		if r.Header.Get("Content-Type") != "application/dns-message" {
			http.Error(w, http.StatusText(http.StatusUnsupportedMediaType), http.StatusUnsupportedMediaType)
			return
		}

		buf, err = ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	default:
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	mq := &dns.Msg{}
	if err := mq.Unpack(buf); err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	w.Header().Set("Server", "SDNS")
	w.Header().Set("Content-Type", "application/dns-message")

	raddr, _ := net.ResolveTCPAddr("tcp", r.RemoteAddr)
	if err := l.serve(newDoHResponseWriter(raddr, w), buf); err != nil {
		log.Logf("[dns] %s: %v", l.addr, err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

func (l *dnsListener) Accept() (conn net.Conn, err error) {
	select {
	case conn = <-l.connChan:
	case err = <-l.errc:
	}
	return
}

func (l *dnsListener) Close() error {
	return l.server.Shutdown()
}

func (l *dnsListener) Addr() net.Addr {
	return l.addr
}

type dnsServer interface {
	ListenAndServe() error
	Shutdown() error
}

type dohServer struct {
	addr      string
	tlsConfig *tls.Config
	server    *http.Server
}

func (s *dohServer) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	ln = tls.NewListener(tcpKeepAliveListener{ln.(*net.TCPListener)}, s.tlsConfig)
	return s.server.Serve(ln)
}

func (s *dohServer) Shutdown() error {
	return s.server.Shutdown(context.Background())
}

type dnsServerConn struct {
	mq           chan []byte
	mr           chan []byte
	cclose       chan struct{}
	laddr, raddr net.Addr
}

func newDNSServerConn(laddr, raddr net.Addr) *dnsServerConn {
	return &dnsServerConn{
		mq:     make(chan []byte, 1),
		mr:     make(chan []byte, 1),
		laddr:  laddr,
		raddr:  raddr,
		cclose: make(chan struct{}),
	}
}

func (c *dnsServerConn) Read(b []byte) (n int, err error) {
	select {
	case mb := <-c.mq:
		n = copy(b, mb)
	case <-c.cclose:
		err = errors.New("connection is closed")
	}
	return
}

func (c *dnsServerConn) Write(b []byte) (n int, err error) {
	select {
	case c.mr <- b:
		n = len(b)
	case <-c.cclose:
		err = errors.New("broken pipe")
	}

	return
}

func (c *dnsServerConn) Close() error {
	select {
	case <-c.cclose:
	default:
		close(c.cclose)
	}
	return nil
}

func (c *dnsServerConn) LocalAddr() net.Addr {
	return c.laddr
}

func (c *dnsServerConn) RemoteAddr() net.Addr {
	return c.raddr
}

func (c *dnsServerConn) SetDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "dns", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

func (c *dnsServerConn) SetReadDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "dns", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

func (c *dnsServerConn) SetWriteDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "dns", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

type dnsResponseWriter interface {
	io.Writer
	RemoteAddr() net.Addr
}

type dohResponseWriter struct {
	raddr net.Addr
	http.ResponseWriter
}

func newDoHResponseWriter(raddr net.Addr, w http.ResponseWriter) dnsResponseWriter {
	return &dohResponseWriter{
		raddr:          raddr,
		ResponseWriter: w,
	}
}

func (w *dohResponseWriter) RemoteAddr() net.Addr {
	return w.raddr
}
