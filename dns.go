package gost

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strconv"
	"time"

	"github.com/go-log/log"
	"github.com/miekg/dns"
)

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
	reply, err := h.options.Resolver.Exchange(context.Background(), b[:n])
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

type DNSOptions struct {
	TCPMode      bool
	UDPSize      int
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

type dnsListener struct {
	addr     net.Addr
	server   *dns.Server
	connChan chan net.Conn
	errc     chan error
}

func DNSListener(addr string, options *DNSOptions) (Listener, error) {
	if options == nil {
		options = &DNSOptions{}
	}

	ln := &dnsListener{
		connChan: make(chan net.Conn, 128),
		errc:     make(chan error, 1),
	}

	var nets string
	var err error

	if options.TCPMode {
		nets = "tcp"
		ln.addr, err = net.ResolveTCPAddr("tcp", addr)
	} else {
		nets = "udp"
		ln.addr, err = net.ResolveUDPAddr("udp", addr)
	}
	if err != nil {
		return nil, err
	}

	ln.server = &dns.Server{
		Addr: addr,
		Net:  nets,
	}

	dns.HandleFunc(".", ln.handleRequest)

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

func (l *dnsListener) handleRequest(w dns.ResponseWriter, m *dns.Msg) {
	if w == nil || m == nil {
		return
	}

	conn := &dnsServerConn{
		mq:             make(chan []byte, 1),
		ResponseWriter: w,
	}

	buf := mPool.Get().([]byte)
	defer mPool.Put(buf)
	buf = buf[:0]
	b, err := m.PackBuffer(buf)
	if err != nil {
		log.Logf("[dns] %s: %v", l.addr, err)
		return
	}
	conn.mq <- b

	select {
	case l.connChan <- conn:
	default:
		log.Logf("[dns] %s: connection queue is full", l.addr)
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

type dnsServerConn struct {
	mq chan []byte
	dns.ResponseWriter
}

func (c *dnsServerConn) Read(b []byte) (n int, err error) {
	var mb []byte
	select {
	case mb = <-c.mq:
	default:
	}
	n = copy(b, mb)
	return
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
