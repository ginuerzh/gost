package gost

import (
	"crypto/tls"
	"errors"
	"net"
	"time"

	"fmt"

	"github.com/ginuerzh/gosocks5"
	"github.com/go-log/log"
)

type tcpForwardHandler struct {
	raddr   string
	options *HandlerOptions
}

// TCPForwardHandler creates a server Handler for TCP port forwarding server.
// The raddr is the remote address that the server will forward to.
func TCPForwardHandler(raddr string, opts ...HandlerOption) Handler {
	h := &tcpForwardHandler{
		raddr: raddr,
		options: &HandlerOptions{
			Chain: new(Chain),
		},
	}
	for _, opt := range opts {
		opt(h.options)
	}
	return h
}

func (h *tcpForwardHandler) Handle(conn net.Conn) {
	defer conn.Close()

	log.Logf("[tcp] %s - %s", conn.RemoteAddr(), h.raddr)
	cc, err := h.options.Chain.Dial(h.raddr)
	if err != nil {
		log.Logf("[tcp] %s -> %s : %s", conn.RemoteAddr(), h.raddr, err)
		return
	}
	defer cc.Close()

	log.Logf("[tcp] %s <-> %s", conn.RemoteAddr(), h.raddr)
	transport(conn, cc)
	log.Logf("[tcp] %s >-< %s", conn.RemoteAddr(), h.raddr)
}

type udpForwardHandler struct {
	raddr   string
	ttl     time.Duration
	options *HandlerOptions
}

// UDPForwardHandler creates a server Handler for UDP port forwarding server.
// The raddr is the remote address that the server will forward to.
func UDPForwardHandler(raddr string, ttl time.Duration, opts ...HandlerOption) Handler {
	h := &udpForwardHandler{
		raddr: raddr,
		ttl:   ttl,
		options: &HandlerOptions{
			Chain: new(Chain),
		},
	}
	for _, opt := range opts {
		opt(h.options)
	}
	return h
}

func (h *udpForwardHandler) Handle(conn net.Conn) {
	defer conn.Close()
}

type rtcpForwardHandler struct {
	laddr   string
	raddr   string
	options *HandlerOptions
}

// RTCPForwardHandler creates a server Handler for TCP remote port forwarding server.
// The raddr is the remote address that the server will forward to.
func RTCPForwardHandler(laddr, raddr string, opts ...HandlerOption) Handler {
	h := &rtcpForwardHandler{
		laddr:   laddr,
		raddr:   raddr,
		options: &HandlerOptions{},
	}
	for _, opt := range opts {
		opt(h.options)
	}
	return h
}

func (h *rtcpForwardHandler) Handle(conn net.Conn) {
	defer conn.Close()

	cc, err := net.DialTimeout("tcp", h.raddr, DialTimeout)
	if err != nil {
		log.Logf("[rtcp] %s -> %s : %s", h.laddr, h.raddr, err)
		return
	}
	defer cc.Close()

	log.Logf("[rtcp] %s <-> %s", h.laddr, h.raddr)
	transport(cc, conn)
	log.Logf("[rtcp] %s >-< %s", h.laddr, h.raddr)
}

type rudpForwardHandler struct {
	laddr   string
	raddr   string
	options *HandlerOptions
}

// RUDPForwardHandler creates a server Handler for UDP remote port forwarding server.
// The raddr is the remote address that the server will forward to.
func RUDPForwardHandler(laddr, raddr string, opts ...HandlerOption) Handler {
	h := &rudpForwardHandler{
		laddr:   laddr,
		raddr:   raddr,
		options: &HandlerOptions{},
	}
	for _, opt := range opts {
		opt(h.options)
	}
	return h
}

func (h *rudpForwardHandler) Handle(conn net.Conn) {
	defer conn.Close()

	// TODO: handle connection

	/*
		ra, err := net.ResolveUDPAddr("udp", h.raddr)
		if err != nil {
			log.Logf("[rudp] %s - %s : %s", h.laddr, h.raddr, err)
			return
		}

		for {
			dgram, err := gosocks5.ReadUDPDatagram(conn)
			if err != nil {
				log.Logf("[rudp] %s -> %s : %s", h.laddr, h.raddr, err)
				return
			}

			go func() {
				b := make([]byte, mediumBufferSize)

				relay, err := net.DialUDP("udp", nil, ra)
				if err != nil {
					log.Logf("[rudp] %s -> %s : %s", h.laddr, h.raddr, err)
					return
				}
				defer relay.Close()

				if _, err := relay.Write(dgram.Data); err != nil {
					log.Logf("[rudp] %s -> %s : %s", h.laddr, h.raddr, err)
					return
				}
				if Debug {
					log.Logf("[rudp] %s >>> %s length: %d", h.laddr, h.raddr, len(dgram.Data))
				}
				relay.SetReadDeadline(time.Now().Add(ReadTimeout))
				n, err := relay.Read(b)
				if err != nil {
					log.Logf("[rudp] %s <- %s : %s", h.laddr, h.raddr, err)
					return
				}
				relay.SetReadDeadline(time.Time{})
				if Debug {
					log.Logf("[rudp] %s <<< %s length: %d", h.laddr, h.raddr, n)
				}
				conn.SetWriteDeadline(time.Now().Add(WriteTimeout))
				if err := gosocks5.NewUDPDatagram(gosocks5.NewUDPHeader(uint16(n), 0, dgram.Header.Addr), b[:n]).Write(conn); err != nil {
					log.Logf("[rudp] %s <- %s : %s", h.laddr, h.raddr, err)
					return
				}
				conn.SetWriteDeadline(time.Time{})
			}()
		}
	*/
}

type udpForwardListener struct {
	addr *net.UDPAddr
	conn *net.UDPConn
}

// UDPForwardListener creates a Listener for UDP port forwarding server.
func UDPForwardListener(addr string) (Listener, error) {
	laddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return nil, err
	}
	return &udpForwardListener{conn: conn}, nil
}

func (l *udpForwardListener) Accept() (net.Conn, error) {
	// TODO: create udp forward connection
	return nil, nil
}

func (l *udpForwardListener) Addr() net.Addr {
	return l.addr
}

func (l *udpForwardListener) Close() error {
	return l.conn.Close()
}

type rtcpForwardListener struct {
	addr     net.Addr
	chain    *Chain
	selector *clientSelector
	close    chan struct{}
}

// RTCPForwardListener creates a Listener for TCP remote port forwarding server.
func RTCPForwardListener(addr string, chain *Chain) (Listener, error) {
	laddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, err
	}
	if chain.IsEmpty() || chain.LastNode().Protocol != "socks5" {
		return nil, errors.New("invalid chain")
	}
	selector := &clientSelector{
		TLSConfig: &tls.Config{InsecureSkipVerify: true},
		User:      chain.LastNode().User,
	}
	selector.AddMethod(
		gosocks5.MethodNoAuth,
		gosocks5.MethodUserPass,
		MethodTLS,
	)

	return &rtcpForwardListener{
		addr:     laddr,
		chain:    chain,
		selector: selector,
		close:    make(chan struct{}),
	}, nil
}

func (l *rtcpForwardListener) Accept() (net.Conn, error) {
	select {
	case <-l.close:
		return nil, errors.New("closed")
	default:
	}

	if l.chain.IsEmpty() || l.chain.LastNode().Protocol != "socks5" {
		return nil, errors.New("invalid chain")
	}

	conn, err := l.chain.Conn()
	if err != nil {
		return nil, err
	}
	cc, err := l.handshake(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}

	return cc, nil
}

func (l *rtcpForwardListener) handshake(conn net.Conn) (net.Conn, error) {
	cc := gosocks5.ClientConn(conn, l.selector)
	if err := cc.Handleshake(); err != nil {
		return nil, err
	}
	conn = cc

	req := gosocks5.NewRequest(gosocks5.CmdBind, toSocksAddr(l.addr))
	if err := req.Write(conn); err != nil {
		log.Log("[rtcp] SOCKS5 BIND request: ", err)
		return nil, err
	}

	// first reply, bind status
	conn.SetReadDeadline(time.Now().Add(ReadTimeout))
	rep, err := gosocks5.ReadReply(conn)
	if err != nil {
		log.Log("[rtcp] SOCKS5 BIND reply: ", err)
		return nil, err
	}
	conn.SetReadDeadline(time.Time{})
	if rep.Rep != gosocks5.Succeeded {
		log.Logf("[rtcp] bind on %s failure", l.addr)
		return nil, fmt.Errorf("Bind on %s failure", l.addr.String())
	}
	log.Logf("[rtcp] BIND ON %s OK", rep.Addr)

	// second reply, peer connected
	rep, err = gosocks5.ReadReply(conn)
	if err != nil {
		log.Log("[rtcp]", err)
		return nil, err
	}
	if rep.Rep != gosocks5.Succeeded {
		log.Logf("[rtcp] peer connect failure: %d", rep.Rep)
		return nil, errors.New("peer connect failure")
	}

	log.Logf("[rtcp] PEER %s CONNECTED", rep.Addr)
	return conn, nil
}

func (l *rtcpForwardListener) Addr() net.Addr {
	return l.addr
}

func (l *rtcpForwardListener) Close() error {
	close(l.close)
	return nil
}

type rudpForwardListener struct {
	addr     net.Addr
	chain    *Chain
	selector *clientSelector
	close    chan struct{}
}

// RUDPForwardListener creates a Listener for UDP remote port forwarding server.
func RUDPForwardListener(addr string, chain *Chain) (Listener, error) {
	laddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	if chain.IsEmpty() || chain.LastNode().Protocol != "socks5" {
		return nil, errors.New("invalid chain")
	}
	selector := &clientSelector{
		TLSConfig: &tls.Config{InsecureSkipVerify: true},
		User:      chain.LastNode().User,
	}
	selector.AddMethod(
		gosocks5.MethodNoAuth,
		gosocks5.MethodUserPass,
		MethodTLS,
	)

	return &rudpForwardListener{
		addr:     laddr,
		chain:    chain,
		selector: selector,
		close:    make(chan struct{}),
	}, nil
}

func (l *rudpForwardListener) Accept() (net.Conn, error) {
	select {
	case <-l.close:
		return nil, errors.New("closed")
	default:
	}

	conn, err := l.chain.Conn()
	if err != nil {
		return nil, err
	}
	cc, err := l.handshake(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	conn = cc

	return cc, nil
}

func (l *rudpForwardListener) handshake(conn net.Conn) (net.Conn, error) {
	cc := gosocks5.ClientConn(conn, l.selector)
	if err := cc.Handleshake(); err != nil {
		return nil, err
	}
	conn = cc

	req := gosocks5.NewRequest(CmdUDPTun, toSocksAddr(l.addr))
	if err := req.Write(conn); err != nil {
		log.Log("[rudp] SOCKS5 UDP relay request: ", err)
		return nil, err
	}

	conn.SetReadDeadline(time.Now().Add(ReadTimeout))
	rep, err := gosocks5.ReadReply(conn)
	if err != nil {
		log.Log("[rudp] SOCKS5 UDP relay reply: ", err)
		return nil, err
	}
	conn.SetReadDeadline(time.Time{})
	if rep.Rep != gosocks5.Succeeded {
		log.Logf("[rudp] bind on %s failure: %d", l.addr, rep.Rep)
		return nil, fmt.Errorf("Bind on %s failure", l.addr.String())
	}
	log.Logf("[rudp] BIND ON %s OK", rep.Addr)
	return conn, nil
}

func (l *rudpForwardListener) Addr() net.Addr {
	return l.addr
}

func (l *rudpForwardListener) Close() error {
	close(l.close)
	return nil
}
