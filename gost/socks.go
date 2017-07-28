package gost

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"time"

	"io"

	"github.com/ginuerzh/gosocks4"
	"github.com/ginuerzh/gosocks5"
	"github.com/go-log/log"
)

const (
	// MethodTLS is an extended SOCKS5 method for TLS.
	MethodTLS uint8 = 0x80
	// MethodTLSAuth is an extended SOCKS5 method for TLS+AUTH.
	MethodTLSAuth uint8 = 0x82
)

const (
	// CmdUDPTun is an extended SOCKS5 method for UDP over TCP.
	CmdUDPTun uint8 = 0xF3
)

type clientSelector struct {
	methods   []uint8
	User      *url.Userinfo
	TLSConfig *tls.Config
}

func (selector *clientSelector) Methods() []uint8 {
	return selector.methods
}

func (selector *clientSelector) AddMethod(methods ...uint8) {
	selector.methods = append(selector.methods, methods...)
}

func (selector *clientSelector) Select(methods ...uint8) (method uint8) {
	return
}

func (selector *clientSelector) OnSelected(method uint8, conn net.Conn) (net.Conn, error) {
	switch method {
	case MethodTLS:
		conn = tls.Client(conn, selector.TLSConfig)

	case gosocks5.MethodUserPass, MethodTLSAuth:
		if method == MethodTLSAuth {
			conn = tls.Client(conn, selector.TLSConfig)
		}

		var username, password string
		if selector.User != nil {
			username = selector.User.Username()
			password, _ = selector.User.Password()
		}

		req := gosocks5.NewUserPassRequest(gosocks5.UserPassVer, username, password)
		if err := req.Write(conn); err != nil {
			log.Log("[socks5]", err)
			return nil, err
		}
		if Debug {
			log.Log("[socks5]", req)
		}
		resp, err := gosocks5.ReadUserPassResponse(conn)
		if err != nil {
			log.Log("[socks5]", err)
			return nil, err
		}
		if Debug {
			log.Log("[socks5]", resp)
		}
		if resp.Status != gosocks5.Succeeded {
			return nil, gosocks5.ErrAuthFailure
		}
	case gosocks5.MethodNoAcceptable:
		return nil, gosocks5.ErrBadMethod
	}

	return conn, nil
}

type serverSelector struct {
	methods   []uint8
	Users     []*url.Userinfo
	TLSConfig *tls.Config
}

func (selector *serverSelector) Methods() []uint8 {
	return selector.methods
}

func (selector *serverSelector) AddMethod(methods ...uint8) {
	selector.methods = append(selector.methods, methods...)
}

func (selector *serverSelector) Select(methods ...uint8) (method uint8) {
	if Debug {
		log.Logf("[socks5] %d %d %v", gosocks5.Ver5, len(methods), methods)
	}
	method = gosocks5.MethodNoAuth
	for _, m := range methods {
		if m == MethodTLS {
			method = m
			break
		}
	}

	// when user/pass is set, auth is mandatory
	if len(selector.Users) > 0 {
		if method == gosocks5.MethodNoAuth {
			method = gosocks5.MethodUserPass
		}
		if method == MethodTLS {
			method = MethodTLSAuth
		}
	}

	return
}

func (selector *serverSelector) OnSelected(method uint8, conn net.Conn) (net.Conn, error) {
	if Debug {
		log.Logf("[socks5] %d %d", gosocks5.Ver5, method)
	}
	switch method {
	case MethodTLS:
		conn = tls.Server(conn, selector.TLSConfig)

	case gosocks5.MethodUserPass, MethodTLSAuth:
		if method == MethodTLSAuth {
			conn = tls.Server(conn, selector.TLSConfig)
		}

		req, err := gosocks5.ReadUserPassRequest(conn)
		if err != nil {
			log.Log("[socks5]", err)
			return nil, err
		}
		if Debug {
			log.Log("[socks5]", req.String())
		}
		valid := false
		for _, user := range selector.Users {
			username := user.Username()
			password, _ := user.Password()
			if (req.Username == username && req.Password == password) ||
				(req.Username == username && password == "") ||
				(username == "" && req.Password == password) {
				valid = true
				break
			}
		}
		if len(selector.Users) > 0 && !valid {
			resp := gosocks5.NewUserPassResponse(gosocks5.UserPassVer, gosocks5.Failure)
			if err := resp.Write(conn); err != nil {
				log.Log("[socks5]", err)
				return nil, err
			}
			if Debug {
				log.Log("[socks5]", resp)
			}
			log.Log("[socks5] proxy authentication required")
			return nil, gosocks5.ErrAuthFailure
		}

		resp := gosocks5.NewUserPassResponse(gosocks5.UserPassVer, gosocks5.Succeeded)
		if err := resp.Write(conn); err != nil {
			log.Log("[socks5]", err)
			return nil, err
		}
		if Debug {
			log.Log("[socks5]", resp)
		}
	case gosocks5.MethodNoAcceptable:
		return nil, gosocks5.ErrBadMethod
	}

	return conn, nil
}

type socks5Connector struct {
	User *url.Userinfo
}

// SOCKS5Connector creates a connector for SOCKS5 proxy client.
// It accepts an optional auth info for SOCKS5 Username/Password Authentication.
func SOCKS5Connector(user *url.Userinfo) Connector {
	return &socks5Connector{User: user}
}

func (c *socks5Connector) Connect(conn net.Conn, addr string) (net.Conn, error) {
	selector := &clientSelector{
		TLSConfig: &tls.Config{InsecureSkipVerify: true},
		User:      c.User,
	}
	selector.AddMethod(
		gosocks5.MethodNoAuth,
		gosocks5.MethodUserPass,
		MethodTLS,
	)

	cc := gosocks5.ClientConn(conn, selector)
	if err := cc.Handleshake(); err != nil {
		return nil, err
	}
	conn = cc

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	p, _ := strconv.Atoi(port)
	req := gosocks5.NewRequest(gosocks5.CmdConnect, &gosocks5.Addr{
		Type: gosocks5.AddrDomain,
		Host: host,
		Port: uint16(p),
	})
	if err := req.Write(conn); err != nil {
		return nil, err
	}

	if Debug {
		log.Log("[socks5]", req)
	}

	reply, err := gosocks5.ReadReply(conn)
	if err != nil {
		return nil, err
	}

	if Debug {
		log.Log("[socks5]", reply)
	}

	if reply.Rep != gosocks5.Succeeded {
		return nil, errors.New("Service unavailable")
	}

	return conn, nil
}

type socks4Connector struct{}

// SOCKS4Connector creates a Connector for SOCKS4 proxy client.
func SOCKS4Connector() Connector {
	return &socks4Connector{}
}

func (c *socks4Connector) Connect(conn net.Conn, addr string) (net.Conn, error) {
	taddr, err := net.ResolveTCPAddr("tcp4", addr)
	if err != nil {
		return nil, err
	}

	req := gosocks4.NewRequest(gosocks4.CmdConnect,
		&gosocks4.Addr{
			Type: gosocks4.AddrIPv4,
			Host: taddr.IP.String(),
			Port: uint16(taddr.Port),
		}, nil,
	)
	if err := req.Write(conn); err != nil {
		return nil, err
	}

	if Debug {
		log.Logf("[socks4] %s", req)
	}

	reply, err := gosocks4.ReadReply(conn)
	if err != nil {
		return nil, err
	}

	if Debug {
		log.Logf("[socks4] %s", reply)
	}

	if reply.Code != gosocks4.Granted {
		return nil, fmt.Errorf("[socks4] %d", reply.Code)
	}

	return conn, nil
}

type socks4aConnector struct{}

// SOCKS4AConnector creates a Connector for SOCKS4A proxy client.
func SOCKS4AConnector() Connector {
	return &socks4aConnector{}
}

func (c *socks4aConnector) Connect(conn net.Conn, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	p, _ := strconv.Atoi(port)

	req := gosocks4.NewRequest(gosocks4.CmdConnect,
		&gosocks4.Addr{Type: gosocks4.AddrDomain, Host: host, Port: uint16(p)}, nil)
	if err := req.Write(conn); err != nil {
		return nil, err
	}

	if Debug {
		log.Logf("[socks4] %s", req)
	}

	reply, err := gosocks4.ReadReply(conn)
	if err != nil {
		return nil, err
	}

	if Debug {
		log.Logf("[socks4] %s", reply)
	}

	if reply.Code != gosocks4.Granted {
		return nil, fmt.Errorf("[socks4] %d", reply.Code)
	}

	return conn, nil
}

type socks5Handler struct {
	selector *serverSelector
	options  *HandlerOptions
}

// SOCKS5Handler creates a server Handler for SOCKS5 proxy server.
func SOCKS5Handler(opts ...HandlerOption) Handler {
	options := &HandlerOptions{
		Chain: new(Chain),
	}
	for _, opt := range opts {
		opt(options)
	}

	selector := &serverSelector{ // socks5 server selector
		Users:     options.Users,
		TLSConfig: options.TLSConfig,
	}
	// methods that socks5 server supported
	selector.AddMethod(
		gosocks5.MethodNoAuth,
		gosocks5.MethodUserPass,
		MethodTLS,
		MethodTLSAuth,
	)
	return &socks5Handler{
		options:  options,
		selector: selector,
	}
}

func (h *socks5Handler) Handle(conn net.Conn) {
	defer conn.Close()

	conn = gosocks5.ServerConn(conn, h.selector)
	req, err := gosocks5.ReadRequest(conn)
	if err != nil {
		log.Log("[socks5]", err)
		return
	}

	if Debug {
		log.Logf("[socks5] %s - %s\n%s", conn.RemoteAddr(), req.Addr, req)
	}
	switch req.Cmd {
	case gosocks5.CmdConnect:
		h.handleConnect(conn, req)

	case gosocks5.CmdBind:
		h.handleBind(conn, req)

	case gosocks5.CmdUdp:
		h.handleUDPRelay(conn, req)

	case CmdUDPTun:
		h.handleUDPTunnel(conn, req)

	default:
		log.Log("[socks5] Unrecognized request:", req.Cmd)
	}
}

func (h *socks5Handler) handleConnect(conn net.Conn, req *gosocks5.Request) {
	addr := req.Addr.String()

	//! if !s.Base.Node.Can("tcp", addr) {
	//! 	glog.Errorf("Unauthorized to tcp connect to %s", addr)
	//! 	rep := gosocks5.NewReply(gosocks5.NotAllowed, nil)
	//! 	rep.Write(s.conn)
	//! 	return
	//! }

	cc, err := h.options.Chain.Dial(addr)
	if err != nil {
		log.Logf("[socks5-connect] %s -> %s : %s", conn.RemoteAddr(), req.Addr, err)
		rep := gosocks5.NewReply(gosocks5.HostUnreachable, nil)
		rep.Write(conn)
		if Debug {
			log.Logf("[socks5-connect] %s <- %s\n%s", conn.RemoteAddr(), req.Addr, rep)
		}
		return
	}
	defer cc.Close()

	rep := gosocks5.NewReply(gosocks5.Succeeded, nil)
	if err := rep.Write(conn); err != nil {
		log.Logf("[socks5-connect] %s <- %s : %s", conn.RemoteAddr(), req.Addr, err)
		return
	}
	if Debug {
		log.Logf("[socks5-connect] %s <- %s\n%s", conn.RemoteAddr(), req.Addr, rep)
	}
	log.Logf("[socks5-connect] %s <-> %s", conn.RemoteAddr(), req.Addr)
	transport(conn, cc)
	log.Logf("[socks5-connect] %s >-< %s", conn.RemoteAddr(), req.Addr)
}

func (h *socks5Handler) handleBind(conn net.Conn, req *gosocks5.Request) {
	if h.options.Chain.IsEmpty() {

		//! if !s.Base.Node.Can("rtcp", addr) {
		//! 	glog.Errorf("Unauthorized to tcp bind to %s", addr)
		//! 	return
		//! }

		h.bindOn(conn, req.Addr.String())
		return
	}

	cc, err := h.options.Chain.Conn()
	if err != nil {
		log.Logf("[socks5-bind] %s <- %s : %s", conn.RemoteAddr(), req.Addr, err)
		reply := gosocks5.NewReply(gosocks5.Failure, nil)
		reply.Write(conn)
		if Debug {
			log.Logf("[socks5-bind] %s <- %s\n%s", conn.RemoteAddr(), req.Addr, reply)
		}
		return
	}

	// forward request
	// note: this type of request forwarding is defined when starting server,
	// so we don't need to authenticate it, as it's as explicit as whitelisting
	defer cc.Close()
	req.Write(cc)
	log.Logf("[socks5-bind] %s <-> %s", conn.RemoteAddr(), cc.RemoteAddr())
	transport(conn, cc)
	log.Logf("[socks5-bind] %s >-< %s", conn.RemoteAddr(), cc.RemoteAddr())
}

func (h *socks5Handler) bindOn(conn net.Conn, addr string) {
	bindAddr, _ := net.ResolveTCPAddr("tcp", addr)
	ln, err := net.ListenTCP("tcp", bindAddr) // strict mode: if the port already in use, it will return error
	if err != nil {
		log.Logf("[socks5-bind] %s -> %s : %s", conn.RemoteAddr(), addr, err)
		gosocks5.NewReply(gosocks5.Failure, nil).Write(conn)
		return
	}

	socksAddr := toSocksAddr(ln.Addr())
	// Issue: may not reachable when host has multi-interface
	socksAddr.Host, _, _ = net.SplitHostPort(conn.LocalAddr().String())
	reply := gosocks5.NewReply(gosocks5.Succeeded, socksAddr)
	if err := reply.Write(conn); err != nil {
		log.Logf("[socks5-bind] %s <- %s : %s", conn.RemoteAddr(), addr, err)
		ln.Close()
		return
	}
	if Debug {
		log.Logf("[socks5-bind] %s <- %s\n%s", conn.RemoteAddr(), addr, reply)
	}
	log.Logf("[socks5-bind] %s - %s BIND ON %s OK", conn.RemoteAddr(), addr, socksAddr)

	var pconn net.Conn
	accept := func() <-chan error {
		errc := make(chan error, 1)

		go func() {
			defer close(errc)
			defer ln.Close()

			c, err := ln.AcceptTCP()
			if err != nil {
				errc <- err
				return
			}
			pconn = c
		}()

		return errc
	}

	pc1, pc2 := net.Pipe()
	pipe := func() <-chan error {
		errc := make(chan error, 1)

		go func() {
			defer close(errc)
			defer pc1.Close()

			errc <- transport(conn, pc1)
		}()

		return errc
	}

	defer pc2.Close()

	for {
		select {
		case err := <-accept():
			if err != nil || pconn == nil {
				log.Logf("[socks5-bind] %s <- %s : %v", conn.RemoteAddr(), addr, err)
				return
			}
			defer pconn.Close()

			reply := gosocks5.NewReply(gosocks5.Succeeded, toSocksAddr(pconn.RemoteAddr()))
			if err := reply.Write(pc2); err != nil {
				log.Logf("[socks5-bind] %s <- %s : %v", conn.RemoteAddr(), addr, err)
			}
			if Debug {
				log.Logf("[socks5-bind] %s <- %s\n%s", conn.RemoteAddr(), addr, reply)
			}
			log.Logf("[socks5-bind] %s <- %s PEER %s ACCEPTED", conn.RemoteAddr(), socksAddr, pconn.RemoteAddr())

			log.Logf("[socks5-bind] %s <-> %s", conn.RemoteAddr(), pconn.RemoteAddr())
			if err = transport(pc2, pconn); err != nil {
				log.Logf("[socks5-bind] %s - %s : %v", conn.RemoteAddr(), pconn.RemoteAddr(), err)
			}
			log.Logf("[socks5-bind] %s >-< %s", conn.RemoteAddr(), pconn.RemoteAddr())
			return
		case err := <-pipe():
			if err != nil {
				log.Logf("[socks5-bind] %s -> %s : %v", conn.RemoteAddr(), addr, err)
			}
			ln.Close()
			return
		}
	}
}

func (h *socks5Handler) handleUDPRelay(conn net.Conn, req *gosocks5.Request) {
	//! addr := req.Addr.String()
	//!
	//! if !s.Base.Node.Can("udp", addr) {
	//! 	glog.Errorf("Unauthorized to udp connect to %s", addr)
	//! 	rep := gosocks5.NewReply(gosocks5.NotAllowed, nil)
	//! 	rep.Write(s.conn)
	//! 	return
	//! }

	relay, err := net.ListenUDP("udp", nil)
	if err != nil {
		log.Logf("[socks5-udp] %s -> %s : %s", conn.RemoteAddr(), relay.LocalAddr(), err)
		reply := gosocks5.NewReply(gosocks5.Failure, nil)
		reply.Write(conn)
		if Debug {
			log.Logf("[socks5-udp] %s <- %s\n%s", conn.RemoteAddr(), relay.LocalAddr(), reply)
		}
		return
	}
	defer relay.Close()

	socksAddr := toSocksAddr(relay.LocalAddr())
	socksAddr.Host, _, _ = net.SplitHostPort(conn.LocalAddr().String()) // replace the IP to the out-going interface's
	reply := gosocks5.NewReply(gosocks5.Succeeded, socksAddr)
	if err := reply.Write(conn); err != nil {
		log.Logf("[socks5-udp] %s <- %s : %s", conn.RemoteAddr(), relay.LocalAddr(), err)
		return
	}
	if Debug {
		log.Logf("[socks5-udp] %s <- %s\n%s", conn.RemoteAddr(), reply.Addr, reply)
	}
	log.Logf("[socks5-udp] %s - %s BIND ON %s OK", conn.RemoteAddr(), relay.LocalAddr(), socksAddr)

	// serve as standard socks5 udp relay local <-> remote
	if h.options.Chain.IsEmpty() {
		peer, er := net.ListenUDP("udp", nil)
		if er != nil {
			log.Logf("[socks5-udp] %s -> %s : %s", conn.RemoteAddr(), socksAddr, er)
			return
		}
		defer peer.Close()

		go h.transportUDP(relay, peer)
		log.Logf("[socks5-udp] %s <-> %s", conn.RemoteAddr(), socksAddr)
		if err := h.discardClientData(conn); err != nil {
			log.Logf("[socks5-udp] %s - %s : %s", conn.RemoteAddr(), socksAddr, err)
		}
		log.Logf("[socks5-udp] %s >-< %s", conn.RemoteAddr(), socksAddr)
		return
	}

	cc, err := h.options.Chain.Conn()
	// connection error
	if err != nil {
		log.Logf("[socks5-udp] %s -> %s : %s", conn.RemoteAddr(), socksAddr, err)
		return
	}

	// forward udp local <-> tunnel
	defer cc.Close()

	cc.SetWriteDeadline(time.Now().Add(WriteTimeout))
	r := gosocks5.NewRequest(CmdUDPTun, nil)
	if err := r.Write(cc); err != nil {
		log.Logf("[socks5-udp] %s -> %s : %s", conn.RemoteAddr(), cc.RemoteAddr(), err)
		return
	}
	cc.SetWriteDeadline(time.Time{})
	if Debug {
		log.Logf("[socks5-udp] %s -> %s\n%s", conn.RemoteAddr(), cc.RemoteAddr(), r)
	}
	cc.SetReadDeadline(time.Now().Add(ReadTimeout))
	reply, err = gosocks5.ReadReply(cc)
	if err != nil {
		log.Logf("[socks5-udp] %s -> %s : %s", conn.RemoteAddr(), cc.RemoteAddr(), err)
		return
	}
	if Debug {
		log.Logf("[socks5-udp] %s <- %s\n%s", conn.RemoteAddr(), cc.RemoteAddr(), reply)
	}

	if reply.Rep != gosocks5.Succeeded {
		log.Logf("[socks5-udp] %s <- %s : udp associate failed", conn.RemoteAddr(), cc.RemoteAddr())
		return
	}
	cc.SetReadDeadline(time.Time{})
	log.Logf("[socks5-udp] %s <-> %s [tun: %s]", conn.RemoteAddr(), socksAddr, reply.Addr)

	go h.tunnelClientUDP(relay, cc)
	log.Logf("[socks5-udp] %s <-> %s", conn.RemoteAddr(), socksAddr)
	if err := h.discardClientData(conn); err != nil {
		log.Logf("[socks5-udp] %s - %s : %s", conn.RemoteAddr(), socksAddr, err)
	}
	log.Logf("[socks5-udp] %s >-< %s", conn.RemoteAddr(), socksAddr)
}

func (h *socks5Handler) discardClientData(conn net.Conn) (err error) {
	b := make([]byte, tinyBufferSize)
	n := 0
	for {
		n, err = conn.Read(b) // discard any data from tcp connection
		if err != nil {
			if err == io.EOF { // disconnect normally
				err = nil
			}
			break // client disconnected
		}
		log.Logf("[socks5-udp] read %d UNEXPECTED TCP data from client", n)
	}
	return
}

func (h *socks5Handler) transportUDP(relay, peer *net.UDPConn) (err error) {
	errc := make(chan error, 2)

	var clientAddr *net.UDPAddr

	go func() {
		b := make([]byte, largeBufferSize)

		for {
			n, laddr, err := relay.ReadFromUDP(b)
			if err != nil {
				errc <- err
				return
			}
			if clientAddr == nil {
				clientAddr = laddr
			}
			dgram, err := gosocks5.ReadUDPDatagram(bytes.NewReader(b[:n]))
			if err != nil {
				errc <- err
				return
			}

			raddr, err := net.ResolveUDPAddr("udp", dgram.Header.Addr.String())
			if err != nil {
				continue // drop silently
			}
			if _, err := peer.WriteToUDP(dgram.Data, raddr); err != nil {
				errc <- err
				return
			}
			if Debug {
				log.Logf("[socks5-udp] %s >>> %s length: %d", relay.LocalAddr(), raddr, len(dgram.Data))
			}
		}
	}()

	go func() {
		b := make([]byte, largeBufferSize)

		for {
			n, raddr, err := peer.ReadFromUDP(b)
			if err != nil {
				errc <- err
				return
			}
			if clientAddr == nil {
				continue
			}
			buf := bytes.Buffer{}
			dgram := gosocks5.NewUDPDatagram(gosocks5.NewUDPHeader(0, 0, toSocksAddr(raddr)), b[:n])
			dgram.Write(&buf)
			if _, err := relay.WriteToUDP(buf.Bytes(), clientAddr); err != nil {
				errc <- err
				return
			}
			if Debug {
				log.Logf("[socks5-udp] %s <<< %s length: %d", relay.LocalAddr(), raddr, len(dgram.Data))
			}
		}
	}()

	select {
	case err = <-errc:
		//log.Println("w exit", err)
	}

	return
}

func (h *socks5Handler) tunnelClientUDP(uc *net.UDPConn, cc net.Conn) (err error) {
	errc := make(chan error, 2)

	var clientAddr *net.UDPAddr

	go func() {
		b := make([]byte, largeBufferSize)

		for {
			n, addr, err := uc.ReadFromUDP(b)
			if err != nil {
				log.Logf("[udp-tun] %s <- %s : %s", cc.RemoteAddr(), addr, err)
				errc <- err
				return
			}

			// glog.V(LDEBUG).Infof("read udp %d, % #x", n, b[:n])
			// pipe from relay to tunnel
			dgram, err := gosocks5.ReadUDPDatagram(bytes.NewReader(b[:n]))
			if err != nil {
				errc <- err
				return
			}
			if clientAddr == nil {
				clientAddr = addr
			}
			dgram.Header.Rsv = uint16(len(dgram.Data))
			if err := dgram.Write(cc); err != nil {
				errc <- err
				return
			}
			if Debug {
				log.Logf("[udp-tun] %s >>> %s length: %d", uc.LocalAddr(), dgram.Header.Addr, len(dgram.Data))
			}
		}
	}()

	go func() {
		for {
			dgram, err := gosocks5.ReadUDPDatagram(cc)
			if err != nil {
				log.Logf("[udp-tun] %s -> 0 : %s", cc.RemoteAddr(), err)
				errc <- err
				return
			}

			// pipe from tunnel to relay
			if clientAddr == nil {
				continue
			}
			dgram.Header.Rsv = 0

			buf := bytes.Buffer{}
			dgram.Write(&buf)
			if _, err := uc.WriteToUDP(buf.Bytes(), clientAddr); err != nil {
				errc <- err
				return
			}
			if Debug {
				log.Logf("[udp-tun] %s <<< %s length: %d", uc.LocalAddr(), dgram.Header.Addr, len(dgram.Data))
			}
		}
	}()

	select {
	case err = <-errc:
	}

	return
}

func (h *socks5Handler) handleUDPTunnel(conn net.Conn, req *gosocks5.Request) {
	// serve tunnel udp, tunnel <-> remote, handle tunnel udp request
	if h.options.Chain.IsEmpty() {
		addr := req.Addr.String()

		//! if !s.Base.Node.Can("rudp", addr) {
		//! 	glog.Errorf("Unauthorized to udp bind to %s", addr)
		//! 	return
		//! }

		bindAddr, _ := net.ResolveUDPAddr("udp", addr)
		uc, err := net.ListenUDP("udp", bindAddr)
		if err != nil {
			log.Logf("[socks5-udp] %s -> %s : %s", conn.RemoteAddr(), req.Addr, err)
			return
		}
		defer uc.Close()

		socksAddr := toSocksAddr(uc.LocalAddr())
		socksAddr.Host, _, _ = net.SplitHostPort(conn.LocalAddr().String())
		reply := gosocks5.NewReply(gosocks5.Succeeded, socksAddr)
		if err := reply.Write(conn); err != nil {
			log.Logf("[socks5-udp] %s <- %s : %s", conn.RemoteAddr(), socksAddr, err)
			return
		}
		if Debug {
			log.Logf("[socks5-udp] %s <- %s\n%s", conn.RemoteAddr(), socksAddr, reply)
		}
		log.Logf("[socks5-udp] %s <-> %s", conn.RemoteAddr(), socksAddr)
		h.tunnelServerUDP(conn, uc)
		log.Logf("[socks5-udp] %s >-< %s", conn.RemoteAddr(), socksAddr)
		return
	}

	cc, err := h.options.Chain.Conn()
	// connection error
	if err != nil {
		log.Logf("[socks5-udp] %s -> %s : %s", conn.RemoteAddr(), req.Addr, err)
		reply := gosocks5.NewReply(gosocks5.Failure, nil)
		reply.Write(conn)
		log.Logf("[socks5-udp] %s -> %s\n%s", conn.RemoteAddr(), req.Addr, reply)
		return
	}
	defer cc.Close()

	cc, err = socks5Handshake(cc, h.options.Chain.LastNode().User)
	if err != nil {
		log.Logf("[socks5-udp] %s -> %s : %s", conn.RemoteAddr(), req.Addr, err)
		return
	}
	// tunnel <-> tunnel, direct forwarding
	// note: this type of request forwarding is defined when starting server
	// so we don't need to authenticate it, as it's as explicit as whitelisting
	req.Write(cc)

	log.Logf("[socks5-udp] %s <-> %s [tun]", conn.RemoteAddr(), cc.RemoteAddr())
	transport(conn, cc)
	log.Logf("[socks5-udp] %s >-< %s [tun]", conn.RemoteAddr(), cc.RemoteAddr())
}

func socks5Handshake(conn net.Conn, user *url.Userinfo) (net.Conn, error) {
	selector := &clientSelector{
		TLSConfig: &tls.Config{InsecureSkipVerify: true},
		User:      user,
	}
	selector.AddMethod(
		gosocks5.MethodNoAuth,
		gosocks5.MethodUserPass,
		MethodTLS,
	)
	cc := gosocks5.ClientConn(conn, selector)
	if err := cc.Handleshake(); err != nil {
		return nil, err
	}
	return cc, nil
}

func (h *socks5Handler) tunnelServerUDP(cc net.Conn, uc *net.UDPConn) (err error) {
	errc := make(chan error, 2)

	go func() {
		b := make([]byte, largeBufferSize)

		for {
			n, addr, err := uc.ReadFromUDP(b)
			if err != nil {
				// log.Logf("[udp-tun] %s <- %s : %s", cc.RemoteAddr(), addr, err)
				errc <- err
				return
			}

			// pipe from peer to tunnel
			dgram := gosocks5.NewUDPDatagram(
				gosocks5.NewUDPHeader(uint16(n), 0, toSocksAddr(addr)), b[:n])
			if err := dgram.Write(cc); err != nil {
				log.Logf("[udp-tun] %s <- %s : %s", cc.RemoteAddr(), dgram.Header.Addr, err)
				errc <- err
				return
			}
			if Debug {
				log.Logf("[udp-tun] %s <<< %s length: %d", cc.RemoteAddr(), dgram.Header.Addr, len(dgram.Data))
			}
		}
	}()

	go func() {
		for {
			dgram, err := gosocks5.ReadUDPDatagram(cc)
			if err != nil {
				// log.Logf("[udp-tun] %s -> 0 : %s", cc.RemoteAddr(), err)
				errc <- err
				return
			}

			// pipe from tunnel to peer
			addr, err := net.ResolveUDPAddr("udp", dgram.Header.Addr.String())
			if err != nil {
				continue // drop silently
			}
			if _, err := uc.WriteToUDP(dgram.Data, addr); err != nil {
				log.Logf("[udp-tun] %s -> %s : %s", cc.RemoteAddr(), addr, err)
				errc <- err
				return
			}
			if Debug {
				log.Logf("[udp-tun] %s >>> %s length: %d", cc.RemoteAddr(), addr, len(dgram.Data))
			}
		}
	}()

	select {
	case err = <-errc:
	}

	return
}

func toSocksAddr(addr net.Addr) *gosocks5.Addr {
	host := "0.0.0.0"
	port := 0
	if addr != nil {
		h, p, _ := net.SplitHostPort(addr.String())
		host = h
		port, _ = strconv.Atoi(p)
	}
	return &gosocks5.Addr{
		Type: gosocks5.AddrIPv4,
		Host: host,
		Port: uint16(port),
	}
}

type socks4Handler struct {
	options *HandlerOptions
}

// SOCKS4Handler creates a server Handler for SOCKS4(A) proxy server.
func SOCKS4Handler(opts ...HandlerOption) Handler {
	options := &HandlerOptions{
		Chain: new(Chain),
	}
	for _, opt := range opts {
		opt(options)
	}
	return &socks4Handler{
		options: options,
	}
}

func (h *socks4Handler) Handle(conn net.Conn) {
	defer conn.Close()

	req, err := gosocks4.ReadRequest(conn)
	if err != nil {
		log.Log("[socks4]", err)
		return
	}

	if Debug {
		log.Logf("[socks4] %s -> %s\n%s", conn.RemoteAddr(), req.Addr, req)
	}

	switch req.Cmd {
	case gosocks4.CmdConnect:
		log.Logf("[socks4-connect] %s -> %s", conn.RemoteAddr(), req.Addr)
		h.handleConnect(conn, req)

	case gosocks4.CmdBind:
		log.Logf("[socks4-bind] %s - %s", conn.RemoteAddr(), req.Addr)
		h.handleBind(conn, req)

	default:
		log.Logf("[socks4] Unrecognized request: %d", req.Cmd)
	}
}

func (h *socks4Handler) handleConnect(conn net.Conn, req *gosocks4.Request) {
	addr := req.Addr.String()

	//! if !s.Base.Node.Can("tcp", addr) {
	//! 	glog.Errorf("Unauthorized to tcp connect to %s", addr)
	//! 	rep := gosocks5.NewReply(gosocks4.Rejected, nil)
	//! 	rep.Write(s.conn)
	//! 	return
	//! }

	cc, err := h.options.Chain.Dial(addr)
	if err != nil {
		log.Logf("[socks4-connect] %s -> %s : %s", conn.RemoteAddr(), req.Addr, err)
		rep := gosocks4.NewReply(gosocks4.Failed, nil)
		rep.Write(conn)
		if Debug {
			log.Logf("[socks4-connect] %s <- %s\n%s", conn.RemoteAddr(), req.Addr, rep)
		}
		return
	}
	defer cc.Close()

	rep := gosocks4.NewReply(gosocks4.Granted, nil)
	if err := rep.Write(conn); err != nil {
		log.Logf("[socks4-connect] %s <- %s : %s", conn.RemoteAddr(), req.Addr, err)
		return
	}
	if Debug {
		log.Logf("[socks4-connect] %s <- %s\n%s", conn.RemoteAddr(), req.Addr, rep)
	}

	log.Logf("[socks4-connect] %s <-> %s", conn.RemoteAddr(), req.Addr)
	transport(conn, cc)
	log.Logf("[socks4-connect] %s >-< %s", conn.RemoteAddr(), req.Addr)
}

func (h *socks4Handler) handleBind(conn net.Conn, req *gosocks4.Request) {
	// TODO: serve socks4 bind
	if h.options.Chain.IsEmpty() {
		reply := gosocks4.NewReply(gosocks4.Rejected, nil)
		reply.Write(conn)
		if Debug {
			log.Logf("[socks4-bind] %s <- %s\n%s", conn.RemoteAddr(), req.Addr, reply)
		}
		return
	}

	cc, err := h.options.Chain.Conn()
	// connection error
	if err != nil && err != ErrEmptyChain {
		log.Logf("[socks4-bind] %s <- %s : %s", conn.RemoteAddr(), req.Addr, err)
		reply := gosocks4.NewReply(gosocks4.Failed, nil)
		reply.Write(conn)
		if Debug {
			log.Logf("[socks4-bind] %s <- %s\n%s", conn.RemoteAddr(), req.Addr, reply)
		}
		return
	}

	defer cc.Close()
	// forward request
	req.Write(cc)

	log.Logf("[socks4-bind] %s <-> %s", conn.RemoteAddr(), cc.RemoteAddr())
	transport(conn, cc)
	log.Logf("[socks4-bind] %s >-< %s", conn.RemoteAddr(), cc.RemoteAddr())
}
