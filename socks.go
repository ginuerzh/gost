package gost

import (
	"bytes"
	"crypto/tls"
	"net"
	"net/url"
	"strconv"
	"time"

	"github.com/ginuerzh/gosocks4"
	"github.com/ginuerzh/gosocks5"
	"github.com/golang/glog"
)

const (
	MethodTLS     uint8 = 0x80 // extended method for tls
	MethodTLSAuth uint8 = 0x82 // extended method for tls+auth
)

const (
	CmdUdpTun uint8 = 0xF3 // extended method for udp over tcp
)

type clientSelector struct {
	methods   []uint8
	user      *url.Userinfo
	tlsConfig *tls.Config
}

func (selector *clientSelector) Methods() []uint8 {
	return selector.methods
}

func (selector *clientSelector) Select(methods ...uint8) (method uint8) {
	return
}

func (selector *clientSelector) OnSelected(method uint8, conn net.Conn) (net.Conn, error) {
	switch method {
	case MethodTLS:
		conn = tls.Client(conn, selector.tlsConfig)

	case gosocks5.MethodUserPass, MethodTLSAuth:
		if method == MethodTLSAuth {
			conn = tls.Client(conn, selector.tlsConfig)
		}

		var username, password string
		if selector.user != nil {
			username = selector.user.Username()
			password, _ = selector.user.Password()
		}

		req := gosocks5.NewUserPassRequest(gosocks5.UserPassVer, username, password)
		if err := req.Write(conn); err != nil {
			glog.V(LWARNING).Infoln("socks5 auth:", err)
			return nil, err
		}
		glog.V(LDEBUG).Infoln(req)

		resp, err := gosocks5.ReadUserPassResponse(conn)
		if err != nil {
			glog.V(LWARNING).Infoln("socks5 auth:", err)
			return nil, err
		}
		glog.V(LDEBUG).Infoln(resp)

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
	users     []*url.Userinfo
	tlsConfig *tls.Config
}

func (selector *serverSelector) Methods() []uint8 {
	return selector.methods
}

func (selector *serverSelector) Select(methods ...uint8) (method uint8) {
	glog.V(LDEBUG).Infof("%d %d %v", gosocks5.Ver5, len(methods), methods)

	method = gosocks5.MethodNoAuth
	for _, m := range methods {
		if m == MethodTLS {
			method = m
			break
		}
	}

	// when user/pass is set, auth is mandatory
	if selector.users != nil {
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
	glog.V(LDEBUG).Infof("%d %d", gosocks5.Ver5, method)

	switch method {
	case MethodTLS:
		conn = tls.Server(conn, selector.tlsConfig)

	case gosocks5.MethodUserPass, MethodTLSAuth:
		if method == MethodTLSAuth {
			conn = tls.Server(conn, selector.tlsConfig)
		}

		req, err := gosocks5.ReadUserPassRequest(conn)
		if err != nil {
			glog.V(LWARNING).Infoln("[socks5-auth]", err)
			return nil, err
		}
		glog.V(LDEBUG).Infoln("[socks5]", req.String())

		valid := false
		for _, user := range selector.users {
			username := user.Username()
			password, _ := user.Password()
			if (req.Username == username && req.Password == password) ||
				(req.Username == username && password == "") ||
				(username == "" && req.Password == password) {
				valid = true
				break
			}
		}
		if len(selector.users) > 0 && !valid {
			resp := gosocks5.NewUserPassResponse(gosocks5.UserPassVer, gosocks5.Failure)
			if err := resp.Write(conn); err != nil {
				glog.V(LWARNING).Infoln("[socks5-auth]", err)
				return nil, err
			}
			glog.V(LDEBUG).Infoln("[socks5]", resp)
			glog.V(LWARNING).Infoln("[socks5-auth] proxy authentication required")

			return nil, gosocks5.ErrAuthFailure
		}

		resp := gosocks5.NewUserPassResponse(gosocks5.UserPassVer, gosocks5.Succeeded)
		if err := resp.Write(conn); err != nil {
			glog.V(LWARNING).Infoln("[socks5-auth]", err)
			return nil, err
		}
		glog.V(LDEBUG).Infoln(resp)

	case gosocks5.MethodNoAcceptable:
		return nil, gosocks5.ErrBadMethod
	}

	return conn, nil
}

type Socks5Server struct {
	conn net.Conn
	Base *ProxyServer
}

func NewSocks5Server(conn net.Conn, base *ProxyServer) *Socks5Server {
	return &Socks5Server{conn: conn, Base: base}
}

func (s *Socks5Server) HandleRequest(req *gosocks5.Request) {
	glog.V(LDEBUG).Infof("[socks5] %s -> %s\n%s", s.conn.RemoteAddr(), req.Addr, req)

	switch req.Cmd {
	case gosocks5.CmdConnect:
		glog.V(LINFO).Infof("[socks5-connect] %s -> %s", s.conn.RemoteAddr(), req.Addr)
		s.handleConnect(req)

	case gosocks5.CmdBind:
		glog.V(LINFO).Infof("[socks5-bind] %s - %s", s.conn.RemoteAddr(), req.Addr)
		s.handleBind(req)

	case gosocks5.CmdUdp:
		glog.V(LINFO).Infof("[socks5-udp] %s - %s", s.conn.RemoteAddr(), req.Addr)
		s.handleUDPRelay(req)

	case CmdUdpTun:
		glog.V(LINFO).Infof("[socks5-rudp] %s - %s", s.conn.RemoteAddr(), req.Addr)
		s.handleUDPTunnel(req)

	default:
		glog.V(LWARNING).Infoln("[socks5] Unrecognized request:", req.Cmd)
	}
}

func (s *Socks5Server) handleConnect(req *gosocks5.Request) {
	addr := req.Addr.String()

	if !s.Base.Node.Can("tcp", addr) {
		glog.Errorf("Unauthorized to tcp connect to %s", addr)
		rep := gosocks5.NewReply(gosocks5.NotAllowed, nil)
		rep.Write(s.conn)
		return
	}

	cc, err := s.Base.Chain.Dial(addr)
	if err != nil {
		glog.V(LWARNING).Infof("[socks5-connect] %s -> %s : %s", s.conn.RemoteAddr(), req.Addr, err)
		rep := gosocks5.NewReply(gosocks5.HostUnreachable, nil)
		rep.Write(s.conn)
		glog.V(LDEBUG).Infof("[socks5-connect] %s <- %s\n%s", s.conn.RemoteAddr(), req.Addr, rep)
		return
	}
	defer cc.Close()

	rep := gosocks5.NewReply(gosocks5.Succeeded, nil)
	if err := rep.Write(s.conn); err != nil {
		glog.V(LWARNING).Infof("[socks5-connect] %s <- %s : %s", s.conn.RemoteAddr(), req.Addr, err)
		return
	}
	glog.V(LDEBUG).Infof("[socks5-connect] %s <- %s\n%s", s.conn.RemoteAddr(), req.Addr, rep)

	glog.V(LINFO).Infof("[socks5-connect] %s <-> %s", s.conn.RemoteAddr(), req.Addr)
	//Transport(conn, cc)
	s.Base.transport(s.conn, cc)
	glog.V(LINFO).Infof("[socks5-connect] %s >-< %s", s.conn.RemoteAddr(), req.Addr)
}

func (s *Socks5Server) handleBind(req *gosocks5.Request) {
	cc, err := s.Base.Chain.GetConn()

	// connection error when forwarding bind
	if err != nil && err != ErrEmptyChain {
		glog.V(LWARNING).Infof("[socks5-bind] %s <- %s : %s", s.conn.RemoteAddr(), req.Addr, err)
		reply := gosocks5.NewReply(gosocks5.Failure, nil)
		reply.Write(s.conn)
		glog.V(LDEBUG).Infof("[socks5-bind] %s <- %s\n%s", s.conn.RemoteAddr(), req.Addr, reply)
		return
	}

	// serve socks5 bind
	if err == ErrEmptyChain {
		addr := req.Addr.String()

		if !s.Base.Node.Can("rtcp", addr) {
			glog.Errorf("Unauthorized to tcp bind to %s", addr)
			return
		}

		s.bindOn(addr)

		return
	}

	// forward request
	// note: this type of request forwarding is defined when starting server
	// so we don't need to authenticate it, as it's as explicit as whitelisting
	defer cc.Close()
	req.Write(cc)
	glog.V(LINFO).Infof("[socks5-bind] %s <-> %s", s.conn.RemoteAddr(), cc.RemoteAddr())
	s.Base.transport(s.conn, cc)
	glog.V(LINFO).Infof("[socks5-bind] %s >-< %s", s.conn.RemoteAddr(), cc.RemoteAddr())
}

func (s *Socks5Server) handleUDPRelay(req *gosocks5.Request) {
	addr := req.Addr.String()

	if !s.Base.Node.Can("udp", addr) {
		glog.Errorf("Unauthorized to udp connect to %s", addr)
		rep := gosocks5.NewReply(gosocks5.NotAllowed, nil)
		rep.Write(s.conn)
		return
	}

	relay, err := net.ListenUDP("udp", nil)
	if err != nil {
		glog.V(LWARNING).Infof("[socks5-udp] %s -> %s : %s", s.conn.RemoteAddr(), relay.LocalAddr(), err)
		reply := gosocks5.NewReply(gosocks5.Failure, nil)
		reply.Write(s.conn)
		glog.V(LDEBUG).Infof("[socks5-udp] %s <- %s\n%s", s.conn.RemoteAddr(), relay.LocalAddr(), reply)
		return
	}
	defer relay.Close()

	socksAddr := ToSocksAddr(relay.LocalAddr())
	socksAddr.Host, _, _ = net.SplitHostPort(s.conn.LocalAddr().String()) // replace the IP to out-going interface's
	reply := gosocks5.NewReply(gosocks5.Succeeded, socksAddr)
	if err := reply.Write(s.conn); err != nil {
		glog.V(LWARNING).Infof("[socks5-udp] %s <- %s : %s", s.conn.RemoteAddr(), relay.LocalAddr(), err)
		return
	}
	glog.V(LDEBUG).Infof("[socks5-udp] %s <- %s\n%s", s.conn.RemoteAddr(), reply.Addr, reply)
	glog.V(LINFO).Infof("[socks5-udp] %s - %s BIND ON %s OK", s.conn.RemoteAddr(), relay.LocalAddr(), socksAddr)

	cc, err := s.Base.Chain.GetConn()
	// connection error
	if err != nil && err != ErrEmptyChain {
		glog.V(LWARNING).Infof("[socks5-udp] %s -> %s : %s", s.conn.RemoteAddr(), socksAddr, err)
		return
	}

	// serve as standard socks5 udp relay local <-> remote
	if err == ErrEmptyChain {
		peer, er := net.ListenUDP("udp", nil)
		if er != nil {
			glog.V(LWARNING).Infof("[socks5-udp] %s -> %s : %s", s.conn.RemoteAddr(), socksAddr, er)
			return
		}
		defer peer.Close()

		go s.transportUDP(relay, peer)
	}

	// forward udp local <-> tunnel
	if err == nil {
		defer cc.Close()

		cc.SetWriteDeadline(time.Now().Add(WriteTimeout))
		req := gosocks5.NewRequest(CmdUdpTun, nil)
		if err := req.Write(cc); err != nil {
			glog.V(LWARNING).Infoln("[socks5-udp] %s -> %s : %s", s.conn.RemoteAddr(), cc.RemoteAddr(), err)
			return
		}
		cc.SetWriteDeadline(time.Time{})
		glog.V(LDEBUG).Infof("[socks5-udp] %s -> %s\n%s", s.conn.RemoteAddr(), cc.RemoteAddr(), req)

		cc.SetReadDeadline(time.Now().Add(ReadTimeout))
		reply, err = gosocks5.ReadReply(cc)
		if err != nil {
			glog.V(LWARNING).Infoln("[socks5-udp] %s -> %s : %s", s.conn.RemoteAddr(), cc.RemoteAddr(), err)
			return
		}
		glog.V(LDEBUG).Infof("[socks5-udp] %s <- %s\n%s", s.conn.RemoteAddr(), cc.RemoteAddr(), reply)

		if reply.Rep != gosocks5.Succeeded {
			glog.V(LWARNING).Infoln("[socks5-udp] %s <- %s : udp associate failed", s.conn.RemoteAddr(), cc.RemoteAddr())
			return
		}
		cc.SetReadDeadline(time.Time{})
		glog.V(LINFO).Infof("[socks5-udp] %s <-> %s [tun: %s]", s.conn.RemoteAddr(), socksAddr, reply.Addr)

		go s.tunnelClientUDP(relay, cc)
	}

	glog.V(LINFO).Infof("[socks5-udp] %s <-> %s", s.conn.RemoteAddr(), socksAddr)
	b := make([]byte, SmallBufferSize)
	for {
		_, err := s.conn.Read(b) // discard any data from tcp connection
		if err != nil {
			glog.V(LWARNING).Infof("[socks5-udp] %s - %s : %s", s.conn.RemoteAddr(), socksAddr, err)
			break // client disconnected
		}
	}
	glog.V(LINFO).Infof("[socks5-udp] %s >-< %s", s.conn.RemoteAddr(), socksAddr)
}

func (s *Socks5Server) handleUDPTunnel(req *gosocks5.Request) {
	cc, err := s.Base.Chain.GetConn()

	// connection error
	if err != nil && err != ErrEmptyChain {
		glog.V(LWARNING).Infof("[socks5-rudp] %s -> %s : %s", s.conn.RemoteAddr(), req.Addr, err)
		reply := gosocks5.NewReply(gosocks5.Failure, nil)
		reply.Write(s.conn)
		glog.V(LDEBUG).Infof("[socks5-rudp] %s -> %s\n%s", s.conn.RemoteAddr(), req.Addr, reply)
		return
	}

	// serve tunnel udp, tunnel <-> remote, handle tunnel udp request
	if err == ErrEmptyChain {
		addr := req.Addr.String()

		if !s.Base.Node.Can("rudp", addr) {
			glog.Errorf("Unauthorized to udp bind to %s", addr)
			return
		}

		bindAddr, _ := net.ResolveUDPAddr("udp", addr)
		uc, err := net.ListenUDP("udp", bindAddr)
		if err != nil {
			glog.V(LWARNING).Infof("[socks5-rudp] %s -> %s : %s", s.conn.RemoteAddr(), req.Addr, err)
			return
		}
		defer uc.Close()

		socksAddr := ToSocksAddr(uc.LocalAddr())
		socksAddr.Host, _, _ = net.SplitHostPort(s.conn.LocalAddr().String())
		reply := gosocks5.NewReply(gosocks5.Succeeded, socksAddr)
		if err := reply.Write(s.conn); err != nil {
			glog.V(LWARNING).Infof("[socks5-rudp] %s <- %s : %s", s.conn.RemoteAddr(), socksAddr, err)
			return
		}
		glog.V(LDEBUG).Infof("[socks5-rudp] %s <- %s\n%s", s.conn.RemoteAddr(), socksAddr, reply)

		glog.V(LINFO).Infof("[socks5-rudp] %s <-> %s", s.conn.RemoteAddr(), socksAddr)
		s.tunnelServerUDP(s.conn, uc)
		glog.V(LINFO).Infof("[socks5-rudp] %s >-< %s", s.conn.RemoteAddr(), socksAddr)
		return
	}

	defer cc.Close()

	// tunnel <-> tunnel, direct forwarding
	// note: this type of request forwarding is defined when starting server
	// so we don't need to authenticate it, as it's as explicit as whitelisting
	req.Write(cc)

	glog.V(LINFO).Infof("[socks5-rudp] %s <-> %s [tun]", s.conn.RemoteAddr(), cc.RemoteAddr())
	s.Base.transport(s.conn, cc)
	glog.V(LINFO).Infof("[socks5-rudp] %s >-< %s [tun]", s.conn.RemoteAddr(), cc.RemoteAddr())
}

func (s *Socks5Server) bindOn(addr string) {
	bindAddr, _ := net.ResolveTCPAddr("tcp", addr)
	ln, err := net.ListenTCP("tcp", bindAddr) // strict mode: if the port already in use, it will return error
	if err != nil {
		glog.V(LWARNING).Infof("[socks5-bind] %s -> %s : %s", s.conn.RemoteAddr(), addr, err)
		gosocks5.NewReply(gosocks5.Failure, nil).Write(s.conn)
		return
	}

	socksAddr := ToSocksAddr(ln.Addr())
	// Issue: may not reachable when host has multi-interface
	socksAddr.Host, _, _ = net.SplitHostPort(s.conn.LocalAddr().String())
	reply := gosocks5.NewReply(gosocks5.Succeeded, socksAddr)
	if err := reply.Write(s.conn); err != nil {
		glog.V(LWARNING).Infof("[socks5-bind] %s <- %s : %s", s.conn.RemoteAddr(), addr, err)
		ln.Close()
		return
	}
	glog.V(LDEBUG).Infof("[socks5-bind] %s <- %s\n%s", s.conn.RemoteAddr(), addr, reply)
	glog.V(LINFO).Infof("[socks5-bind] %s - %s BIND ON %s OK", s.conn.RemoteAddr(), addr, socksAddr)

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

			errc <- s.Base.transport(s.conn, pc1)
		}()

		return errc
	}

	defer pc2.Close()

	for {
		select {
		case err := <-accept():
			if err != nil || pconn == nil {
				glog.V(LWARNING).Infof("[socks5-bind] %s <- %s : %s", s.conn.RemoteAddr(), addr, err)
				return
			}
			defer pconn.Close()

			reply := gosocks5.NewReply(gosocks5.Succeeded, ToSocksAddr(pconn.RemoteAddr()))
			if err := reply.Write(pc2); err != nil {
				glog.V(LWARNING).Infof("[socks5-bind] %s <- %s : %s", s.conn.RemoteAddr(), addr, err)
			}
			glog.V(LDEBUG).Infof("[socks5-bind] %s <- %s\n%s", s.conn.RemoteAddr(), addr, reply)
			glog.V(LINFO).Infof("[socks5-bind] %s <- %s PEER %s ACCEPTED", s.conn.RemoteAddr(), socksAddr, pconn.RemoteAddr())

			glog.V(LINFO).Infof("[socks5-bind] %s <-> %s", s.conn.RemoteAddr(), pconn.RemoteAddr())
			if err = s.Base.transport(pc2, pconn); err != nil {
				glog.V(LWARNING).Infoln(err)
			}
			glog.V(LINFO).Infof("[socks5-bind] %s >-< %s", s.conn.RemoteAddr(), pconn.RemoteAddr())
			return
		case err := <-pipe():
			glog.V(LWARNING).Infof("[socks5-bind] %s -> %s : %v", s.conn.RemoteAddr(), addr, err)
			ln.Close()
			return
		}
	}
}

func (s *Socks5Server) transportUDP(relay, peer *net.UDPConn) (err error) {
	errc := make(chan error, 2)

	var clientAddr *net.UDPAddr

	go func() {
		b := make([]byte, LargeBufferSize)

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
			glog.V(LDEBUG).Infof("[socks5-udp] %s >>> %s length: %d", relay.LocalAddr(), raddr, len(dgram.Data))
		}
	}()

	go func() {
		b := make([]byte, LargeBufferSize)

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
			dgram := gosocks5.NewUDPDatagram(gosocks5.NewUDPHeader(0, 0, ToSocksAddr(raddr)), b[:n])
			dgram.Write(&buf)
			if _, err := relay.WriteToUDP(buf.Bytes(), clientAddr); err != nil {
				errc <- err
				return
			}
			glog.V(LDEBUG).Infof("[socks5-udp] %s <<< %s length: %d", relay.LocalAddr(), raddr, len(dgram.Data))
		}
	}()

	select {
	case err = <-errc:
		//log.Println("w exit", err)
	}

	return
}

func (s *Socks5Server) tunnelClientUDP(uc *net.UDPConn, cc net.Conn) (err error) {
	errc := make(chan error, 2)

	var clientAddr *net.UDPAddr

	go func() {
		b := make([]byte, LargeBufferSize)

		for {
			n, addr, err := uc.ReadFromUDP(b)
			if err != nil {
				glog.V(LWARNING).Infof("[udp-tun] %s <- %s : %s", cc.RemoteAddr(), addr, err)
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
			glog.V(LDEBUG).Infof("[udp-tun] %s >>> %s length: %d", uc.LocalAddr(), dgram.Header.Addr, len(dgram.Data))
		}
	}()

	go func() {
		for {
			dgram, err := gosocks5.ReadUDPDatagram(cc)
			if err != nil {
				glog.V(LWARNING).Infof("[udp-tun] %s -> 0 : %s", cc.RemoteAddr(), err)
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
			glog.V(LDEBUG).Infof("[udp-tun] %s <<< %s length: %d", uc.LocalAddr(), dgram.Header.Addr, len(dgram.Data))
		}
	}()

	select {
	case err = <-errc:
	}

	return
}

func (s *Socks5Server) tunnelServerUDP(cc net.Conn, uc *net.UDPConn) (err error) {
	errc := make(chan error, 2)

	go func() {
		b := make([]byte, LargeBufferSize)

		for {
			n, addr, err := uc.ReadFromUDP(b)
			if err != nil {
				glog.V(LWARNING).Infof("[udp-tun] %s <- %s : %s", cc.RemoteAddr(), addr, err)
				errc <- err
				return
			}

			// pipe from peer to tunnel
			dgram := gosocks5.NewUDPDatagram(
				gosocks5.NewUDPHeader(uint16(n), 0, ToSocksAddr(addr)), b[:n])
			if err := dgram.Write(cc); err != nil {
				glog.V(LWARNING).Infof("[udp-tun] %s <- %s : %s", cc.RemoteAddr(), dgram.Header.Addr, err)
				errc <- err
				return
			}
			glog.V(LDEBUG).Infof("[udp-tun] %s <<< %s length: %d", cc.RemoteAddr(), dgram.Header.Addr, len(dgram.Data))
		}
	}()

	go func() {
		for {
			dgram, err := gosocks5.ReadUDPDatagram(cc)
			if err != nil {
				glog.V(LWARNING).Infof("[udp-tun] %s -> 0 : %s", cc.RemoteAddr(), err)
				errc <- err
				return
			}

			// pipe from tunnel to peer
			addr, err := net.ResolveUDPAddr("udp", dgram.Header.Addr.String())
			if err != nil {
				continue // drop silently
			}
			if _, err := uc.WriteToUDP(dgram.Data, addr); err != nil {
				glog.V(LWARNING).Infof("[udp-tun] %s -> %s : %s", cc.RemoteAddr(), addr, err)
				errc <- err
				return
			}
			glog.V(LDEBUG).Infof("[udp-tun] %s >>> %s length: %d", cc.RemoteAddr(), addr, len(dgram.Data))
		}
	}()

	select {
	case err = <-errc:
	}

	return
}

func ToSocksAddr(addr net.Addr) *gosocks5.Addr {
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

type Socks4Server struct {
	conn net.Conn
	Base *ProxyServer
}

func NewSocks4Server(conn net.Conn, base *ProxyServer) *Socks4Server {
	return &Socks4Server{conn: conn, Base: base}
}

func (s *Socks4Server) HandleRequest(req *gosocks4.Request) {
	glog.V(LDEBUG).Infof("[socks4] %s -> %s\n%s", s.conn.RemoteAddr(), req.Addr, req)

	switch req.Cmd {
	case gosocks4.CmdConnect:
		glog.V(LINFO).Infof("[socks4-connect] %s -> %s", s.conn.RemoteAddr(), req.Addr)
		s.handleConnect(req)

	case gosocks4.CmdBind:
		glog.V(LINFO).Infof("[socks4-bind] %s - %s", s.conn.RemoteAddr(), req.Addr)
		s.handleBind(req)

	default:
		glog.V(LWARNING).Infoln("[socks4] Unrecognized request:", req.Cmd)
	}
}

func (s *Socks4Server) handleConnect(req *gosocks4.Request) {
	addr := req.Addr.String()

	if !s.Base.Node.Can("tcp", addr) {
		glog.Errorf("Unauthorized to tcp connect to %s", addr)
		rep := gosocks5.NewReply(gosocks4.Rejected, nil)
		rep.Write(s.conn)
		return
	}

	cc, err := s.Base.Chain.Dial(addr)
	if err != nil {
		glog.V(LWARNING).Infof("[socks4-connect] %s -> %s : %s", s.conn.RemoteAddr(), req.Addr, err)
		rep := gosocks4.NewReply(gosocks4.Failed, nil)
		rep.Write(s.conn)
		glog.V(LDEBUG).Infof("[socks4-connect] %s <- %s\n%s", s.conn.RemoteAddr(), req.Addr, rep)
		return
	}
	defer cc.Close()

	rep := gosocks4.NewReply(gosocks4.Granted, nil)
	if err := rep.Write(s.conn); err != nil {
		glog.V(LWARNING).Infof("[socks4-connect] %s <- %s : %s", s.conn.RemoteAddr(), req.Addr, err)
		return
	}
	glog.V(LDEBUG).Infof("[socks4-connect] %s <- %s\n%s", s.conn.RemoteAddr(), req.Addr, rep)

	glog.V(LINFO).Infof("[socks4-connect] %s <-> %s", s.conn.RemoteAddr(), req.Addr)
	s.Base.transport(s.conn, cc)
	glog.V(LINFO).Infof("[socks4-connect] %s >-< %s", s.conn.RemoteAddr(), req.Addr)
}

func (s *Socks4Server) handleBind(req *gosocks4.Request) {
	cc, err := s.Base.Chain.GetConn()

	// connection error
	if err != nil && err != ErrEmptyChain {
		glog.V(LWARNING).Infof("[socks4-bind] %s <- %s : %s", s.conn.RemoteAddr(), req.Addr, err)
		reply := gosocks4.NewReply(gosocks4.Failed, nil)
		reply.Write(s.conn)
		glog.V(LDEBUG).Infof("[socks4-bind] %s <- %s\n%s", s.conn.RemoteAddr(), req.Addr, reply)
		return
	}
	// TODO: serve socks4 bind
	if err == ErrEmptyChain {
		//s.bindOn(req.Addr.String())
		return
	}

	defer cc.Close()
	// forward request
	req.Write(cc)

	glog.V(LINFO).Infof("[socks4-bind] %s <-> %s", s.conn.RemoteAddr(), cc.RemoteAddr())
	s.Base.transport(s.conn, cc)
	glog.V(LINFO).Infof("[socks4-bind] %s >-< %s", s.conn.RemoteAddr(), cc.RemoteAddr())
}
