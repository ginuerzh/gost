package gost

import (
	"bytes"
	"crypto/tls"
	"errors"
	"github.com/ginuerzh/gosocks5"
	"github.com/golang/glog"
	//"os/exec"
	//"io"
	//"io/ioutil"
	"net"
	"net/url"
	"strconv"
	"time"
)

const (
	MethodTLS     uint8 = 0x80 // extended method for tls
	MethodTLSAuth uint8 = 0x82 // extended method for tls+auth
)

const (
	CmdUdpConnect uint8 = 0xF1 // extended method for udp local port forwarding
	CmdUdpTun     uint8 = 0xF3 // extended method for udp over tcp
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
	user      *url.Userinfo
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
	if selector.user != nil {
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

		var username, password string
		if selector.user != nil {
			username = selector.user.Username()
			password, _ = selector.user.Password()
		}

		if (username != "" && req.Username != username) || (password != "" && req.Password != password) {
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
	glog.V(LDEBUG).Infof("[socks5] %s - %s\n%s", s.conn.RemoteAddr(), req.Addr, req)

	switch req.Cmd {
	case gosocks5.CmdConnect:
		glog.V(LINFO).Infof("[socks5-connect] %s -> %s", s.conn.RemoteAddr(), req.Addr)
		s.handleConnect(req)

	case gosocks5.CmdBind:
		glog.V(LINFO).Infof("[socks5-bind] %s - %s", s.conn.RemoteAddr(), req.Addr)
		s.handleBind(req)

	case CmdUdpConnect:
		glog.V(LINFO).Infof("[udp] %s - %s", s.conn.RemoteAddr(), req.Addr)
		s.handleUDPConnect(req)

	case gosocks5.CmdUdp:
		glog.V(LINFO).Infof("[socks5-udp] %s - %s", s.conn.RemoteAddr(), req.Addr)
		s.handleUDPRelay(req)

	case CmdUdpTun:
		glog.V(LINFO).Infof("[socks5-udp] %s - %s", s.conn.RemoteAddr(), req.Addr)
		s.handleUDPTunnel(req)

	default:
		glog.V(LWARNING).Infoln("[socks5] Unrecognized request:", req.Cmd)
	}
}

func (s *Socks5Server) handleConnect(req *gosocks5.Request) {
	cc, err := s.Base.Chain.Dial(req.Addr.String())
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
	// forward request
	if err == nil {
		req.Write(cc)
	}
	// connection error
	if err != nil && err != ErrEmptyChain {
		glog.V(LWARNING).Infof("[socks5-bind] %s <- %s : %s", s.conn.RemoteAddr(), req.Addr, err)
		reply := gosocks5.NewReply(gosocks5.Failure, nil)
		reply.Write(s.conn)
		glog.V(LDEBUG).Infof("[socks5-bind] %s <- %s\n%s", s.conn.RemoteAddr(), req.Addr, reply)
		return
	}
	// serve socks5 bind
	if err == ErrEmptyChain {
		cc, err = s.bind(req.Addr.String())
		if err != nil {
			glog.V(LWARNING).Infof("[socks5-bind] %s <- %s : %s", s.conn.RemoteAddr(), req.Addr, err)
			reply := gosocks5.NewReply(gosocks5.Failure, nil)
			reply.Write(s.conn)
			glog.V(LDEBUG).Infof("[socks5-bind] %s <- %s\n%s", s.conn.RemoteAddr(), req.Addr, reply)
			return
		}
	}

	defer cc.Close()

	glog.V(LINFO).Infof("[socks5-bind] %s <-> %s", s.conn.RemoteAddr(), cc.RemoteAddr())
	s.Base.transport(s.conn, cc)
	glog.V(LINFO).Infof("[socks5-bind] %s >-< %s", s.conn.RemoteAddr(), cc.RemoteAddr())
}

func (s *Socks5Server) handleUDPConnect(req *gosocks5.Request) {
	cc, err := s.Base.Chain.GetConn()

	// connection error
	if err != nil && err != ErrEmptyChain {
		glog.V(LWARNING).Infof("[udp] %s <- %s : %s", s.conn.RemoteAddr(), req.Addr, err)
		reply := gosocks5.NewReply(gosocks5.Failure, nil)
		reply.Write(s.conn)
		glog.V(LDEBUG).Infof("[udp] %s <- %s\n%s", s.conn.RemoteAddr(), req.Addr, reply)
		return
	}

	// serve udp connect
	if err == ErrEmptyChain {
		s.udpConnect(req.Addr.String())
		return
	}

	defer cc.Close()

	// forward request
	if err := req.Write(cc); err != nil {
		glog.V(LINFO).Infof("[udp] %s -> %s : %s", s.conn.RemoteAddr(), req.Addr, err)
		gosocks5.NewReply(gosocks5.Failure, nil).Write(s.conn)
		return
	}

	glog.V(LINFO).Infof("[udp] %s <-> %s", s.conn.RemoteAddr(), req.Addr)
	s.Base.transport(s.conn, cc)
	glog.V(LINFO).Infof("[udp] %s >-< %s", s.conn.RemoteAddr(), req.Addr)
}

func (s *Socks5Server) handleUDPRelay(req *gosocks5.Request) {
	bindAddr, _ := net.ResolveUDPAddr("udp", req.Addr.String())
	relay, err := net.ListenUDP("udp", bindAddr) // udp associate, strict mode: if the port already in use, it will return error
	if err != nil {
		glog.V(LWARNING).Infof("[socks5-udp] %s -> %s : %s", s.conn.RemoteAddr(), req.Addr, err)
		reply := gosocks5.NewReply(gosocks5.Failure, nil)
		reply.Write(s.conn)
		glog.V(LDEBUG).Infof("[socks5-udp] %s <- %s\n%s", s.conn.RemoteAddr(), req.Addr, reply)
		return
	}
	defer relay.Close()

	socksAddr := ToSocksAddr(relay.LocalAddr())
	socksAddr.Host, _, _ = net.SplitHostPort(s.conn.LocalAddr().String())
	reply := gosocks5.NewReply(gosocks5.Succeeded, socksAddr)
	if err := reply.Write(s.conn); err != nil {
		glog.V(LWARNING).Infof("[socks5-udp] %s <- %s : %s", s.conn.RemoteAddr(), req.Addr, err)
		return
	}
	glog.V(LDEBUG).Infof("[socks5-udp] %s <- %s\n%s", s.conn.RemoteAddr(), reply.Addr, reply)
	glog.V(LINFO).Infof("[socks5-udp] %s - %s BIND ON %s OK", s.conn.RemoteAddr(), req.Addr, socksAddr)

	cc, err := s.Base.Chain.GetConn()
	// connection error
	if err != nil && err != ErrEmptyChain {
		glog.V(LWARNING).Infof("[udp] %s -> %s : %s", s.conn.RemoteAddr(), req.Addr, err)
		return
	}

	// serve as standard socks5 udp relay
	if err == ErrEmptyChain {
		peer, err := net.ListenUDP("udp", nil)
		if err != nil {
			glog.V(LWARNING).Infof("[socks5-udp] %s -> %s : %s", s.conn.RemoteAddr(), req.Addr, err)
			return
		}
		defer peer.Close()
		go s.transportUDP(relay, peer)
	}

	if err == nil {
		defer cc.Close()

		cc.SetWriteDeadline(time.Now().Add(WriteTimeout))
		if err := gosocks5.NewRequest(CmdUdpTun, nil).Write(cc); err != nil {
			glog.V(LWARNING).Infoln("[socks5-udp] %s -> %s : %s", s.conn.RemoteAddr(), req.Addr, err)
			return
		}
		cc.SetWriteDeadline(time.Time{})

		cc.SetReadDeadline(time.Now().Add(ReadTimeout))
		reply, err = gosocks5.ReadReply(cc)
		if err != nil {
			glog.V(LWARNING).Infoln("[socks5-udp] %s -> %s : %s", s.conn.RemoteAddr(), req.Addr, err)
			return
		}
		if reply.Rep != gosocks5.Succeeded {
			glog.V(LWARNING).Infoln("[socks5-udp] %s -> %s : udp associate error", s.conn.RemoteAddr(), req.Addr)
			return
		}
		cc.SetReadDeadline(time.Time{})
		go s.tunnelUDP(relay, cc, true)
	}

	glog.V(LINFO).Infof("[socks5-udp] %s <-> %s", s.conn.RemoteAddr(), req.Addr)
	b := make([]byte, SmallBufferSize)
	for {
		_, err := s.conn.Read(b) // discard any data from tcp connection
		if err != nil {
			break // client disconnected
		}
	}
	glog.V(LINFO).Infof("[socks5-udp] %s >-< %s", s.conn.RemoteAddr(), req.Addr)
}

func (s *Socks5Server) handleUDPTunnel(req *gosocks5.Request) {
	cc, err := s.Base.Chain.GetConn()

	// connection error
	if err != nil && err != ErrEmptyChain {
		glog.V(LWARNING).Infof("[socks5-udp] %s <- %s : %s", s.conn.RemoteAddr(), req.Addr, err)
		reply := gosocks5.NewReply(gosocks5.Failure, nil)
		reply.Write(s.conn)
		glog.V(LDEBUG).Infof("[socks5-udp] %s <- %s\n%s", s.conn.RemoteAddr(), req.Addr, reply)
		return
	}

	// serve tunnel udp, tunnel <-> remote, handle tunnel udp request
	if err == ErrEmptyChain {
		bindAddr, _ := net.ResolveUDPAddr("udp", req.Addr.String())
		uc, err := net.ListenUDP("udp", bindAddr)
		if err != nil {
			glog.V(LWARNING).Infof("[socks5-udp] %s <- %s : %s", s.conn.RemoteAddr(), req.Addr, err)
			return
		}
		defer uc.Close()

		socksAddr := ToSocksAddr(uc.LocalAddr())
		socksAddr.Host, _, _ = net.SplitHostPort(s.conn.LocalAddr().String())
		reply := gosocks5.NewReply(gosocks5.Succeeded, socksAddr)
		if err := reply.Write(s.conn); err != nil {
			glog.V(LWARNING).Infof("[socks5-udp] %s <- %s : %s", s.conn.RemoteAddr(), req.Addr, err)
			return
		}
		glog.V(LDEBUG).Infof("[socks5-udp] %s <- %s\n%s", s.conn.RemoteAddr(), uc.LocalAddr(), reply)

		glog.V(LINFO).Infof("[socks5-udp] %s <-> %s", s.conn.RemoteAddr(), uc.LocalAddr())
		s.tunnelUDP(uc, s.conn, false)
		glog.V(LINFO).Infof("[socks5-udp] %s >-< %s", s.conn.RemoteAddr(), uc.LocalAddr())
		return
	}

	defer cc.Close()

	// tunnel <-> tunnel, direct forwarding
	req.Write(cc)

	glog.V(LINFO).Infof("[socks5-udp] %s <-> %s[tun]", s.conn.RemoteAddr(), cc.RemoteAddr())
	s.Base.transport(s.conn, cc)
	glog.V(LINFO).Infof("[socks5-udp] %s >-< %s[tun]", s.conn.RemoteAddr(), cc.RemoteAddr())
}

func (s *Socks5Server) bind(addr string) (net.Conn, error) {
	bindAddr, _ := net.ResolveTCPAddr("tcp", addr)
	ln, err := net.ListenTCP("tcp", bindAddr) // strict mode: if the port already in use, it will return error
	if err != nil {
		return nil, err
	}

	socksAddr := ToSocksAddr(ln.Addr())
	// Issue: may not reachable when host has multi-interface
	socksAddr.Host, _, _ = net.SplitHostPort(s.conn.LocalAddr().String())
	reply := gosocks5.NewReply(gosocks5.Succeeded, socksAddr)
	if err := reply.Write(s.conn); err != nil {
		glog.V(LWARNING).Infof("[socks5-bind] %s <- %s : %s", s.conn.RemoteAddr(), addr, err)
		ln.Close()
		return nil, err
	}
	glog.V(LDEBUG).Infof("[socks5-bind] %s <- %s\n%s", s.conn.RemoteAddr(), addr, reply)
	glog.V(LINFO).Infof("[socks5-bind] %s - %s BIND ON %s OK", s.conn.RemoteAddr(), addr, socksAddr)

	lnChan := make(chan net.Conn, 1)
	go func() {
		defer close(lnChan)
		c, err := ln.AcceptTCP()
		if err != nil {
			return
		}
		lnChan <- c
	}()

	peerChan := make(chan error, 1)
	go func() {
		defer close(peerChan)
		b := make([]byte, SmallBufferSize)
		_, err := s.conn.Read(b)
		if err != nil {
			if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
				return
			}
			peerChan <- err
		}
	}()

	var pconn net.Conn

	for {
		select {
		case c := <-lnChan:
			ln.Close() // only accept one peer
			if c == nil {
				return nil, errors.New("accept error")
			}
			pconn = c
			lnChan = nil
			ln = nil
			// TODO: implement deadline
			s.conn.SetReadDeadline(time.Now()) // timeout right now ,so we can break out of blocking
		case err := <-peerChan:
			if err != nil || pconn == nil {
				if ln != nil {
					ln.Close()
				}
				if pconn != nil {
					pconn.Close()
				}
				if err == nil {
					err = errors.New("Oops, some mysterious error!")
				}
				return nil, err
			}
			goto out
		}
	}

out:
	s.conn.SetReadDeadline(time.Time{})

	glog.V(LINFO).Infof("[socks5-bind] %s <- %s PEER %s ACCEPTED", s.conn.RemoteAddr(), socksAddr, pconn.RemoteAddr())
	return pconn, nil
}

func (s *Socks5Server) udpConnect(addr string) {
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		glog.V(LINFO).Infof("[udp] %s -> %s : %s", s.conn.RemoteAddr(), addr, err)
		gosocks5.NewReply(gosocks5.Failure, nil).Write(s.conn)
		return
	}

	if err := gosocks5.NewReply(gosocks5.Succeeded, nil).Write(s.conn); err != nil {
		glog.V(LINFO).Infof("[udp] %s <- %s : %s", s.conn.RemoteAddr(), addr, err)
		return
	}

	glog.V(LINFO).Infof("[udp] %s <-> %s", s.conn.RemoteAddr(), raddr)
	defer glog.V(LINFO).Infof("[udp] %s >-< %s", s.conn.RemoteAddr(), raddr)

	for {
		dgram, err := gosocks5.ReadUDPDatagram(s.conn)
		if err != nil {
			glog.V(LWARNING).Infof("[udp] %s -> %s : %s", s.conn.RemoteAddr(), addr, err)
			return
		}

		go func() {
			b := make([]byte, LargeBufferSize)

			relay, err := net.DialUDP("udp", nil, raddr)
			if err != nil {
				glog.V(LWARNING).Infof("[udp] %s -> %s : %s", s.conn.RemoteAddr(), raddr, err)
				return
			}
			defer relay.Close()

			if _, err := relay.Write(dgram.Data); err != nil {
				glog.V(LWARNING).Infof("[udp] %s -> %s : %s", s.conn.RemoteAddr(), raddr, err)
				return
			}
			glog.V(LDEBUG).Infof("[udp-tun] %s >>> %s length: %d", s.conn.RemoteAddr(), raddr, len(dgram.Data))

			relay.SetReadDeadline(time.Now().Add(time.Second * 60))
			n, err := relay.Read(b)
			if err != nil {
				glog.V(LWARNING).Infof("[udp] %s <- %s : %s", s.conn.RemoteAddr(), raddr, err)
				return
			}
			relay.SetReadDeadline(time.Time{})

			glog.V(LDEBUG).Infof("[udp-tun] %s <<< %s length: %d", s.conn.RemoteAddr(), raddr, n)

			s.conn.SetWriteDeadline(time.Now().Add(time.Second * 90))
			if err := gosocks5.NewUDPDatagram(gosocks5.NewUDPHeader(uint16(n), 0, dgram.Header.Addr), b[:n]).Write(s.conn); err != nil {
				glog.V(LWARNING).Infof("[udp] %s <- %s : %s", s.conn.RemoteAddr(), raddr, err)
				return
			}
			s.conn.SetWriteDeadline(time.Time{})
		}()
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

func (s *Socks5Server) tunnelUDP(uc *net.UDPConn, cc net.Conn, client bool) (err error) {
	errc := make(chan error, 2)

	var clientAddr *net.UDPAddr

	go func() {
		b := make([]byte, LargeBufferSize)

		for {
			n, addr, err := uc.ReadFromUDP(b)
			if err != nil {
				errc <- err
				return
			}

			var dgram *gosocks5.UDPDatagram
			if client { // pipe from relay to tunnel
				dgram, err = gosocks5.ReadUDPDatagram(bytes.NewReader(b[:n]))
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
			} else { // pipe from peer to tunnel
				dgram = gosocks5.NewUDPDatagram(
					gosocks5.NewUDPHeader(uint16(n), 0, ToSocksAddr(addr)), b[:n])
				if err := dgram.Write(cc); err != nil {
					errc <- err
					return
				}
				glog.V(LDEBUG).Infof("[udp-tun] %s <<< %s length: %d", cc.RemoteAddr(), dgram.Header.Addr, len(dgram.Data))
			}
		}
	}()

	go func() {
		for {
			dgram, err := gosocks5.ReadUDPDatagram(cc)
			if err != nil {
				errc <- err
				return
			}

			if client { // pipe from tunnel to relay
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
			} else { // pipe from tunnel to peer
				addr, err := net.ResolveUDPAddr("udp", dgram.Header.Addr.String())
				if err != nil {
					continue // drop silently
				}
				if _, err := uc.WriteToUDP(dgram.Data, addr); err != nil {
					errc <- err
					return
				}
				glog.V(LDEBUG).Infof("[udp-tun] %s >>> %s length: %d", cc.RemoteAddr(), addr, len(dgram.Data))
			}
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
