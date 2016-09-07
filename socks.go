package main

import (
	//"bytes"
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
	CmdUdpTun uint8 = 0xf3 // extended method for udp over tcp
)

type clientSelector struct {
	methods []uint8
	user    *url.Userinfo
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
		conn = tls.Client(conn, &tls.Config{InsecureSkipVerify: true})

	case gosocks5.MethodUserPass, MethodTLSAuth:
		if method == MethodTLSAuth {
			conn = tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
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
	methods []uint8
	user    *url.Userinfo
	cert    tls.Certificate
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
		conn = tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{selector.cert}})

	case gosocks5.MethodUserPass, MethodTLSAuth:
		if method == MethodTLSAuth {
			conn = tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{selector.cert}})
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

func handleSocks5Request(req *gosocks5.Request, conn net.Conn) {
	glog.V(LDEBUG).Infof("[socks5] %s -> %s\n%s", conn.RemoteAddr(), req.Addr, req)

	switch req.Cmd {
	case gosocks5.CmdConnect:
		glog.V(LINFO).Infof("[socks5-connect] %s - %s", conn.RemoteAddr(), req.Addr)

		tconn, err := Connect(req.Addr.String())
		if err != nil {
			glog.V(LWARNING).Infof("[socks5-connect] %s -> %s : %s", conn.RemoteAddr(), req.Addr, err)
			rep := gosocks5.NewReply(gosocks5.HostUnreachable, nil)
			if err := rep.Write(conn); err != nil {
				glog.V(LWARNING).Infof("[socks5-connect] %s <- %s : %s", conn.RemoteAddr(), req.Addr, err)
			} else {
				glog.V(LDEBUG).Infof("[socks5-connect] %s <- %s\n%s", conn.RemoteAddr(), req.Addr, rep)
			}
			return
		}
		defer tconn.Close()

		rep := gosocks5.NewReply(gosocks5.Succeeded, nil)
		if err := rep.Write(conn); err != nil {
			glog.V(LWARNING).Infof("[socks5-connect] %s <- %s : %s", conn.RemoteAddr(), req.Addr, err)
			return
		}
		glog.V(LDEBUG).Infof("[socks5-connect] %s <- %s\n%s", conn.RemoteAddr(), req.Addr, rep)

		glog.V(LINFO).Infof("[socks5-connect] %s <-> %s", conn.RemoteAddr(), req.Addr)
		Transport(conn, tconn)
		glog.V(LINFO).Infof("[socks5-connect] %s >-< %s", conn.RemoteAddr(), req.Addr)

	case gosocks5.CmdBind:
		glog.V(LINFO).Infof("[socks5-bind] %s - %s", conn.RemoteAddr(), req.Addr)

		reply, fconn, err := socks5Bind(req, conn)
		if reply != nil {
			if err := reply.Write(conn); err != nil {
				glog.V(LWARNING).Infof("[socks5-bind] %s <- %s : %s", conn.RemoteAddr(), req.Addr, err)
				if fconn != nil {
					fconn.Close()
				}
				return
			}
			glog.V(LDEBUG).Infof("[socks5-bind] %s <- %s\n%s", conn.RemoteAddr(), req.Addr, reply)
		}

		if err != nil {
			glog.V(LWARNING).Infof("[socks5-bind] %s - %s : %s", conn.RemoteAddr(), req.Addr, err)
			return
		}
		defer fconn.Close()

		glog.V(LINFO).Infof("[socks5-bind] %s <-> %s", conn.RemoteAddr(), fconn.RemoteAddr())
		Transport(conn, fconn)
		glog.V(LINFO).Infof("[socks5-bind] %s >-< %s", conn.RemoteAddr(), fconn.RemoteAddr())

	case gosocks5.CmdUdp:
		glog.V(LINFO).Infof("[socks5-udp] %s - %s", conn.RemoteAddr(), req.Addr)
		socks5UDP(req, conn)

	case CmdUdpTun:
		glog.V(LINFO).Infof("[socks5-udp] %s - %s", conn.RemoteAddr(), req.Addr)
		if err := socks5TunnelUDP(req, conn); err != nil {
			glog.V(LWARNING).Infof("[socks5-udp] %s - %s : %s", conn.RemoteAddr(), req.Addr, err)
			rep := gosocks5.NewReply(gosocks5.Failure, nil)
			if err := rep.Write(conn); err != nil {
				glog.V(LWARNING).Infof("[socks5-udp] %s <- %s : %s", conn.RemoteAddr(), req.Addr, err)
			} else {
				glog.V(LDEBUG).Infof("[socks5-udp] %s <- %s\n%s", conn.RemoteAddr(), req.Addr, rep)
			}
			return
		}

	default:
		glog.V(LWARNING).Infoln("[socks5] Unrecognized request:", req.Cmd)
	}
}

func socks5UDP(req *gosocks5.Request, conn net.Conn) error {
	bindAddr, _ := net.ResolveUDPAddr("udp", req.Addr.String())
	relay, err := net.ListenUDP("udp", bindAddr) // udp associate, strict mode: if the port already in use, it will return error
	if err != nil {
		glog.V(LWARNING).Infof("[socks5-udp] %s -> %s : %s", conn.RemoteAddr(), req.Addr, err)

		rep := gosocks5.NewReply(gosocks5.Failure, nil)
		if err := rep.Write(conn); err != nil {
			glog.V(LWARNING).Infof("[socks5-udp] %s <- %s : %s", conn.RemoteAddr(), req.Addr, err)
		} else {
			glog.V(LDEBUG).Infof("[socks5-udp] %s <- %s\n%s", conn.RemoteAddr(), req.Addr, rep)
		}
		return err
	}
	defer relay.Close()

	addr := ToSocksAddr(relay.LocalAddr())
	addr.Host, _, _ = net.SplitHostPort(conn.LocalAddr().String())
	rep := gosocks5.NewReply(gosocks5.Succeeded, addr)
	if err := rep.Write(conn); err != nil {
		return err
	}
	glog.V(LDEBUG).Infof("[socks5-udp] %s <- %s\n%s", conn.RemoteAddr(), req.Addr, rep)

	glog.V(LINFO).Infof("[socks5-udp] %s - %s BIND ON %s OK", conn.RemoteAddr(), req.Addr, addr)

	if len(forwardArgs) > 0 { // client -> tunnel, tunnel udp over tcp
		tun, _, err := forwardChain(forwardArgs...)
		if err != nil {
			glog.V(LWARNING).Infof("[socks5-udp] %s -> %s : %s", conn.RemoteAddr(), req.Addr, err)
			return err
		}
		defer tun.Close()

		tun.SetWriteDeadline(time.Now().Add(time.Second * 90))
		if err := gosocks5.NewRequest(CmdUdpTun, nil).Write(tun); err != nil {
			glog.V(LWARNING).Infoln("[socks5-udp] %s -> %s : %s", conn.RemoteAddr(), req.Addr, err)
			return err
		}
		tun.SetWriteDeadline(time.Time{})

		tun.SetReadDeadline(time.Now().Add(time.Second * 90))
		rep, err := gosocks5.ReadReply(tun)
		if err != nil {
			glog.V(LWARNING).Infoln("[socks5-udp] %s -> %s : %s", conn.RemoteAddr(), req.Addr, err)
			return err
		}
		if rep.Rep != gosocks5.Succeeded {
			return errors.New("udp associate error")
		}
		tun.SetReadDeadline(time.Time{})

		glog.V(LINFO).Infof("[socks5-udp] %s <-> %s", conn.RemoteAddr(), req.Addr)
		go tunnelUDP(relay, tun, true)
	} else { // standard socks5 udp relay
		peer, err := net.ListenUDP("udp", nil)
		if err != nil {
			glog.V(LWARNING).Infof("[socks5-udp] %s -> %s : %s", conn.RemoteAddr(), req.Addr, err)
			return err
		}
		defer peer.Close()

		glog.V(LINFO).Infof("[socks5-udp] %s <-> %s", conn.RemoteAddr(), req.Addr)
		go transportUDP(relay, peer)
	}

	b := tcpPool.Get().([]byte)
	defer tcpPool.Put(b)
	for {
		_, err := conn.Read(b) // discard any data from tcp connection
		if err != nil {
			break // client disconnected
		}
	}
	glog.V(LINFO).Infof("[socks5-udp] %s >-< %s", conn.RemoteAddr(), req.Addr)
	return nil
}

func socks5TunnelUDP(req *gosocks5.Request, conn net.Conn) error {
	if len(forwardArgs) > 0 { // tunnel -> tunnel, direct forward
		tun, _, err := forwardChain(forwardArgs...)
		if err != nil {
			return err
		}
		defer tun.Close()

		if err := req.Write(tun); err != nil {
			return err
		}

		glog.V(LINFO).Infof("[socks5-udp] %s <-> %s[tun]", conn.RemoteAddr(), tun.RemoteAddr())
		Transport(conn, tun)
		glog.V(LINFO).Infof("[socks5-udp] %s >-< %s[tun]", conn.RemoteAddr(), tun.RemoteAddr())
	} else { // tunnel -> remote, handle tunnel udp request
		bindAddr, _ := net.ResolveUDPAddr("udp", req.Addr.String())
		uconn, err := net.ListenUDP("udp", bindAddr)
		if err != nil {
			return err
		}
		defer uconn.Close()

		addr := ToSocksAddr(uconn.LocalAddr())
		addr.Host, _, _ = net.SplitHostPort(conn.LocalAddr().String())
		rep := gosocks5.NewReply(gosocks5.Succeeded, addr)
		if err := rep.Write(conn); err != nil {
			return nil
		}
		glog.V(LDEBUG).Infof("[socks5-udp] %s <- %s\n%s", conn.RemoteAddr(), uconn.LocalAddr(), rep)

		glog.V(LINFO).Infof("[socks5-udp] %s <-> %s", conn.RemoteAddr(), uconn.LocalAddr())
		tunnelUDP(uconn, conn, false)
		glog.V(LINFO).Infof("[socks5-udp] %s >-< %s", conn.RemoteAddr(), uconn.LocalAddr())
	}
	return nil
}

func socks5Bind(req *gosocks5.Request, conn net.Conn) (*gosocks5.Reply, net.Conn, error) {
	if len(forwardArgs) > 0 {
		fconn, _, err := forwardChain(forwardArgs...)
		if err != nil {
			return gosocks5.NewReply(gosocks5.Failure, nil), nil, err
		}

		if err := req.Write(fconn); err != nil {
			fconn.Close()
			return gosocks5.NewReply(gosocks5.Failure, nil), nil, err
		}

		return nil, fconn, nil
	}

	bindAddr, _ := net.ResolveTCPAddr("tcp", req.Addr.String())
	ln, err := net.ListenTCP("tcp", bindAddr) // strict mode: if the port already in use, it will return error
	if err != nil {
		return gosocks5.NewReply(gosocks5.Failure, nil), nil, err
	}

	addr := ToSocksAddr(ln.Addr())
	// Issue: may not reachable when host has multi-interface
	addr.Host, _, _ = net.SplitHostPort(conn.LocalAddr().String())
	rep := gosocks5.NewReply(gosocks5.Succeeded, addr)
	if err := rep.Write(conn); err != nil {
		glog.V(LWARNING).Infof("[socks5-bind] %s <- %s : %s", conn.RemoteAddr(), req.Addr, err)
		ln.Close()
		return nil, nil, err
	}
	glog.V(LDEBUG).Infof("[socks5-bind] %s <- %s\n%s", conn.RemoteAddr(), req.Addr, rep)
	glog.V(LINFO).Infof("[socks5-bind] %s - %s BIND ON %s OK", conn.RemoteAddr(), req.Addr, addr)

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
		b := tcpPool.Get().([]byte)
		defer tcpPool.Put(b)
		_, err := conn.Read(b)
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
				return gosocks5.NewReply(gosocks5.Failure, nil), nil, errors.New("[socks5-bind] accept error")
			}
			pconn = c
			lnChan = nil
			ln = nil
			conn.SetReadDeadline(time.Now()) // timeout right now ,so we can break out of blocking
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
				return nil, nil, err
			}
			goto out
		}
	}

out:
	conn.SetReadDeadline(time.Time{})

	glog.V(LINFO).Infof("[socks5-bind] %s <- %s PEER %s ACCEPTED", conn.RemoteAddr(), addr, pconn.RemoteAddr())
	rep = gosocks5.NewReply(gosocks5.Succeeded, ToSocksAddr(pconn.RemoteAddr()))
	return rep, pconn, nil
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
