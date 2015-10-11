package main

import (
	"crypto/tls"
	"github.com/ginuerzh/gosocks5"
	"github.com/golang/glog"
	"net"
	"strconv"
)

const (
	MethodTLS     uint8 = 0x80 // extended method for tls
	MethodTLSAuth uint8 = 0x82 // extended method for tls+auth
)

type clientSelector struct {
	methods []uint8
	arg     Args
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
		if selector.arg.User != nil {
			username = selector.arg.User.Username()
			password, _ = selector.arg.User.Password()
		}

		req := gosocks5.NewUserPassRequest(gosocks5.UserPassVer, username, password)
		if err := req.Write(conn); err != nil {
			if glog.V(LWARNING) {
				glog.Warningln(err)
			}
			return nil, err
		}
		if glog.V(LDEBUG) {
			glog.Infoln(req)
		}

		res, err := gosocks5.ReadUserPassResponse(conn)
		if err != nil {
			if glog.V(LWARNING) {
				glog.Warningln(err)
			}
			return nil, err
		}
		if glog.V(LDEBUG) {
			glog.Infoln(res)
		}

		if res.Status != gosocks5.Succeeded {
			return nil, gosocks5.ErrAuthFailure
		}
	case gosocks5.MethodNoAcceptable:
		return nil, gosocks5.ErrBadMethod
	}

	return conn, nil
}

type serverSelector struct {
	methods []uint8
	arg     Args
}

func (selector *serverSelector) Methods() []uint8 {
	return selector.methods
}

func (selector *serverSelector) Select(methods ...uint8) (method uint8) {
	if glog.V(LDEBUG) {
		glog.Infof("%d %d % d", gosocks5.Ver5, len(methods), methods)
	}

	method = gosocks5.MethodNoAcceptable

	for _, m := range methods {
		for _, mm := range selector.methods {
			if m == mm {
				method = m
				goto out
			}
		}
	}

out:
	if method == gosocks5.MethodNoAcceptable {
		return
	}
	// when user/pass is set, auth is mandatory
	if selector.arg.User != nil {
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
	if glog.V(LDEBUG) {
		glog.Infof("%d %d", gosocks5.Ver5, method)
	}

	switch method {
	case MethodTLS:
		conn = tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{selector.arg.Cert}})

	case gosocks5.MethodUserPass, MethodTLSAuth:
		if method == MethodTLSAuth {
			conn = tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{selector.arg.Cert}})
		}

		req, err := gosocks5.ReadUserPassRequest(conn)
		if err != nil {
			if glog.V(LWARNING) {
				glog.Warningln(err)
			}
			return nil, err
		}
		if glog.V(LDEBUG) {
			glog.Infoln(req)
		}

		var username, password string
		if selector.arg.User != nil {
			username = selector.arg.User.Username()
			password, _ = selector.arg.User.Password()
		}

		if (username != "" && req.Username != username) || (password != "" && req.Password != password) {
			resp := gosocks5.NewUserPassResponse(gosocks5.UserPassVer, gosocks5.Failure)
			if err := resp.Write(conn); err != nil {
				if glog.V(LWARNING) {
					glog.Warningln(err)
				}
				return nil, err
			}
			if glog.V(LDEBUG) {
				glog.Infoln(resp)
			}
			return nil, gosocks5.ErrAuthFailure
		}

		resp := gosocks5.NewUserPassResponse(gosocks5.UserPassVer, gosocks5.Succeeded)
		if err := resp.Write(conn); err != nil {
			if glog.V(LWARNING) {
				glog.Warningln(err)
			}
			return nil, err
		}
		if glog.V(LDEBUG) {
			glog.Infoln(resp)
		}

	case gosocks5.MethodNoAcceptable:
		return nil, gosocks5.ErrBadMethod
	}

	return conn, nil
}

func requestSocks5(conn net.Conn, req *gosocks5.Request) (*gosocks5.Reply, error) {
	if err := req.Write(conn); err != nil {
		return nil, err
	}
	if glog.V(LDEBUG) {
		glog.Infoln(req.String())
	}
	rep, err := gosocks5.ReadReply(conn)
	if err != nil {
		return nil, err
	}
	if glog.V(LDEBUG) {
		glog.Infoln(rep.String())
	}
	return rep, nil
}

func handleSocks5Request(req *gosocks5.Request, conn net.Conn, arg Args) {
	if glog.V(LDEBUG) {
		glog.Infoln(req)
	}

	switch req.Cmd {
	case gosocks5.CmdConnect:
		if glog.V(LINFO) {
			glog.Infoln("socks5 connect:", req.Addr.String())
		}
		tconn, err := connect(ConnSocks5, req.Addr.String())
		if err != nil {
			if glog.V(LWARNING) {
				glog.Warningln("socks5 connect:", err)
			}
			rep := gosocks5.NewReply(gosocks5.HostUnreachable, nil)
			if err := rep.Write(conn); err != nil {
				if glog.V(LWARNING) {
					glog.Warningln("socks5 connect:", err)
				}
			} else {
				if glog.V(LDEBUG) {
					glog.Infoln(rep)
				}
			}
			return
		}
		defer tconn.Close()

		rep := gosocks5.NewReply(gosocks5.Succeeded, nil)
		if err := rep.Write(conn); err != nil {
			if glog.V(LWARNING) {
				glog.Warningln("socks5 connect:", err)
			}
			return
		} else {
			if glog.V(LDEBUG) {
				glog.Infoln(rep)
			}
		}
		Transport(conn, tconn)
	case gosocks5.CmdBind:
		l, err := net.ListenTCP("tcp", nil)
		if err != nil {
			if glog.V(LWARNING) {
				glog.Warningln("socks5 bind listen:", err)
			}
			rep := gosocks5.NewReply(gosocks5.Failure, nil)
			if err := rep.Write(conn); err != nil {
				if glog.V(LWARNING) {
					glog.Warningln("socks5 bind listen:", err)
				}
			} else {
				if glog.V(LDEBUG) {
					glog.Infoln(rep)
				}
			}
			return
		}

		addr := ToSocksAddr(l.Addr())
		addr.Host, _, _ = net.SplitHostPort(conn.LocalAddr().String())
		if glog.V(LINFO) {
			glog.Infoln("socks5 bind:", addr)
		}
		rep := gosocks5.NewReply(gosocks5.Succeeded, addr)
		if err := rep.Write(conn); err != nil {
			if glog.V(LWARNING) {
				glog.Warningln("socks5 bind:", err)
			}
			l.Close()
			return
		} else {
			if glog.V(LDEBUG) {
				glog.Infoln(rep)
			}
		}

		tconn, err := l.AcceptTCP()
		l.Close() // only accept one peer
		if err != nil {
			if glog.V(LWARNING) {
				glog.Warningln("socks5 bind accept:", err)
			}
			rep = gosocks5.NewReply(gosocks5.Failure, nil)
			if err := rep.Write(conn); err != nil {
				if glog.V(LWARNING) {
					glog.Warningln("socks5 bind accept:", err)
				}
			} else {
				if glog.V(LDEBUG) {
					glog.Infoln(rep)
				}
			}
			return
		}
		defer tconn.Close()

		addr = ToSocksAddr(tconn.RemoteAddr())
		if glog.V(LINFO) {
			glog.Infoln("socks5 bind accept:", addr.String())
		}
		rep = gosocks5.NewReply(gosocks5.Succeeded, addr)
		if err := rep.Write(conn); err != nil {
			if glog.V(LWARNING) {
				glog.Warningln("socks5 bind accept:", err)
			}
			return
		} else {
			if glog.V(LDEBUG) {
				glog.Infoln(rep)
			}
		}

		if err := Transport(conn, tconn); err != nil {
			//log.Println(err)
		}
	case gosocks5.CmdUdp:
		uconn, err := net.ListenUDP("udp", nil)
		if err != nil {
			if glog.V(LWARNING) {
				glog.Warningln("socks5 udp listen:", err)
			}
			rep := gosocks5.NewReply(gosocks5.Failure, nil)
			if err := rep.Write(conn); err != nil {
				if glog.V(LWARNING) {
					glog.Warningln("socks5 udp listen:", err)
				}
			} else {
				if glog.V(LDEBUG) {
					glog.Infoln(rep)
				}
			}
			return
		}
		defer uconn.Close()

		addr := ToSocksAddr(uconn.LocalAddr())
		addr.Host, _, _ = net.SplitHostPort(conn.LocalAddr().String())
		if glog.V(LINFO) {
			glog.Infoln("socks5 udp:", addr)
		}
		rep := gosocks5.NewReply(gosocks5.Succeeded, addr)
		if err := rep.Write(conn); err != nil {
			if glog.V(LWARNING) {
				glog.Warningln("socks5 udp:", err)
			}
			return
		} else {
			if glog.V(LDEBUG) {
				glog.Infoln(rep)
			}
		}
		srvTunnelUDP(conn, uconn)
	}
}

func srvTunnelUDP(conn net.Conn, uconn *net.UDPConn) {
	go func() {
		b := make([]byte, 16*1024)

		for {
			n, addr, err := uconn.ReadFromUDP(b)
			if err != nil {
				if glog.V(LWARNING) {
					glog.Warningln(err)
				}
				return
			}

			udp := gosocks5.NewUDPDatagram(
				gosocks5.NewUDPHeader(uint16(n), 0, ToSocksAddr(addr)), b[:n])
			//log.Println("r", udp.Header)
			if err := udp.Write(conn); err != nil {
				if glog.V(LWARNING) {
					glog.Warningln(err)
				}
				return
			}
		}
	}()

	for {
		udp, err := gosocks5.ReadUDPDatagram(conn)
		if err != nil {
			if glog.V(LWARNING) {
				glog.Warningln(err)
			}
			return
		}
		//log.Println("w", udp.Header)
		addr, err := net.ResolveUDPAddr("udp", udp.Header.Addr.String())
		if err != nil {
			if glog.V(LWARNING) {
				glog.Warningln(err)
			}
			continue // drop silently
		}

		if _, err := uconn.WriteToUDP(udp.Data, addr); err != nil {
			if glog.V(LWARNING) {
				glog.Warningln(err)
			}
			return
		}
	}
}

func ToSocksAddr(addr net.Addr) *gosocks5.Addr {
	host, port, _ := net.SplitHostPort(addr.String())
	p, _ := strconv.Atoi(port)

	return &gosocks5.Addr{
		Type: gosocks5.AddrIPv4,
		Host: host,
		Port: uint16(p),
	}
}
