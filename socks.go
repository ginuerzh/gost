package main

import (
	"bytes"
	"crypto/tls"
	"errors"
	"github.com/ginuerzh/gosocks5"
	"github.com/golang/glog"
	"io"
	"io/ioutil"
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
				glog.Warningln("socks5 auth:", err)
			}
			return nil, err
		}
		if glog.V(LDEBUG) {
			glog.Infoln(req)
		}

		res, err := gosocks5.ReadUserPassResponse(conn)
		if err != nil {
			if glog.V(LWARNING) {
				glog.Warningln("socks5 auth:", err)
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

	method = gosocks5.MethodNoAuth
	for _, m := range methods {
		if m == MethodTLS {
			method = m
			break
		}
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
				glog.Warningln("socks5 auth:", err)
			}
			return nil, err
		}
		if glog.V(LDEBUG) {
			glog.Infoln(req.String())
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
					glog.Warningln("socks5 auth:", err)
				}
				return nil, err
			}
			if glog.V(LDEBUG) {
				glog.Infoln(resp)
			}
			if glog.V(LWARNING) {
				glog.Warningln("socks5: proxy authentication required")
			}
			return nil, gosocks5.ErrAuthFailure
		}

		resp := gosocks5.NewUserPassResponse(gosocks5.UserPassVer, gosocks5.Succeeded)
		if err := resp.Write(conn); err != nil {
			if glog.V(LWARNING) {
				glog.Warningln("socks5 auth:", err)
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

func handleSocks5Request(req *gosocks5.Request, conn net.Conn) {
	if glog.V(LDEBUG) {
		glog.Infoln(req)
	}

	switch req.Cmd {
	case gosocks5.CmdConnect:
		if glog.V(LINFO) {
			glog.Infoln("socks5 connect:", req.Addr.String())
		}
		tconn, err := Connect(req.Addr.String())
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
		}
		if glog.V(LDEBUG) {
			glog.Infoln(rep)
		}

		Transport(conn, tconn)
	case gosocks5.CmdBind:
		if glog.V(LINFO) {
			glog.Infoln("socks5 bind:", req.Addr)
		}
		if len(forwardArgs) > 0 {
			forwardBind(req, conn)
		} else {
			serveBind(conn)
		}
	case gosocks5.CmdUdp:
		if glog.V(LINFO) {
			glog.Infoln("socks5 udp associate:", req.Addr)
		}
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
			glog.Infoln("socks5 udp listen:", addr)
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

		clientConn, dgram, err := createClientConn(conn, uconn)
		if err != nil {
			if glog.V(LWARNING) {
				glog.Warningln("socks5 udp:", err)
			}
			return
		}
		if glog.V(LDEBUG) {
			glog.Infof("[udp] length %d, to %s", len(dgram.Data), dgram.Header.Addr)
		}

		serverConn, err := createServerConn(uconn)
		if err != nil {
			if glog.V(LWARNING) {
				glog.Warningln("socks5 udp forward:", err)
			}
		}
	default:
		if glog.V(LWARNING) {
			glog.Warningln("Unrecognized request: ", req)
		}
	}
}

func createClientConn(conn net.Conn, uconn *net.UDPConn) (c *UDPConn, dgram *gosocks5.UDPDatagram, err error) {
	var raddr *net.UDPAddr
	dgramChan := make(chan *gosocks5.UDPDatagram, 1)
	errChan := make(chan error, 1)
	go func() {
		b := make([]byte, 64*1024+262)

		n, addr, err := uconn.ReadFromUDP(b)
		if err != nil {
			errChan <- err
			return
		}
		raddr = addr

		dgram, err := gosocks5.ReadUDPDatagram(bytes.NewReader(b[:n]))
		if err != nil {
			errChan <- err
			return
		}
		dgramChan <- dgram
	}()

	go func() {
		dgram, err := gosocks5.ReadUDPDatagram(conn)
		if err != nil {
			errChan <- err
			return
		}
		dgramChan <- dgram
	}()

	select {
	case dgram = <-dgramChan:
		if raddr != nil {
			c = Client(uconn, raddr)
		} else {
			c = Client(conn, nil)
		}
	case err = <-errChan:
	}

	return
}

func createServerConn(uconn *net.UDPConn) (c *UDPConn, err error) {
	if len(forwardArgs) == 0 {
		c = Server(uconn)
		return
	}

	fconn, _, err := forwardChain(forwardArgs...)
	if err != nil {
		if fconn != nil {
			fconn.Close()
		}
		return
	}

	c = Server(fconn)
	return
}

func forwardUDP(req *gosocks5.Request) (conn net.Conn, err error) {

	if err != nil {
		if conn != nil {
			conn.Close()
		}
		rep := gosocks5.NewReply(gosocks5.Failure, nil)
		if err := rep.Write(conn); err != nil {
			if glog.V(LWARNING) {
				glog.Warningln("socks5 udp forward:", err)
			}
		} else {
			if glog.V(LDEBUG) {
				glog.Infoln(rep)
			}
		}
		return
	}

	if err = req.Write(fconn); err != nil {
		if glog.V(LWARNING) {
			glog.Warningln("socks5 udp forward:", err)
		}
		return
	}

	if err = peekReply(conn, fconn); err != nil {
		if glog.V(LWARNING) {
			glog.Warningln("socks5 udp forward:", err)
		}
		return
	}

}

func transportUDP() {

}

func serveBind(conn net.Conn) error {
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
		return err
	}

	addr := ToSocksAddr(l.Addr())
	// Issue: may not reachable when host has two interfaces
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
		return err
	}
	if glog.V(LDEBUG) {
		glog.Infoln(rep)
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
		return err
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
		return err
	}
	if glog.V(LDEBUG) {
		glog.Infoln(rep)
	}

	return Transport(conn, tconn)
}

func forwardBind(req *gosocks5.Request, conn net.Conn) error {
	fconn, _, err := forwardChain(forwardArgs...)
	if err != nil {
		if fconn != nil {
			fconn.Close()
		}
		rep := gosocks5.NewReply(gosocks5.Failure, nil)
		if err := rep.Write(conn); err != nil {
			if glog.V(LWARNING) {
				glog.Warningln("socks5 bind forward:", err)
			}
		} else {
			if glog.V(LDEBUG) {
				glog.Infoln(rep)
			}
		}
		return err
	}
	defer fconn.Close()

	if err := req.Write(fconn); err != nil {
		if glog.V(LWARNING) {
			glog.Warningln("socks5 bind forward:", err)
		}
		gosocks5.NewReply(gosocks5.Failure, nil).Write(conn)
		return err
	}
	if glog.V(LDEBUG) {
		glog.Infoln(req)
	}

	// first reply
	if err := peekReply(conn, fconn); err != nil {
		if glog.V(LWARNING) {
			glog.Warningln("socks5 bind forward:", err)
		}
		return err
	}
	// second reply
	if err := peekReply(conn, fconn); err != nil {
		if glog.V(LWARNING) {
			glog.Warningln("socks5 bind forward:", err)
		}
		return err
	}

	return Transport(conn, fconn)
}

func peekReply(dst io.Writer, src io.Reader) error {
	rep, err := gosocks5.ReadReply(src)
	if err != nil {
		if glog.V(LWARNING) {
			glog.Warningln(err)
		}
		rep = gosocks5.NewReply(gosocks5.Failure, nil)
	}
	if err := rep.Write(dst); err != nil {
		return err
	}
	if glog.V(LDEBUG) {
		glog.Infoln(rep)
	}
	if rep.Rep != gosocks5.Succeeded {
		return errors.New("Failure")
	}

	return nil
}

func cliTunnelUDP(uconn *net.UDPConn, sconn net.Conn) {
	var raddr *net.UDPAddr

	go func() {
		b := make([]byte, 16*1024)
		for {
			n, addr, err := uconn.ReadFromUDP(b)
			if err != nil {
				log.Println(err)
				return
			}
			raddr = addr
			r := bytes.NewBuffer(b[:n])
			udp, err := gosocks5.ReadUDPDatagram(r)
			if err != nil {
				return
			}
			udp.Header.Rsv = uint16(len(udp.Data))
			//log.Println("r", raddr.String(), udp.Header)

			if err := udp.Write(sconn); err != nil {
				log.Println(err)
				return
			}
		}
	}()

	for {
		b := lpool.Take()
		defer lpool.put(b)

		udp, err := gosocks5.ReadUDPDatagram(sconn)
		if err != nil {
			log.Println(err)
			return
		}
		//log.Println("w", udp.Header)
		udp.Header.Rsv = 0
		buf := bytes.NewBuffer(b[0:0])
		udp.Write(buf)
		if _, err := uconn.WriteTo(buf.Bytes(), raddr); err != nil {
			log.Println(err)
			return
		}
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
