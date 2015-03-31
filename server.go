package main

import (
	"github.com/ginuerzh/gosocks5"
	"github.com/shadowsocks/shadowsocks-go/shadowsocks"
	"net"
	//"strconv"
	"crypto/tls"
	"log"
)

func selectMethod(methods ...uint8) uint8 {
	for _, method := range methods {
		if _, ok := Methods[method]; ok {
			return method
		}
	}
	return gosocks5.MethodNoAuth
}

func methodSelected(method uint8, conn net.Conn) (net.Conn, error) {
	switch method {
	case MethodTLS:
		cert, err := tls.LoadX509KeyPair(CertFile, KeyFile)
		if err != nil {
			log.Println(err)
			return nil, err
		}
		conn = tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}})
	case MethodAES128, MethodAES192, MethodAES256,
		MethodDES, MethodBF, MethodCAST5, MethodRC4MD5, MethodRC4, MethodTable:
		cipher, err := shadowsocks.NewCipher(Methods[method], Password)
		if err != nil {
			return nil, err
		}
		conn = shadowsocks.NewConn(conn, cipher)
	case gosocks5.MethodNoAcceptable:
		return nil, gosocks5.ErrBadMethod
	}

	return conn, nil
}

func srvHandle(conn net.Conn) {
	req, err := gosocks5.ReadRequest(conn)
	if err != nil {
		//log.Println(err)
		return
	}

	switch req.Cmd {
	case gosocks5.CmdConnect:
		//log.Println("connect", req.Addr.String())
		tconn, err := Connect(req.Addr.String(), Proxy)
		if err != nil {
			gosocks5.NewReply(gosocks5.HostUnreachable, nil).Write(conn)
			return
		}
		defer tconn.Close()

		rep := gosocks5.NewReply(gosocks5.Succeeded, nil)
		if err := rep.Write(conn); err != nil {
			return
		}

		if err := Transport(conn, tconn); err != nil {
			log.Println(err)
		}
	case gosocks5.CmdBind:
		l, err := net.ListenTCP("tcp", nil)
		if err != nil {
			gosocks5.NewReply(gosocks5.Failure, nil).Write(conn)
			return
		}

		addr := ToSocksAddr(l.Addr())
		addr.Host, _, _ = net.SplitHostPort(conn.LocalAddr().String())
		//log.Println("bind:", addr)
		rep := gosocks5.NewReply(gosocks5.Succeeded, addr)
		if err := rep.Write(conn); err != nil {
			return
		}

		tconn, err := l.AcceptTCP()
		if err != nil {
			log.Println("accept:", err)
			gosocks5.NewReply(gosocks5.Failure, nil).Write(conn)
			return
		}
		defer tconn.Close()
		l.Close()

		addr = ToSocksAddr(tconn.RemoteAddr())
		log.Println("accept peer:", addr.String())
		rep = gosocks5.NewReply(gosocks5.Succeeded, addr)
		if err := rep.Write(conn); err != nil {
			log.Println(err)
			return
		}

		if err := Transport(conn, tconn); err != nil {
			log.Println(err)
		}
	case gosocks5.CmdUdp:
		uconn, err := net.ListenUDP("udp", nil)
		if err != nil {
			log.Println(err)
			gosocks5.NewReply(gosocks5.Failure, nil).Write(conn)
			return
		}
		defer uconn.Close()

		addr := ToSocksAddr(uconn.LocalAddr())
		addr.Host, _, _ = net.SplitHostPort(conn.LocalAddr().String())
		//log.Println("udp:", addr)
		rep := gosocks5.NewReply(gosocks5.Succeeded, addr)
		if err := rep.Write(conn); err != nil {
			log.Println(err)
			return
		}
		srvTunnelUDP(conn, uconn)
	}
}

func srvTunnelUDP(conn net.Conn, uconn *net.UDPConn) {
	go func() {
		b := make([]byte, 65535)
		for {
			n, addr, err := uconn.ReadFromUDP(b)
			if err != nil {
				log.Println(err)
				return
			}

			udp := gosocks5.NewUDPDatagram(
				gosocks5.NewUDPHeader(uint16(n), 0, ToSocksAddr(addr)), b[:n])
			//log.Println("r", udp.Header)
			if err := udp.Write(conn); err != nil {
				log.Println(err)
				return
			}
		}
	}()

	for {
		udp, err := gosocks5.ReadUDPDatagram(conn)
		if err != nil {
			log.Println(err)
			return
		}
		//log.Println("w", udp.Header)
		addr, err := net.ResolveUDPAddr("udp", udp.Header.Addr.String())
		if err != nil {
			log.Println(err)
			continue // drop silently
		}

		if _, err := uconn.WriteToUDP(udp.Data, addr); err != nil {
			log.Println(err)
			return
		}
	}
}
