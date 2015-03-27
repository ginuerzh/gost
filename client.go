package main

import (
	"bufio"
	"bytes"
	"github.com/ginuerzh/gosocks5"
	"github.com/shadowsocks/shadowsocks-go/shadowsocks"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
)

func listenAndServe(addr string, handler func(net.Conn)) error {
	laddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return err
	}

	ln, err := net.ListenTCP("tcp", laddr)
	if err != nil {
		return err
	}
	defer ln.Close()

	for {
		conn, err := ln.AcceptTCP()
		if err != nil {
			log.Println("accept:", err)
			continue
		}
		//log.Println("accept", conn.RemoteAddr())
		go handler(conn)
	}
}

func handshake(conn net.Conn, methods ...uint8) (method uint8, err error) {
	nm := len(methods)
	if nm == 0 {
		nm = 1
	}
	b := make([]byte, 2+nm)
	b[0] = Ver5
	b[1] = uint8(nm)
	copy(b[2:], methods)

	if _, err = conn.Write(b); err != nil {
		return
	}

	if _, err = io.ReadFull(conn, b[:2]); err != nil {
		return
	}

	if b[0] != Ver5 {
		err = gosocks5.ErrBadVersion
	}
	method = b[1]

	return
}

func cliHandle(conn net.Conn) {
	defer conn.Close()

	sconn, err := Connect(Saddr, Proxy)
	if err != nil {
		return
	}
	defer sconn.Close()

	method, err := handshake(sconn, MethodAES256, gosocks5.MethodNoAuth)
	if err != nil || method == gosocks5.MethodNoAcceptable {
		return
	}
	if method == MethodAES256 {
		cipher, _ := shadowsocks.NewCipher(Cipher, Password)
		sconn = shadowsocks.NewConn(sconn, cipher)
	}

	b := make([]byte, 8192)

	n, err := io.ReadAtLeast(conn, b, 2)
	if err != nil {
		log.Println(err)
		return
	}

	if b[0] == gosocks5.Ver5 {
		length := 2 + int(b[1])
		if n < length {
			if _, err := io.ReadFull(conn, b[n:length]); err != nil {
				return
			}
		}

		if err := gosocks5.WriteMethod(gosocks5.MethodNoAuth, conn); err != nil {
			return
		}

		handleSocks5(conn, sconn)
		return
	}

	for {
		if bytes.HasSuffix(b[:n], []byte("\r\n\r\n")) {
			break
		}

		nn, err := conn.Read(b[n:])
		if err != nil {
			return
		}
		n += nn
	}

	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(b[:n])))
	if err != nil {
		return
	}
	handleHttp(req, conn, sconn)
}

func handleSocks5(conn net.Conn, sconn net.Conn) {
	req, err := gosocks5.ReadRequest(conn)
	if err != nil {
		return
	}
	log.Println(req)

	switch req.Cmd {
	case gosocks5.CmdConnect, gosocks5.CmdBind:
		if err := req.Write(sconn); err != nil {
			return
		}
		Transport(conn, sconn)
	case gosocks5.CmdUdp:
		if err := req.Write(sconn); err != nil {
			return
		}
		rep, err := gosocks5.ReadReply(sconn)
		if err != nil || rep.Rep != gosocks5.Succeeded {
			return
		}

		uconn, err := net.ListenUDP("udp", nil)
		if err != nil {
			log.Println(err)
			gosocks5.NewReply(Failure, nil).Write(conn)
			return
		}
		defer uconn.Close()

		addr := ToSocksAddr(uconn.LocalAddr())
		addr.Host, _, _ = net.SplitHostPort(conn.LocalAddr().String())
		log.Println("udp:", addr)

		rep = gosocks5.NewReply(Succeeded, addr)
		if err := rep.Write(conn); err != nil {
			log.Println(err)
			return
		}

		cliTunnelUDP(uconn, conn)
	}
}

func cliTunnelUDP(uconn *net.UDPConn, conn net.Conn) {
	var raddr *net.UDPAddr

	go func() {
		b := make([]byte, 65797)
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
			log.Println("r", raddr.String(), udp.Header)

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
		log.Println("w", udp.Header)
		udp.Header.Rsv = 0
		buf := &bytes.Buffer{}
		udp.Write(buf)
		if _, err := uconn.WriteTo(buf.Bytes(), raddr); err != nil {
			log.Println(err)
			return
		}
	}
}

func handleHttp(req *http.Request, conn net.Conn, sconn net.Conn) {
	var host string
	var port uint16

	s := strings.Split(req.Host, ":")
	host = s[0]
	port = 80
	if len(s) == 2 {
		n, _ := strconv.ParseUint(s[1], 10, 16)
		port = uint16(n)
	}

	addr := &gosocks5.Addr{
		Type: gosocks5.AddrDomain,
		Host: host,
		Port: port,
	}
	r := gosocks5.NewRequest(gosocks5.CmdConnect, addr)
	if err := r.Write(sconn); err != nil {
		return
	}
	rep, err := gosocks5.ReadReply(sconn)
	if err != nil || rep.Rep != gosocks5.Succeeded {
		conn.Write([]byte("HTTP/1.1 503 Service unavailable\r\n" +
			"Proxy-Agent: gost/1.0\r\n\r\n"))
		return
	}

	if req.Method == "CONNECT" {
		if _, err = conn.Write(
			[]byte("HTTP/1.1 200 Connection established\r\n" +
				"Proxy-Agent: gost/2.0\r\n\r\n")); err != nil {
			return
		}
	} else {
		if err := req.Write(sconn); err != nil {
			return
		}
	}

	if err := Transport(conn, sconn); err != nil {
		log.Println(err)
	}
}
