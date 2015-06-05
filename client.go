package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"github.com/ginuerzh/gosocks5"
	"github.com/gorilla/websocket"
	"github.com/shadowsocks/shadowsocks-go/shadowsocks"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	//"sync/atomic"
)

var (
	sessionCount int64
	clientConfig = &gosocks5.Config{
		MethodSelected: clientMethodSelected,
	}
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

	for m, v := range Methods {
		if Method == v {
			clientConfig.Methods = []uint8{m}
		}
	}

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

func clientMethodSelected(method uint8, conn net.Conn) (net.Conn, error) {
	switch method {
	case MethodTLS:
		conn = tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
		if err := cliTLSAuth(conn); err != nil {
			return nil, err
		}
	case MethodAES128, MethodAES192, MethodAES256,
		MethodDES, MethodBF, MethodCAST5, MethodRC4MD5, MethodRC4, MethodTable:
		cipher, err := shadowsocks.NewCipher(Methods[method], Password)
		if err != nil {
			log.Println(err)
			return nil, err
		}
		conn = shadowsocks.NewConn(conn, cipher)
	case gosocks5.MethodNoAcceptable:
		return nil, gosocks5.ErrBadMethod
	}

	return conn, nil
}

func cliTLSAuth(conn net.Conn) error {
	if err := gosocks5.NewUserPassRequest(
		gosocks5.UserPassVer, "", Password).Write(conn); err != nil {
		return err
	}
	res, err := gosocks5.ReadUserPassResponse(conn)
	if err != nil {
		return err
	}
	if res.Status != gosocks5.Succeeded {
		return gosocks5.ErrAuthFailure
	}

	return nil
}

func cliHandle(conn net.Conn) {
	defer conn.Close()
	/*
		fmt.Println("new session", atomic.AddInt64(&sessionCount, 1))
		defer func() {
			fmt.Println("session end", atomic.AddInt64(&sessionCount, -1))
		}()
	*/

	//log.Println("connect:", Saddr, Proxy)
	var c net.Conn
	var err error

	if UseWebsocket || !UseHttp {
		c, err = ConnectProxy(Saddr, Proxy)
	} else {
		addr := Saddr
		if len(Proxy) > 0 {
			addr = Proxy
		}
		c, err = Connect(addr)
	}
	if err != nil {
		log.Println(err)
		return
	}
	defer c.Close()

	if UseWebsocket {
		ws, resp, err := websocket.NewClient(c, &url.URL{Host: Saddr}, nil, 8192, 8192)
		if err != nil {
			log.Println(err)
			return
		}
		resp.Body.Close()

		c = NewWSConn(ws)
	} else if UseHttp {
		httpcli := NewHttpClientConn(c)
		if err := httpcli.Handshake(); err != nil {
			log.Println(err)
			return
		}
		c = httpcli
		defer httpcli.Close()
	}

	sc := gosocks5.ClientConn(c, clientConfig)
	if err := sc.Handleshake(); err != nil {
		return
	}
	c = sc

	if Shadows {
		cipher, _ := shadowsocks.NewCipher(SMethod, SPassword)
		conn = shadowsocks.NewConn(conn, cipher)
		handleShadow(conn, c)
		return
	}

	b := mpool.Take()
	defer mpool.put(b)

	n, err := io.ReadAtLeast(conn, b, 2)
	if err != nil {
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

		handleSocks5(conn, c)
		return
	}

	for {
		if bytes.HasSuffix(b[:n], []byte("\r\n\r\n")) {
			break
		}

		nn, err := conn.Read(b[n:])
		if err != nil {
			log.Println(err)
			return
		}
		n += nn
	}

	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(b[:n])))
	if err != nil {
		log.Println(err)
		return
	}
	handleHttp(req, conn, c)
}

func handleSocks5(conn net.Conn, sconn net.Conn) {
	req, err := gosocks5.ReadRequest(conn)
	if err != nil {
		return
	}
	//log.Println(req)

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
			gosocks5.NewReply(gosocks5.Failure, nil).Write(conn)
			return
		}
		defer uconn.Close()

		addr := ToSocksAddr(uconn.LocalAddr())
		addr.Host, _, _ = net.SplitHostPort(conn.LocalAddr().String())
		log.Println("udp:", addr)

		rep = gosocks5.NewReply(gosocks5.Succeeded, addr)
		if err := rep.Write(conn); err != nil {
			log.Println(err)
			return
		}

		go cliTunnelUDP(uconn, sconn)

		// block, waiting for client exit
		ioutil.ReadAll(conn)
	}
}

func cliTunnelUDP(uconn *net.UDPConn, sconn net.Conn) {
	var raddr *net.UDPAddr

	go func() {
		b := lpool.Take()
		defer lpool.put(b)

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
			"Proxy-Agent: gost/" + Version + "\r\n\r\n"))
		return
	}

	if req.Method == "CONNECT" {
		if _, err = conn.Write(
			[]byte("HTTP/1.1 200 Connection established\r\n" +
				"Proxy-Agent: gost/" + Version + "\r\n\r\n")); err != nil {
			return
		}
	} else {
		if err := req.Write(sconn); err != nil {
			return
		}
	}

	if err := Transport(conn, sconn); err != nil {
		//log.Println(err)
	}
}

func handleShadow(conn, sconn net.Conn) {
	addr, extra, err := getShadowRequest(conn)
	if err != nil {
		log.Println(err)
		return
	}

	req := gosocks5.NewRequest(gosocks5.CmdConnect, addr)
	if err := req.Write(sconn); err != nil {
		log.Println(err)
		return
	}
	rep, err := gosocks5.ReadReply(sconn)
	if err != nil || rep.Rep != gosocks5.Succeeded {
		log.Println(err)
		return
	}

	if extra != nil {
		if _, err := sconn.Write(extra); err != nil {
			log.Println(err)
			return
		}
	}

	if err := Transport(conn, sconn); err != nil {
		//log.Println(err)
	}
}

func getShadowRequest(conn net.Conn) (addr *gosocks5.Addr, extra []byte, err error) {
	const (
		idType  = 0 // address type index
		idIP0   = 1 // ip addres start index
		idDmLen = 1 // domain address length index
		idDm0   = 2 // domain address start index

		typeIPv4 = 1 // type is ipv4 address
		typeDm   = 3 // type is domain address
		typeIPv6 = 4 // type is ipv6 address

		lenIPv4   = 1 + net.IPv4len + 2 // 1addrType + ipv4 + 2port
		lenIPv6   = 1 + net.IPv6len + 2 // 1addrType + ipv6 + 2port
		lenDmBase = 1 + 1 + 2           // 1addrType + 1addrLen + 2port, plus addrLen
	)

	// buf size should at least have the same size with the largest possible
	// request size (when addrType is 3, domain name has at most 256 bytes)
	// 1(addrType) + 1(lenByte) + 256(max length address) + 2(port)
	buf := spool.Take()
	defer spool.put(buf)

	var n int
	// read till we get possible domain length field
	//shadowsocks.SetReadTimeout(conn)
	if n, err = io.ReadAtLeast(conn, buf, idDmLen+1); err != nil {
		log.Println(err)
		return
	}

	addr = &gosocks5.Addr{
		Type: buf[idType],
	}

	reqLen := -1
	switch buf[idType] {
	case typeIPv4:
		reqLen = lenIPv4
	case typeIPv6:
		reqLen = lenIPv6
	case typeDm:
		reqLen = int(buf[idDmLen]) + lenDmBase
	default:
		err = fmt.Errorf("addr type %d not supported", buf[idType])
		return
	}

	if n < reqLen { // rare case
		//ss.SetReadTimeout(conn)
		if _, err = io.ReadFull(conn, buf[n:reqLen]); err != nil {
			log.Println(err)
			return
		}
	} else if n > reqLen {
		// it's possible to read more than just the request head
		extra = buf[reqLen:n]
	}

	// Return string for typeIP is not most efficient, but browsers (Chrome,
	// Safari, Firefox) all seems using typeDm exclusively. So this is not a
	// big problem.
	switch buf[idType] {
	case typeIPv4:
		addr.Host = net.IP(buf[idIP0 : idIP0+net.IPv4len]).String()
	case typeIPv6:
		addr.Host = net.IP(buf[idIP0 : idIP0+net.IPv6len]).String()
	case typeDm:
		addr.Host = string(buf[idDm0 : idDm0+buf[idDmLen]])
	}
	// parse port
	addr.Port = binary.BigEndian.Uint16(buf[reqLen-2 : reqLen])

	return
}
