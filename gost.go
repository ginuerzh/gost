package main

import (
	"bufio"
	"bytes"
	//"crypto/tls"
	"errors"
	"io"
	//"io/ioutil"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	//"sync/atomic"
	"encoding/binary"
	"fmt"
	"github.com/shadowsocks/shadowsocks-go/shadowsocks"
	"net/url"
	"time"
)

const (
	readWait  = 300 * time.Second
	writeWait = 300 * time.Second
)

type Gost struct {
	Laddr, Saddr, Proxy string
	Shadows             bool // shadowsocks compatible
	Cipher              bool
}

func (g *Gost) Run() error {
	addr, err := net.ResolveTCPAddr("tcp", g.Laddr)
	if err != nil {
		return err
	}

	ln, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return err
	}

	for {
		conn, err := ln.AcceptTCP()
		if err != nil {
			log.Println("accept:", err)
			continue
		}
		//log.Println("accept", conn.RemoteAddr().String())
		go g.handle(conn)
	}

	return ln.Close()
}

func (g *Gost) handle(conn net.Conn) {
	defer conn.Close()

	// as client
	if len(g.Saddr) > 0 {
		g.cli(conn)
		return
	}
	// as server
	g.srv(conn)
}

func (g *Gost) cli(conn net.Conn) {
	lg := NewLog(true)
	defer func() {
		lg.Logln()
		lg.Flush()
	}()

	lg.Logln("accept", conn.(*net.TCPConn).RemoteAddr().String())

	sconn, err := g.connect(g.Saddr)
	if err != nil {
		lg.Logln(err)
		return
	}

	defer sconn.Close()
	laddr := sconn.(*net.TCPConn).LocalAddr().String()
	lg.Logln(laddr)

	b := make([]byte, 8192)
	b[0] = 5
	b[1] = 1
	if gost.Cipher {
		b[2] = 0x88
	}

	if _, err := sconn.Write(b[:3]); err != nil {
		lg.Logln(err)
		return
	}
	lg.Logln(">>>|", b[:3])

	n, err := io.ReadFull(sconn, b[:2])
	if err != nil {
		lg.Logln(err)
		return
	}
	lg.Logln("<<<|", b[:n])

	if b[1] == 0x88 {
		cipher, _ := shadowsocks.NewCipher("aes-256-cfb", "gost")
		sconn = shadowsocks.NewConn(sconn, cipher)
	}

	if g.Shadows {
		lg.Logln("shadowsocks, aes-256-cfb")
		cipher, _ := shadowsocks.NewCipher("aes-256-cfb", "gost")
		conn = shadowsocks.NewConn(conn, cipher)
		addr, port, extra, err := getRequest(conn)
		if err != nil {
			lg.Logln(err)
			return
		}
		lg.Logln(addr, port)

		cmd := NewCmd(CmdConnect, AddrDomain, addr, port)
		if err = cmd.Write(sconn); err != nil {
			lg.Logln(err)
			return
		}
		lg.Logln(">>>|", cmd)

		if cmd, err = ReadCmd(sconn); err != nil {
			lg.Logln(err)
			return
		}
		lg.Logln("<<<|", cmd)

		if cmd.Cmd != Succeeded {
			conn.Write([]byte("HTTP/1.1 503 Service unavailable\r\n" +
				"Proxy-Agent: gost/1.0\r\n\r\n"))
			return
		}

		if extra != nil {
			if _, err := sconn.Write(extra); err != nil {
				log.Println(err)
				return
			}
		}

		g.transport(conn, sconn)

		return
	}

	n, err = conn.Read(b)
	if err != nil {
		lg.Logln(err)
		return
	}
	//log.Println(b[:n])
	if b[0] == 5 { // socks5,NO AUTHENTICATION
		lg.Logln("|>>>", b[:n])

		if _, err := conn.Write([]byte{5, 0}); err != nil {
			lg.Logln(err)
			return
		}
		lg.Logln("|<<<", []byte{5, 0})

		cmd, err := ReadCmd(conn)
		if err != nil {
			lg.Logln(err)
			return
		}
		lg.Logln("|>>>", cmd)

		if err = cmd.Write(sconn); err != nil {
			lg.Logln(err)
			return
		}
		lg.Logln(">>>|", cmd)

		cmd, err = ReadCmd(sconn)
		if err != nil {
			lg.Logln(err)
			return
		}
		lg.Logln("<<<|", cmd)

		if err = cmd.Write(conn); err != nil {
			lg.Logln(err)
			return
		}
		lg.Logln("|<<<", cmd)

		g.transport(conn, sconn)
		return
	}

	//log.Println(string(b[:n]))
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(b[:n])))
	if err != nil {
		lg.Logln(err)
		return
	}
	lg.Logln(req.Method, req.RequestURI)

	var addr string
	var port uint16

	host := strings.Split(req.Host, ":")
	if len(host) == 1 {
		addr = host[0]
		port = 80
	}
	if len(host) == 2 {
		addr = host[0]
		n, _ := strconv.ParseUint(host[1], 10, 16)
		port = uint16(n)
	}

	cmd := NewCmd(CmdConnect, AddrDomain, addr, port)
	if err = cmd.Write(sconn); err != nil {
		lg.Logln(err)
		return
	}
	lg.Logln(">>>|", cmd)

	if cmd, err = ReadCmd(sconn); err != nil {
		lg.Logln(err)
		return
	}
	lg.Logln("<<<|", cmd)

	if cmd.Cmd != Succeeded {
		conn.Write([]byte("HTTP/1.1 503 Service unavailable\r\n" +
			"Proxy-Agent: gost/1.0\r\n\r\n"))
		return
	}

	if req.Method == "CONNECT" {
		if _, err = conn.Write(
			[]byte("HTTP/1.1 200 Connection established\r\n" +
				"Proxy-Agent: gost/2.0\r\n\r\n")); err != nil {
			lg.Logln(err)
			return
		}
	} else {
		if err = req.Write(sconn); err != nil {
			lg.Logln(err)
			return
		}
	}

	g.transport(conn, sconn)
}

func (g *Gost) srv(conn net.Conn) {
	b := make([]byte, 8192)
	lg := NewLog(true)
	defer func() {
		lg.Logln()
		lg.Flush()
	}()
	lg.Logln("accept", conn.(*net.TCPConn).RemoteAddr().String())

	n, err := conn.Read(b)
	if err != nil {
		lg.Logln(err)
		return
	}

	if b[0] == 5 { // socks5,NO AUTHENTICATION
		lg.Logln("|>>>", b[:n])
		method := b[2]
		if _, err := conn.Write([]byte{5, method}); err != nil {
			lg.Logln(err)
			return
		}
		lg.Logln("|<<<", []byte{5, method})

		if method == 0x88 {
			cipher, _ := shadowsocks.NewCipher("aes-256-cfb", "gost")
			conn = shadowsocks.NewConn(conn, cipher)
		}
		cmd, err := ReadCmd(conn)
		if err != nil {
			lg.Logln(err)
			return
		}
		lg.Logln("|>>>", cmd)

		host := cmd.Addr + ":" + strconv.Itoa(int(cmd.Port))
		lg.Logln("connect", host)

		tconn, err := g.connect(host)
		if err != nil {
			lg.Logln(err)
			cmd = NewCmd(ConnRefused, 0, "", 0)
			cmd.Write(conn)
			lg.Logln("|<<<", cmd)
			return
		}
		defer tconn.Close()

		cmd = NewCmd(Succeeded, AddrIPv4, "0.0.0.0", 0)
		if err = cmd.Write(conn); err != nil {
			lg.Logln(err)
			return
		}
		lg.Logln("|<<<", cmd)

		lg.Logln()
		lg.Flush()

		g.transport(conn, tconn)
		return
	}

	//log.Println(string(b[:n]))
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(b[:n])))
	if err != nil {
		lg.Logln(err)
		return
	}

	lg.Logln(req.Method, req.RequestURI)
	host := req.Host
	if !strings.Contains(host, ":") {
		host = host + ":80"
	}
	tconn, err := g.connect(host)
	if err != nil {
		lg.Logln(err)
		conn.Write([]byte("HTTP/1.1 503 Service unavailable\r\n" +
			"Proxy-Agent: gost/1.0\r\n\r\n"))
		return
	}
	defer tconn.Close()

	if req.Method == "CONNECT" {
		if _, err = conn.Write(
			[]byte("HTTP/1.1 200 Connection established\r\n" +
				"Proxy-Agent: gost/1.0\r\n\r\n")); err != nil {
			lg.Logln(err)
			return
		}
	} else {
		if err := req.Write(tconn); err != nil {
			lg.Logln(err)
			return
		}
	}

	lg.Logln()
	lg.Flush()

	g.transport(conn, tconn)
}

func (g *Gost) connect(addr string) (net.Conn, error) {
	if len(g.Proxy) == 0 {
		taddr, err := net.ResolveTCPAddr("tcp", addr)
		if err != nil {
			log.Println(err)
			return nil, err
		}
		return net.DialTCP("tcp", nil, taddr)
	}

	paddr, err := net.ResolveTCPAddr("tcp", g.Proxy)
	if err != nil {
		return nil, err
	}
	pconn, err := net.DialTCP("tcp", nil, paddr)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	header := http.Header{}
	header.Set("Proxy-Connection", "keep-alive")
	req := &http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Host: addr},
		Host:   addr,
		Header: header,
	}
	if err := req.Write(pconn); err != nil {
		log.Println(err)
		pconn.Close()
		return nil, err
	}

	resp, err := http.ReadResponse(bufio.NewReader(pconn), req)
	if err != nil {
		log.Println(err)
		pconn.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		pconn.Close()
		return nil, errors.New(resp.Status)
	}

	return pconn, nil
}

func (g *Gost) pipe(src io.Reader, dst io.Writer, c chan<- error) {
	_, err := io.Copy(dst, src)
	c <- err
}

func (g *Gost) transport(conn, conn2 net.Conn) (err error) {
	rChan := make(chan error, 1)
	wChan := make(chan error, 1)

	go g.pipe(conn, conn2, wChan)
	go g.pipe(conn2, conn, rChan)

	select {
	case err = <-wChan:
		//log.Println("w exit", err)
	case err = <-rChan:
		//log.Println("r exit", err)
	}

	return
}

func getRequest(conn net.Conn) (host string, port uint16, extra []byte, err error) {
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
	buf := make([]byte, 260)
	var n int
	// read till we get possible domain length field
	//ss.SetReadTimeout(conn)
	if n, err = io.ReadAtLeast(conn, buf, idDmLen+1); err != nil {
		log.Println(err)
		return
	}
	log.Println(buf[:n])

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
		host = net.IP(buf[idIP0 : idIP0+net.IPv4len]).String()
	case typeIPv6:
		host = net.IP(buf[idIP0 : idIP0+net.IPv6len]).String()
	case typeDm:
		host = string(buf[idDm0 : idDm0+buf[idDmLen]])
	}
	// parse port
	port = binary.BigEndian.Uint16(buf[reqLen-2 : reqLen])
	return
}
