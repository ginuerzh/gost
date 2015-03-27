package main

import (
	"bufio"
	"bytes"
	//"crypto/tls"
	//"errors"
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
	//"net/url"
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
	lg := NewLog(false)
	defer func() {
		lg.Logln()
		lg.Flush()
	}()

	raddr := conn.(*net.TCPConn).RemoteAddr()
	lg.Logln("accept", raddr.String())

	sconn, err := Connect(g.Saddr, g.Proxy)
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
	if len(Cipher) > 0 {
		b[2] = MethodAES256
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

	if b[1] == MethodAES256 {
		cipher, _ := shadowsocks.NewCipher("aes-256-cfb", "gost")
		sconn = shadowsocks.NewConn(sconn, cipher)
	}

	if g.Shadows {
		lg.Logln("shadowsocks, aes-256-cfb")
		cipher, _ := shadowsocks.NewCipher("aes-256-cfb", "gost")

		shadowTransfer(shadowsocks.NewConn(conn, cipher), sconn, lg)
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

		socks5Transfer(conn, sconn, lg)
		return
	}

	//log.Println(string(b[:n]))
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(b[:n])))
	if err != nil {
		lg.Logln(err)
		return
	}

	httpTransfer(req, conn, sconn, lg)
}

func (g *Gost) srv(conn net.Conn) {
	b := make([]byte, 8192)
	lg := NewLog(false)
	defer func() {
		lg.Logln()
		lg.Flush()
	}()
	raddr := conn.(*net.TCPConn).RemoteAddr()
	lg.Logln("accept", raddr.String())

	n, err := conn.Read(b)
	if err != nil {
		lg.Logln(err)
		return
	}

	if b[0] == 5 { // socks5
		lg.Logln("|>>>", b[:n])
		method := b[2]
		if _, err := conn.Write([]byte{5, method}); err != nil {
			lg.Logln(err)
			return
		}
		lg.Logln("|<<<", []byte{5, method})

		if method == MethodAES256 {
			cipher, _ := shadowsocks.NewCipher("aes-256-cfb", "gost")
			conn = shadowsocks.NewConn(conn, cipher)
		}
		cmd, err := ReadCmd(conn)
		if err != nil {
			lg.Logln(err)
			return
		}
		lg.Logln("|>>>", cmd)

		switch cmd.Cmd {
		case CmdConnect:
			//host := cmd.Addr + ":" + strconv.Itoa(int(cmd.Port))
			host := net.JoinHostPort(cmd.Addr, strconv.Itoa(int(cmd.Port)))
			lg.Logln("connect", host)

			tconn, err := Connect(host, g.Proxy)
			if err != nil {
				lg.Logln(err)
				cmd = NewCmd(ConnRefused, 0, "", 0)
				cmd.Write(conn)
				lg.Logln("|<<<", cmd)
				return
			}
			defer tconn.Close()

			cmd = NewCmd(Succeeded, AddrIPv4, "", 0)
			if err = cmd.Write(conn); err != nil {
				lg.Logln(err)
				return
			}
			lg.Logln("|<<<", cmd)

			if err := Transport(conn, tconn); err != nil {
				lg.Logln(err)
			}
		case CmdUdp:
			//log.Println("recv udp")
			//addr := &net.UDPAddr{IP: raddr.(*net.TCPAddr).IP}
			uconn, err := net.ListenUDP("udp", nil)
			if err != nil {
				lg.Logln(err)
				return
			}
			defer uconn.Close()

			uaddr := uconn.LocalAddr()
			lg.Logln("listen udp", uaddr)

			_, port, _ := net.SplitHostPort(uaddr.String())
			p, _ := strconv.Atoi(port)
			cmd = NewCmd(Succeeded, AddrIPv4, "", uint16(p))
			if err = cmd.Write(conn); err != nil {
				lg.Logln(err)
				return
			}
			lg.Logln("|<<<", cmd)

			if err := tunnelUdp(conn, uconn, true); err != nil {
				lg.Logln(err)
			}
			/*
				up, err := ReadUdpPayload(uconn)
				if err != nil {
					lg.Logln(err)
					return
				}
				lg.Logln("[>>>", up)
			*/
		case CmdBind:
			//log.Println("recv bind")
			l, err := net.ListenTCP("tcp", nil)
			if err != nil {
				lg.Logln(err)
				cmd := NewCmd(Failure, AddrIPv4, "", 0)
				cmd.Write(conn)
				lg.Logln("|<<<", cmd)
				return
			}
			defer l.Close()

			addr := ""
			ifis, _ := net.Interfaces()
			for _, ifi := range ifis {
				if strings.HasPrefix(ifi.Name, "eth") {
					addrs, _ := ifi.Addrs()
					if len(addrs) > 0 {
						ip, _, _ := net.ParseCIDR(addrs[0].String())
						addr = ip.String()
					}
					break
				}
			}
			lg.Logln("bind", addr, l.Addr().(*net.TCPAddr).Port)
			cmd := NewCmd(Succeeded, AddrIPv4, addr, uint16(l.Addr().(*net.TCPAddr).Port))
			if err := cmd.Write(conn); err != nil {
				lg.Logln(err)
				return
			}
			lg.Logln("|<<<", cmd)

			for {
				c, err := l.AcceptTCP()
				if err != nil {
					log.Println("accept:", err)
					return
				}
				raddr := c.RemoteAddr().(*net.TCPAddr)
				cmd := NewCmd(Succeeded, AddrIPv4, raddr.IP.String(), uint16(raddr.Port))
				if err := cmd.Write(conn); err != nil {
					log.Println(err)
					return
				}
				defer c.Close()

				Transport(conn, c)
				return
			}
		}

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
	tconn, err := Connect(host, g.Proxy)
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

	if err := Transport(conn, tconn); err != nil {
		lg.Logln(err)
	}
}

func tunnelUdp(conn net.Conn, uconn *net.UDPConn, rawUdp bool) (err error) {
	rChan := make(chan error, 1)
	wChan := make(chan error, 1)
	var raddr *net.UDPAddr

	go func() {
		for {
			up, err := ReadUdpPayload(conn)
			if err != nil {
				rChan <- err
				return
			}

			addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(up.Addr, strconv.Itoa(int(up.Port))))
			if err != nil {
				log.Println(err)
				continue
			}
			if rawUdp {
				if _, err = uconn.WriteToUDP(up.Data, addr); err != nil {
					log.Println(err)
				}
				log.Println("r", up)
			} else {
				up.Rsv = 0
				buf := &bytes.Buffer{}
				up.Write(buf)
				log.Println(raddr, buf.Bytes())
				if _, err := uconn.WriteToUDP(buf.Bytes(), raddr); err != nil {
					log.Println(err)
				}
				log.Println("r", up)
			}
		}
	}()

	go func() {
		for {
			b := make([]byte, 65797)
			n, addr, err := uconn.ReadFromUDP(b)
			if err != nil {
				log.Println(err)
				return
			}
			raddr = addr

			if rawUdp {
				host, port, _ := net.SplitHostPort(addr.String())
				p, _ := strconv.Atoi(port)
				up := NewUdpPayload(uint16(n), AddrIPv4, host, uint16(p), b[:n])
				if err := up.Write(conn); err != nil {
					wChan <- err
					return
				}
				log.Println("w", up)
				continue
			}

			rbuf := bytes.NewReader(b[:n])
			up, err := ReadUdpPayload(rbuf)
			if err != nil {
				log.Println(err)
				continue
			}
			up.Rsv = uint16(len(up.Data))
			if err := up.Write(conn); err != nil {
				wChan <- err
				return
			}
			log.Println("w", up)
		}
	}()

	select {
	case err = <-wChan:
		//log.Println("w exit", err)
	case err = <-rChan:
		//log.Println("r exit", err)
	}

	return
}

func socks5Transfer(conn, sconn net.Conn, lg *BufferedLog) {
	cmd, err := ReadCmd(conn)
	if err != nil {
		lg.Logln(err)
		return
	}
	lg.Logln("|>>>", cmd)

	switch cmd.Cmd {
	case CmdConnect:
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

		if err := Transport(conn, sconn); err != nil {
			lg.Logln("transport:", err)
		}
	case CmdUdp:
		//raddr := conn.(*net.TCPConn).RemoteAddr()
		addr := &net.UDPAddr{IP: net.ParseIP(cmd.Addr)}
		uconn, err := net.ListenUDP("udp", addr)
		if err != nil {
			lg.Logln(err)
			return
		}
		uaddr := uconn.LocalAddr()
		lg.Logln("listen udp", uaddr)

		cmd := NewCmd(CmdUdp, AddrIPv4, "", 0)
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

		_, port, _ := net.SplitHostPort(uconn.LocalAddr().String())
		p, _ := strconv.Atoi(port)
		cmd = NewCmd(Succeeded, AddrIPv4, "", uint16(p))
		if err = cmd.Write(conn); err != nil {
			lg.Logln(err)
			return
		}
		lg.Logln("|<<<", cmd)

		if err := tunnelUdp(sconn, uconn, false); err != nil {
			lg.Logln("tunnel UDP:", err)
		}
	case CmdBind:
		if err := cmd.Write(sconn); err != nil {
			lg.Logln(err)
			return
		}

		cmd, err := ReadCmd(sconn)
		if err != nil {
			lg.Logln(err)
			return
		}
		lg.Logln("<<<|", cmd)
		if err := cmd.Write(conn); err != nil {
			lg.Logln(err)
			return
		}
		lg.Logln("|<<<", cmd)

		if err := Transport(conn, sconn); err != nil {
			lg.Logln("bind:", err)
		}
	}

}

func httpTransfer(req *http.Request, conn, sconn net.Conn, lg *BufferedLog) {
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
	err := cmd.Write(sconn)
	if err != nil {
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

	if err := Transport(conn, sconn); err != nil {
		lg.Logln(err)
	}
}

func shadowTransfer(conn, sconn net.Conn, lg *BufferedLog) {
	t, addr, port, extra, err := getRequest(conn)
	if err != nil {
		lg.Logln(err)
		return
	}
	lg.Logln(addr, port)

	cmd := NewCmd(CmdConnect, t, addr, port)
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
		//lg.Logln("extra:", string(extra))
		if _, err := sconn.Write(extra); err != nil {
			lg.Logln(err)
			return
		}
	}

	if err := Transport(conn, sconn); err != nil {
		lg.Logln(err)
	}
}

func getRequest(conn net.Conn) (addrType uint8, addr string, port uint16, extra []byte, err error) {
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
	//shadowsocks.SetReadTimeout(conn)
	if n, err = io.ReadAtLeast(conn, buf, idDmLen+1); err != nil {
		log.Println(err)
		return
	}
	//log.Println(buf[:n])
	addrType = buf[idType]

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
		addr = net.IP(buf[idIP0 : idIP0+net.IPv4len]).String()
	case typeIPv6:
		addr = net.IP(buf[idIP0 : idIP0+net.IPv6len]).String()
	case typeDm:
		addr = string(buf[idDm0 : idDm0+buf[idDmLen]])
	}
	// parse port
	port = binary.BigEndian.Uint16(buf[reqLen-2 : reqLen])
	return
}
