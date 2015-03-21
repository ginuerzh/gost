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
	"time"
)

const (
	readWait  = 300 * time.Second
	writeWait = 300 * time.Second
)

type Gost struct {
	Laddr, Saddr, Proxy string
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
	sconn, err := g.connect(g.Saddr)
	if err != nil {
		return
	}
	defer sconn.Close()

	g.transport(conn, sconn)
	return
}

func (g *Gost) srv(conn net.Conn) {
	b := make([]byte, 8192)

	n, err := conn.Read(b)
	if err != nil {
		log.Println(err)
		return
	}

	if bytes.Equal(b[:n], []byte{5, 1, 0}) { // socks5,NO AUTHENTICATION
		log.Println("read cmd:", b[:n])
		if _, err := conn.Write([]byte{5, 0}); err != nil {
			log.Println(err)
			return
		}

		cmd, err := ReadCmd(conn)
		if err != nil {
			return
		}
		host := cmd.Addr + ":" + strconv.Itoa(int(cmd.Port))
		log.Println("connect", host)
		tconn, err := g.connect(host)
		if err != nil {
			log.Println(err)
			NewCmd(ConnRefused, 0, "", 0).Write(conn)
			return
		}
		defer tconn.Close()

		if err = NewCmd(Succeeded, AddrIPv4, "0.0.0.0", 0).Write(conn); err != nil {
			log.Println(err)
			return
		}

		g.transport(conn, tconn)
		return
	}

	//log.Println(string(b[:n]))
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(b[:n])))
	if err != nil {
		log.Println(err)
		return
	}

	log.Println(req.Method, req.RequestURI)
	host := req.Host
	if !strings.Contains(host, ":") {
		host = host + ":80"
	}
	tconn, err := g.connect(host)
	if err != nil {
		log.Println(err)
		conn.Write([]byte("HTTP/1.1 503 Service unavailable\r\n" +
			"Proxy-Agent: gost/1.0\r\n\r\n"))
		return
	}
	defer tconn.Close()

	if req.Method == "CONNECT" {
		if _, err = conn.Write(
			[]byte("HTTP/1.1 200 Connection established\r\n" +
				"Proxy-Agent: gost/1.0\r\n\r\n")); err != nil {
			return
		}
	} else {
		if err := req.Write(tconn); err != nil {
			return
		}
	}

	g.transport(conn, tconn)
}

func (g *Gost) connect(addr string) (net.Conn, error) {
	if len(g.Proxy) == 0 {
		taddr, err := net.ResolveTCPAddr("tcp", addr)
		if err != nil {
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
		return nil, err
	}

	b := make([]byte, 1500)
	buffer := bytes.NewBuffer(b)
	buffer.WriteString("CONNECT " + addr + " HTTP/1.1\r\n")
	buffer.WriteString("Host: " + addr + "\r\n")
	buffer.WriteString("Proxy-Connection: keep-alive\r\n\r\n")
	if _, err = pconn.Write(buffer.Bytes()); err != nil {
		pconn.Close()
		return nil, err
	}

	r := ""
	for !strings.HasSuffix(r, "\r\n\r\n") {
		n := 0
		if n, err = pconn.Read(b); err != nil {
			pconn.Close()
			return nil, err
		}
		r += string(b[:n])
	}

	log.Println(r)
	if !strings.Contains(r, "200") {
		log.Println("connection failed:\n", r)
		err = errors.New(r)
		pconn.Close()
		return nil, err
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
