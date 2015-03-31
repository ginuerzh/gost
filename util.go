package main

import (
	"bufio"
	//"bytes"
	"errors"
	"github.com/ginuerzh/gosocks5"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
)

const (
	MethodTLS uint8 = 0x80 + iota
	MethodAES128
	MethodAES192
	MethodAES256
	MethodDES
	MethodBF
	MethodCAST5
	MethodRC4MD5
	MethodRC4
	MethodTable
)

var Methods = map[uint8]string{
	MethodTLS:    "tls",         // 0x80
	MethodAES128: "aes-128-cfb", // 0x81
	MethodAES192: "aes-192-cfb", // 0x82
	MethodAES256: "aes-256-cfb", // 0x83
	MethodDES:    "des-cfb",     // 0x84
	MethodBF:     "bf-cfb",      // 0x85
	MethodCAST5:  "cast5-cfb",   // 0x86
	MethodRC4MD5: "rc4-md5",     // 8x87
	MethodRC4:    "rc4",         // 0x88
	MethodTable:  "table",       // 0x89
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

func Connect(addr, proxy string) (net.Conn, error) {
	if len(proxy) == 0 {
		taddr, err := net.ResolveTCPAddr("tcp", addr)
		if err != nil {
			log.Println(err)
			return nil, err
		}
		return net.DialTCP("tcp", nil, taddr)
	}

	paddr, err := net.ResolveTCPAddr("tcp", proxy)
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

// based on io.Copy
func Copy(dst io.Writer, src io.Reader) (written int64, err error) {
	buf := lpool.Take()
	defer lpool.put(buf)

	for {
		nr, er := src.Read(buf)
		//log.Println("cp r", nr, er)
		if nr > 0 {
			nw, ew := dst.Write(buf[:nr])
			//log.Println("cp w", nw, ew)
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
			/*
				if nr != nw {
					err = io.ErrShortWrite
					break
				}
			*/
		}
		if er == io.EOF {
			break
		}
		if er != nil {
			err = er
			break
		}
	}
	return
}

func Pipe(src io.Reader, dst io.Writer, c chan<- error) {
	_, err := Copy(dst, src)
	c <- err
}

func Transport(conn, conn2 net.Conn) (err error) {
	rChan := make(chan error, 1)
	wChan := make(chan error, 1)

	go Pipe(conn, conn2, wChan)
	go Pipe(conn2, conn, rChan)

	select {
	case err = <-wChan:
		//log.Println("w exit", err)
	case err = <-rChan:
		//log.Println("r exit", err)
	}

	return
}
