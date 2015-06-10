package main

import (
	"bufio"
	//"bytes"
	"encoding/base64"
	"errors"
	"github.com/ginuerzh/gosocks5"
	"io"
	//"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
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
	MethodTLSAuth
)

var ErrEmptyPassword = errors.New("empty key")

var Methods = map[uint8]string{
	gosocks5.MethodNoAuth: "",            // 0x00
	MethodTLS:             "tls",         // 0x80
	MethodAES128:          "aes-128-cfb", // 0x81
	MethodAES192:          "aes-192-cfb", // 0x82
	MethodAES256:          "aes-256-cfb", // 0x83
	MethodDES:             "des-cfb",     // 0x84
	MethodBF:              "bf-cfb",      // 0x85
	MethodCAST5:           "cast5-cfb",   // 0x86
	MethodRC4MD5:          "rc4-md5",     // 8x87
	MethodRC4:             "rc4",         // 0x88
	MethodTable:           "table",       // 0x89
	MethodTLSAuth:         "tls-auth",    // 0x90
}

func parseURL(rawurl string) (*url.URL, error) {
	if len(rawurl) == 0 {
		return nil, nil
	}
	if !strings.HasPrefix(rawurl, "http://") &&
		!strings.HasPrefix(rawurl, "socks://") {
		rawurl = "http://" + rawurl
	}
	return url.Parse(rawurl)
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

func dial(addr string) (net.Conn, error) {
	taddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, err
	}
	return net.DialTCP("tcp", nil, taddr)
}

func connect(addr string) (net.Conn, error) {
	if !strings.Contains(addr, ":") {
		addr += ":80"
	}
	if proxyURL == nil {
		return dial(addr)
	}

	switch proxyURL.Scheme {
	case "socks": // socks5 proxy
		return connectSocks5Proxy(addr)
	case "http": // http proxy
		fallthrough
	default:
		return connectHTTPProxy(addr)
	}

}

func connectHTTPProxy(addr string) (conn net.Conn, err error) {
	conn, err = dial(proxyURL.Host)
	if err != nil {
		return
	}

	req := &http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Host: addr},
		Host:   addr,
		Header: make(http.Header),
	}
	req.Header.Set("Proxy-Connection", "keep-alive")
	setBasicAuth(req)

	if err = req.Write(conn); err != nil {
		conn.Close()
		return
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		conn.Close()
		return
	}
	if resp.StatusCode != http.StatusOK {
		conn.Close()
		//log.Println(resp.Status)
		return nil, errors.New(resp.Status)
	}
	return
}

func connectSocks5Proxy(addr string) (conn net.Conn, err error) {
	conn, err = dial(proxyURL.Host)
	if err != nil {
		return
	}

	conf := &gosocks5.Config{
		Methods:        []uint8{gosocks5.MethodNoAuth, gosocks5.MethodUserPass},
		MethodSelected: proxyMethodSelected,
	}

	c := gosocks5.ClientConn(conn, conf)
	if err := c.Handleshake(); err != nil {
		conn.Close()
		return nil, err
	}
	conn = c

	s := strings.Split(addr, ":")
	host := s[0]
	port := 80
	if len(s) == 2 {
		n, _ := strconv.ParseUint(s[1], 10, 16)
		port = int(n)
	}
	a := &gosocks5.Addr{
		Type: gosocks5.AddrDomain,
		Host: host,
		Port: uint16(port),
	}
	if err := gosocks5.NewRequest(gosocks5.CmdConnect, a).Write(conn); err != nil {
		conn.Close()
		return nil, err
	}
	rep, err := gosocks5.ReadReply(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if rep.Rep != gosocks5.Succeeded {
		conn.Close()
		return nil, errors.New("Socks Failture")
	}

	return conn, nil
}

func proxyMethodSelected(method uint8, conn net.Conn) (net.Conn, error) {
	switch method {
	case gosocks5.MethodUserPass:
		if proxyURL == nil || proxyURL.User == nil {
			return nil, gosocks5.ErrAuthFailure
		}
		pwd, _ := proxyURL.User.Password()
		if err := gosocks5.NewUserPassRequest(gosocks5.UserPassVer,
			proxyURL.User.Username(), pwd).Write(conn); err != nil {
			return nil, err
		}
		resp, err := gosocks5.ReadUserPassResponse(conn)
		if err != nil {
			return nil, err
		}
		if resp.Status != gosocks5.Succeeded {
			return nil, gosocks5.ErrAuthFailure
		}
	case gosocks5.MethodNoAcceptable:
		return nil, gosocks5.ErrBadMethod

		//case gosocks5.MethodNoAuth:
	}

	return conn, nil
}

func setBasicAuth(r *http.Request) {
	if proxyURL != nil && proxyURL.User != nil {
		r.Header.Set("Proxy-Authorization",
			"Basic "+base64.StdEncoding.EncodeToString([]byte(proxyURL.User.String())))
	}
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
