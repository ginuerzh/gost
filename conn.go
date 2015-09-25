package main

import (
	"bufio"
	"crypto/tls"
	"github.com/ginuerzh/gosocks5"
	"github.com/golang/glog"
	"io"
	"net"
	"net/http"
)

func listenAndServe(arg Args) error {
	var ln net.Listener
	var err error

	switch arg.Transport {
	case "ws": // websocket connection
		err = NewWs(arg).ListenAndServe()
		if err != nil {
			if glog.V(LFATAL) {
				glog.Errorln(err)
			}
		}
		return err
	case "tls": // tls connection
		ln, err = tls.Listen("tcp", arg.Addr,
			&tls.Config{Certificates: []tls.Certificate{arg.Cert}})
	default:
		ln, err = net.Listen("tcp", arg.Addr)
	}

	if err != nil {
		if glog.V(LFATAL) {
			glog.Errorln(err)
		}
		return err
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if glog.V(LWARNING) {
				glog.Warningln(err)
			}
			continue
		}
		if glog.V(LINFO) {
			glog.Infoln("accept", conn.RemoteAddr())
		}
		go handleConn(conn, arg)
	}

	return nil
}

func handleConn(conn net.Conn, arg Args) {
	defer conn.Close()

	selector := &serverSelector{
		methods: []uint8{
			gosocks5.MethodNoAuth, gosocks5.MethodUserPass,
			MethodTLS, MethodTLSAuth,
		},
		arg: arg,
	}

	switch arg.Protocol {
	case "ss": // shadowsocks
		return
	case "http":
		req, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			if glog.V(LWARNING) {
				glog.Warningln(err)
			}
			return
		}
		handleHttpRequest(req, conn, arg)
		return
	case "socks", "socks5":
		conn = gosocks5.ServerConn(conn, selector)
		req, err := gosocks5.ReadRequest(conn)
		if err != nil {
			if glog.V(LWARNING) {
				glog.Warningln("socks5:", err)
			}
			return
		}
		handleSocks5Request(req, conn, arg)
		return
	}

	// http + socks5

	b := make([]byte, 16*1024)

	n, err := io.ReadAtLeast(conn, b, 2)
	if err != nil {
		if glog.V(LWARNING) {
			glog.Warningln(err)
		}
		return
	}

	if b[0] == gosocks5.Ver5 {
		mn := int(b[1]) // methods count
		length := 2 + mn
		if n < length {
			if _, err := io.ReadFull(conn, b[n:length]); err != nil {
				if glog.V(LWARNING) {
					glog.Warningln("socks5:", err)
				}
				return
			}
		}
		methods := b[2 : 2+mn]
		method := selector.Select(methods...)
		if _, err := conn.Write([]byte{gosocks5.Ver5, method}); err != nil {
			if glog.V(LWARNING) {
				glog.Warningln("socks5:", err)
			}
			return
		}
		c, err := selector.OnSelected(method, conn)
		if err != nil {
			if glog.V(LWARNING) {
				glog.Warningln("socks5:", err)
			}
			return
		}
		conn = c

		req, err := gosocks5.ReadRequest(conn)
		if err != nil {
			if glog.V(LWARNING) {
				glog.Warningln("socks5:", err)
			}
			return
		}
		handleSocks5Request(req, conn, arg)
		return
	}

	req, err := http.ReadRequest(bufio.NewReader(newReqReader(b[:n], conn)))
	if err != nil {
		if glog.V(LWARNING) {
			glog.Warningln(err)
		}
		return
	}
	handleHttpRequest(req, conn, arg)
}

type reqReader struct {
	b []byte
	r io.Reader
}

func newReqReader(b []byte, r io.Reader) *reqReader {
	return &reqReader{
		b: b,
		r: r,
	}
}

func (r *reqReader) Read(p []byte) (n int, err error) {
	if len(r.b) == 0 {
		return r.r.Read(p)
	}
	n = copy(p, r.b)
	r.b = r.b[n:]

	return
}
