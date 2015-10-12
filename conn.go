package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"github.com/ginuerzh/gosocks5"
	"github.com/golang/glog"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
)

const (
	ConnHttp        = "http"
	ConnHttpConnect = "http-connect"
	ConnSocks5      = "socks5"
)

func listenAndServe(arg Args) error {
	var ln net.Listener
	var err error

	if glog.V(3) {
		b := bytes.Buffer{}
		b.WriteString("listen on %s, use %s tunnel and %s protocol for data transport. ")
		if arg.EncMeth == "tls" {
			b.WriteString("for socks5, tls encrypt method is supported.")
		} else {
			b.WriteString("for socks5, tls encrypt method is NOT supported.")
		}
		protocol := arg.Protocol
		if protocol == "" {
			protocol = "http/socks5"
		}
		glog.Infof(b.String(), arg.Addr, arg.Transport, protocol)

	}

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
	case "tcp":
		fallthrough
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
			gosocks5.MethodNoAuth,
			gosocks5.MethodUserPass,
		},
		arg: arg,
	}

	if arg.EncMeth == "tls" {
		selector.methods = append(selector.methods, MethodTLS, MethodTLSAuth)
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

func connect(addr string) (conn net.Conn, err error) {
	if !strings.Contains(addr, ":") {
		addr += ":80"
	}
	if len(forwardArgs) == 0 {
		return net.Dial("tcp", addr)
	}
	return forwardChain(addr, forwardArgs[0], forwardArgs[1:]...)
}

func forwardChain(addr string, level1 Args, chain ...Args) (conn net.Conn, err error) {
	if glog.V(LINFO) {
		glog.Infof("forward: %s/%s %s", level1.Protocol, level1.Transport, level1.Addr)
	}
	if conn, err = net.Dial("tcp", level1.Addr); err != nil {
		return
	}
	c, err := forward(conn, level1)
	if err != nil {
		conn.Close()
		return nil, err
	}
	conn = c

	if len(chain) == 0 {
		if err := establish(conn, addr, level1); err != nil {
			conn.Close()
			return nil, err
		}
		return
	}

	cur := level1
	for _, arg := range chain {
		if err = establish(conn, arg.Addr, cur); err != nil {
			goto exit
		}

		c, err = forward(conn, arg)
		if err != nil {
			goto exit
		}
		conn = c
		cur = arg
	}

exit:
	if err != nil {
		conn.Close()
		return nil, err
	}

	if err := establish(conn, addr, cur); err != nil {
		conn.Close()
		return nil, err
	}

	return
}

func forward(conn net.Conn, arg Args) (net.Conn, error) {
	var err error

	switch arg.Transport {
	case "ws": // websocket connection
		conn, err = wsClient(conn, arg.Addr)
		if err != nil {
			return nil, err
		}
	case "tls": // tls connection
		conn = tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	case "tcp":
		fallthrough
	default:
	}

	switch arg.Protocol {
	case "ss": // shadowsocks
		return nil, errors.New("Not implemented")
	case "socks", "socks5":
		selector := &clientSelector{
			methods: []uint8{gosocks5.MethodNoAuth, gosocks5.MethodUserPass},
			arg:     arg,
		}
		if arg.EncMeth == "tls" {
			selector.methods = []uint8{MethodTLS, MethodTLSAuth}
		}
		c := gosocks5.ClientConn(conn, selector)
		if err := c.Handleshake(); err != nil {
			return nil, err
		}
		conn = c
	case "http":
		fallthrough
	default:
	}

	return conn, nil
}

func establish(conn net.Conn, addr string, arg Args) error {
	switch arg.Protocol {
	case "ss": // shadowsocks
		return nil
	case "socks", "socks5":
		host, port, err := net.SplitHostPort(addr)
		p, _ := strconv.Atoi(port)
		// TODO: support bind and udp
		req := gosocks5.NewRequest(gosocks5.CmdConnect, &gosocks5.Addr{
			Type: gosocks5.AddrDomain,
			Host: host,
			Port: uint16(p),
		})
		rep, err := requestSocks5(conn, req)
		if err != nil {
			return err
		}
		if rep.Rep != gosocks5.Succeeded {
			return errors.New("Service unavailable")
		}
	case "http":
		fallthrough
	default:
		req := &http.Request{
			Method:     "CONNECT",
			URL:        &url.URL{Host: addr},
			Host:       addr,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     make(http.Header),
		}
		req.Header.Set("Proxy-Connection", "keep-alive")
		if arg.User != nil {
			req.Header.Set("Proxy-Authorization",
				"Basic "+base64.StdEncoding.EncodeToString([]byte(arg.User.String())))
		}
		if err := req.Write(conn); err != nil {
			return err
		}
		if glog.V(LDEBUG) {
			dump, _ := httputil.DumpRequest(req, false)
			glog.Infoln(string(dump))
		}

		resp, err := http.ReadResponse(bufio.NewReader(conn), req)
		if err != nil {
			return err
		}
		if glog.V(LDEBUG) {
			dump, _ := httputil.DumpResponse(resp, false)
			glog.Infoln(string(dump))
		}
		if resp.StatusCode != http.StatusOK {
			return errors.New(resp.Status)
		}
	}

	return nil
}
