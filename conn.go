package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"github.com/ginuerzh/gosocks5"
	"github.com/golang/glog"
	"github.com/shadowsocks/shadowsocks-go/shadowsocks"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

var (
	connCounter int32
)

func listenAndServe(arg Args) error {
	var ln net.Listener
	var err error

	switch arg.Transport {
	case "ws": // websocket connection
		err = NewWs(arg).ListenAndServe()
		if err != nil {
			glog.Infoln(err)
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
		glog.Infoln(err)
		return err
	}

	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			glog.V(LWARNING).Infoln(err)
			continue
		}
		go handleConn(conn, arg)
	}

	return nil
}

func handleConn(conn net.Conn, arg Args) {
	atomic.AddInt32(&connCounter, 1)
	glog.V(LINFO).Infof("%s connected, connections: %d",
		conn.RemoteAddr(), atomic.LoadInt32(&connCounter))

	if glog.V(LINFO) {
		defer func() {
			glog.Infof("%s disconnected, connections: %d",
				conn.RemoteAddr(), atomic.LoadInt32(&connCounter))
		}()
	}
	defer atomic.AddInt32(&connCounter, -1)
	defer conn.Close()

	selector := &serverSelector{
		methods: []uint8{
			gosocks5.MethodNoAuth,
			gosocks5.MethodUserPass,
			MethodTLS,
			MethodTLSAuth,
		},
		arg: arg,
	}

	switch arg.Protocol {
	case "ss": // shadowsocks
		handleShadow(conn, arg)
		return
	case "http":
		req, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			glog.V(LWARNING).Infoln("http:", err)
			return
		}
		handleHttpRequest(req, conn, arg)
		return
	case "socks", "socks5":
		conn = gosocks5.ServerConn(conn, selector)
		req, err := gosocks5.ReadRequest(conn)
		if err != nil {
			glog.V(LWARNING).Infoln("socks5:", err)
			return
		}
		handleSocks5Request(req, conn)
		return
	}

	// http + socks5

	b := make([]byte, 16*1024)

	n, err := io.ReadAtLeast(conn, b, 2)
	if err != nil {
		glog.V(LWARNING).Infoln("client:", err)
		return
	}

	if b[0] == gosocks5.Ver5 {
		mn := int(b[1]) // methods count
		length := 2 + mn
		if n < length {
			if _, err := io.ReadFull(conn, b[n:length]); err != nil {
				glog.V(LWARNING).Infoln("socks5:", err)
				return
			}
		}
		methods := b[2 : 2+mn]
		method := selector.Select(methods...)
		if _, err := conn.Write([]byte{gosocks5.Ver5, method}); err != nil {
			glog.V(LWARNING).Infoln("socks5 select:", err)
			return
		}
		c, err := selector.OnSelected(method, conn)
		if err != nil {
			glog.V(LWARNING).Infoln("socks5 onselected:", err)
			return
		}
		conn = c

		req, err := gosocks5.ReadRequest(conn)
		if err != nil {
			glog.V(LWARNING).Infoln("socks5 request:", err)
			return
		}
		handleSocks5Request(req, conn)
		return
	}

	req, err := http.ReadRequest(bufio.NewReader(newReqReader(b[:n], conn)))
	if err != nil {
		glog.V(LWARNING).Infoln("http:", err)
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

func Connect(addr string) (conn net.Conn, err error) {
	if !strings.Contains(addr, ":") {
		addr += ":80"
	}
	if len(forwardArgs) == 0 {
		return net.DialTimeout("tcp", addr, time.Second*30)
	}

	var end Args
	conn, end, err = forwardChain(forwardArgs...)
	if err != nil {
		if conn != nil {
			conn.Close()
		}
		return nil, err
	}
	if err := establish(conn, addr, end); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func forwardChain(chain ...Args) (conn net.Conn, end Args, err error) {
	end = chain[0]
	if conn, err = net.DialTimeout("tcp", end.Addr, time.Second*30); err != nil {
		return
	}
	c, err := forward(conn, end)
	if err != nil {
		return
	}
	conn = c

	chain = chain[1:]
	for _, arg := range chain {
		if err = establish(conn, arg.Addr, end); err != nil {
			goto exit
		}

		c, err = forward(conn, arg)
		if err != nil {
			goto exit
		}
		conn = c
		end = arg
	}

exit:
	return
}

func forward(conn net.Conn, arg Args) (net.Conn, error) {
	var err error
	if glog.V(LINFO) {
		proto := arg.Protocol
		if proto == "default" {
			proto = "http" // default is http
		}
		glog.Infof("forward: %s/%s %s", proto, arg.Transport, arg.Addr)
	}
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
	case "socks", "socks5":
		selector := &clientSelector{
			methods: []uint8{
				gosocks5.MethodNoAuth,
				gosocks5.MethodUserPass,
				MethodTLS,
			},
			arg: arg,
		}
		c := gosocks5.ClientConn(conn, selector)
		if err := c.Handleshake(); err != nil {
			return nil, err
		}
		conn = c
	case "ss": // shadowsocks
		if arg.User != nil {
			method := arg.User.Username()
			password, _ := arg.User.Password()
			cipher, err := shadowsocks.NewCipher(method, password)
			if err != nil {
				return nil, err
			}
			conn = shadowsocks.NewConn(conn, cipher)
		}
	case "http":
		fallthrough
	default:
	}

	return conn, nil
}

func establish(conn net.Conn, addr string, arg Args) error {
	switch arg.Protocol {
	case "ss": // shadowsocks
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return err
		}
		p, _ := strconv.Atoi(port)
		req := gosocks5.NewRequest(gosocks5.CmdConnect, &gosocks5.Addr{
			Type: gosocks5.AddrDomain,
			Host: host,
			Port: uint16(p),
		})
		buf := bytes.Buffer{}
		if err := req.Write(&buf); err != nil {
			return err
		}
		b := buf.Bytes()
		if _, err := conn.Write(b[3:]); err != nil {
			return err
		}
		glog.V(LDEBUG).Infoln(req)
	case "socks", "socks5":
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return err
		}
		p, _ := strconv.Atoi(port)
		req := gosocks5.NewRequest(gosocks5.CmdConnect, &gosocks5.Addr{
			Type: gosocks5.AddrDomain,
			Host: host,
			Port: uint16(p),
		})
		if err := req.Write(conn); err != nil {
			return err
		}
		glog.V(LDEBUG).Infoln(req)

		rep, err := gosocks5.ReadReply(conn)
		if err != nil {
			return err
		}
		glog.V(LDEBUG).Infoln(rep)
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
