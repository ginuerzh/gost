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
	"sync"
	//"sync/atomic"
	"time"
)

var (
	connCounter int32
)

var (
	// tcp buffer pool
	tcpPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 32*1024)
		},
	}
	// udp buffer pool
	udpPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 32*1024)
		},
	}
)

func listenAndServe(arg Args) error {
	var ln net.Listener
	var err error

	switch arg.Transport {
	case "ws": // websocket connection
		return NewWs(arg).ListenAndServe()
	case "wss": // websocket security connection
		return NewWs(arg).listenAndServeTLS()
	case "tls": // tls connection
		ln, err = tls.Listen("tcp", arg.Addr,
			&tls.Config{Certificates: []tls.Certificate{arg.Cert}})
	case "tcp": // Local TCP port forwarding
		return listenAndServeTcpForward(arg)
	case "udp": // Local UDP port forwarding
		return listenAndServeUdpForward(arg)
	case "rtcp": // Remote TCP port forwarding
		return serveRTcpForward(arg)
	case "rudp": // Remote UDP port forwarding
		return serveRUdpForward(arg)
	default:
		ln, err = net.Listen("tcp", arg.Addr)
	}

	if err != nil {
		return err
	}

	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			glog.V(LWARNING).Infoln(err)
			continue
		}

		if tc, ok := conn.(*net.TCPConn); ok {
			tc.SetKeepAlive(true)
			tc.SetKeepAlivePeriod(time.Second * 180)
		}

		go handleConn(conn, arg)
	}
}

func listenAndServeTcpForward(arg Args) error {
	raddr, err := net.ResolveTCPAddr("tcp", arg.Remote)
	if err != nil {
		return err
	}

	ln, err := net.Listen("tcp", arg.Addr)
	if err != nil {
		return err
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			glog.V(LWARNING).Infoln(err)
			continue
		}
		go handleTcpForward(conn, raddr)
	}
}

func listenAndServeUdpForward(arg Args) error {
	laddr, err := net.ResolveUDPAddr("udp", arg.Addr)
	if err != nil {
		return err
	}

	raddr, err := net.ResolveUDPAddr("udp", arg.Remote)
	if err != nil {
		return err
	}

	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		glog.V(LWARNING).Infof("[udp] %s -> %s : %s", laddr, raddr, err)
		return err
	}
	defer conn.Close()

	if len(forwardArgs) == 0 {
		for {
			b := udpPool.Get().([]byte)

			n, addr, err := conn.ReadFromUDP(b)
			if err != nil {
				glog.V(LWARNING).Infof("[udp] %s -> %s : %s", laddr, raddr, err)
				continue
			}
			go func() {
				handleUdpForwardLocal(conn, addr, raddr, b[:n])
				udpPool.Put(b)
			}()
		}
	}

	rChan, wChan := make(chan *gosocks5.UDPDatagram, 32), make(chan *gosocks5.UDPDatagram, 32)

	go func() {
		for {
			b := make([]byte, 32*1024)
			n, addr, err := conn.ReadFromUDP(b)
			if err != nil {
				glog.V(LWARNING).Infof("[udp] %s -> %s : %s", laddr, raddr, err)
				return
			}

			select {
			case rChan <- gosocks5.NewUDPDatagram(gosocks5.NewUDPHeader(uint16(n), 0, ToSocksAddr(addr)), b[:n]):
			default:
				// glog.V(LWARNING).Infof("[udp-connect] %s -> %s : rbuf is full", laddr, raddr)
			}
		}
	}()

	go func() {
		for {
			dgram := <-wChan
			addr, err := net.ResolveUDPAddr("udp", dgram.Header.Addr.String())
			if err != nil {
				glog.V(LWARNING).Infof("[udp] %s <- %s : %s", laddr, raddr, err)
				continue // drop silently
			}
			if _, err = conn.WriteToUDP(dgram.Data, addr); err != nil {
				glog.V(LWARNING).Infof("[udp] %s <- %s : %s", laddr, raddr, err)
				return
			}
		}
	}()

	for {
		handleUdpForwardTunnel(laddr, raddr, rChan, wChan)
	}
}

func serveRTcpForward(arg Args) error {
	if len(forwardArgs) == 0 {
		return errors.New("rtcp: at least one -F must be assigned")
	}

	laddr, err := net.ResolveTCPAddr("tcp", arg.Addr)
	if err != nil {
		return err
	}
	raddr, err := net.ResolveTCPAddr("tcp", arg.Remote)
	if err != nil {
		return err
	}

	retry := 0
	for {
		conn, _, err := forwardChain(forwardArgs...)
		if err != nil {
			glog.V(LWARNING).Infof("[rtcp] %s - %s : %s", arg.Addr, arg.Remote, err)
			time.Sleep((1 << uint(retry)) * time.Second)
			if retry < 5 {
				retry++
			}
			continue
		}
		retry = 0

		if err := connectRTcpForward(conn, laddr, raddr); err != nil {
			conn.Close()
			time.Sleep(6 * time.Second)
		}
	}
}

func serveRUdpForward(arg Args) error {
	if len(forwardArgs) == 0 {
		return errors.New("rudp: at least one -F must be assigned")
	}

	laddr, err := net.ResolveUDPAddr("udp", arg.Addr)
	if err != nil {
		return err
	}
	raddr, err := net.ResolveUDPAddr("udp", arg.Remote)
	if err != nil {
		return err
	}

	retry := 0
	for {
		conn, _, err := forwardChain(forwardArgs...)
		if err != nil {
			glog.V(LWARNING).Infof("[rudp] %s - %s : %s", arg.Addr, arg.Remote, err)
			time.Sleep((1 << uint(retry)) * time.Second)
			if retry < 5 {
				retry++
			}
			continue
		}
		retry = 0

		if err := connectRUdpForward(conn, laddr, raddr); err != nil {
			conn.Close()
			time.Sleep(6 * time.Second)
		}
	}
}

func handleConn(conn net.Conn, arg Args) {
	defer conn.Close()

	// socks5 server supported methods
	selector := &serverSelector{
		methods: []uint8{
			gosocks5.MethodNoAuth,
			gosocks5.MethodUserPass,
			MethodTLS,
			MethodTLSAuth,
		},
		user: arg.User,
		cert: arg.Cert,
	}

	switch arg.Protocol {
	case "ss": // shadowsocks
		handleShadow(conn, arg)
		return
	case "http":
		req, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			glog.V(LWARNING).Infoln("[http]", err)
			return
		}
		handleHttpRequest(req, conn, arg)
		return
	case "socks", "socks5":
		conn = gosocks5.ServerConn(conn, selector)
		req, err := gosocks5.ReadRequest(conn)
		if err != nil {
			glog.V(LWARNING).Infoln("[socks5]", err)
			return
		}
		handleSocks5Request(req, conn)
		return
	}

	// http or socks5

	//b := make([]byte, 16*1024)
	b := tcpPool.Get().([]byte)
	defer tcpPool.Put(b)

	n, err := io.ReadAtLeast(conn, b, 2)
	if err != nil {
		glog.V(LWARNING).Infoln("[client]", err)
		return
	}

	if b[0] == gosocks5.Ver5 {
		mn := int(b[1]) // methods count
		length := 2 + mn
		if n < length {
			if _, err := io.ReadFull(conn, b[n:length]); err != nil {
				glog.V(LWARNING).Infoln("[socks5]", err)
				return
			}
		}
		methods := b[2 : 2+mn]
		method := selector.Select(methods...)
		if _, err := conn.Write([]byte{gosocks5.Ver5, method}); err != nil {
			glog.V(LWARNING).Infoln("[socks5] select:", err)
			return
		}
		c, err := selector.OnSelected(method, conn)
		if err != nil {
			glog.V(LWARNING).Infoln("[socks5] onselected:", err)
			return
		}
		conn = c

		req, err := gosocks5.ReadRequest(conn)
		if err != nil {
			glog.V(LWARNING).Infoln("[socks5] request:", err)
			return
		}
		handleSocks5Request(req, conn)
		return
	}

	req, err := http.ReadRequest(bufio.NewReader(newReqReader(b[:n], conn)))
	if err != nil {
		glog.V(LWARNING).Infoln("[http]", err)
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
		return net.DialTimeout("tcp", addr, time.Second*90)
	}

	var end Args
	conn, end, err = forwardChain(forwardArgs...)
	if err != nil {
		return nil, err
	}
	if err := establish(conn, addr, end); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// establish connection throughout the forward chain
func forwardChain(chain ...Args) (conn net.Conn, end Args, err error) {
	defer func() {
		if err != nil && conn != nil {
			conn.Close()
			conn = nil
		}
	}()

	end = chain[0]
	if conn, err = net.DialTimeout("tcp", end.Addr, time.Second*90); err != nil {
		return
	}

	tc := conn.(*net.TCPConn)
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(time.Second * 180) // 3min

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
		trans := arg.Transport
		if proto == "" {
			proto = "http" // default is http
		}
		if trans == "" { // default is tcp
			trans = "tcp"
		}
		glog.V(LDEBUG).Infof("forward: %s/%s %s", proto, trans, arg.Addr)
	}

	var tlsUsed bool

	switch arg.Transport {
	case "ws": // websocket connection
		conn, err = wsClient(conn, arg.Addr)
		if err != nil {
			return nil, err
		}
	case "wss": // websocket security
		tlsUsed = true
		conn, err = wssClient(conn, arg.Addr)
		if err != nil {
			return nil, err
		}
	case "tls": // tls connection
		tlsUsed = true
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
				//MethodTLS,
			},
			user: arg.User,
		}

		if !tlsUsed { // if transport is not security, enable security socks5
			selector.methods = append(selector.methods, MethodTLS)
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
