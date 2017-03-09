package gost

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/ginuerzh/gosocks4"
	"github.com/ginuerzh/gosocks5"
	"github.com/golang/glog"
	ss "github.com/shadowsocks/shadowsocks-go/shadowsocks"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

type ProxyConn struct {
	conn           net.Conn
	Node           ProxyNode
	handshaked     bool
	handshakeMutex sync.Mutex
	handshakeErr   error
}

func NewProxyConn(conn net.Conn, node ProxyNode) *ProxyConn {
	return &ProxyConn{
		conn: conn,
		Node: node,
	}
}

// Handshake handshake with this proxy node based on the proxy node info: transport, protocol, authentication, etc.
//
// NOTE: any HTTP2 scheme will be treated as http (for protocol) or tls (for transport).
func (c *ProxyConn) Handshake() error {
	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()

	if err := c.handshakeErr; err != nil {
		return err
	}
	if c.handshaked {
		return nil
	}
	c.handshakeErr = c.handshake()
	return c.handshakeErr
}

func (c *ProxyConn) handshake() error {
	var tlsUsed bool

	switch c.Node.Transport {
	case "ws": // websocket connection
		u := url.URL{Scheme: "ws", Host: c.Node.Addr, Path: "/ws"}
		conn, err := WebsocketClientConn(u.String(), c.conn, nil)
		if err != nil {
			return err
		}
		c.conn = conn
	case "wss": // websocket security
		tlsUsed = true
		u := url.URL{Scheme: "wss", Host: c.Node.Addr, Path: "/ws"}
		config := &tls.Config{
			InsecureSkipVerify: c.Node.insecureSkipVerify(),
			ServerName:         c.Node.serverName,
		}
		conn, err := WebsocketClientConn(u.String(), c.conn, config)
		if err != nil {
			return err
		}
		c.conn = conn
	case "tls", "http2": // tls connection
		tlsUsed = true
		cfg := &tls.Config{
			InsecureSkipVerify: c.Node.insecureSkipVerify(),
			ServerName:         c.Node.serverName,
		}
		c.conn = tls.Client(c.conn, cfg)
	case "h2": // same as http2, but just set a flag for later using.
		tlsUsed = true
	case "kcp": // kcp connection
		tlsUsed = true
	default:
	}

	switch c.Node.Protocol {
	case "socks", "socks5": // socks5 handshake with auth and tls supported
		selector := &clientSelector{
			methods: []uint8{
				gosocks5.MethodNoAuth,
				gosocks5.MethodUserPass,
				//MethodTLS,
			},
		}

		if len(c.Node.Users) > 0 {
			selector.user = c.Node.Users[0]
		}

		if !tlsUsed { // if transport is not security, enable security socks5
			selector.methods = append(selector.methods, MethodTLS)
			selector.tlsConfig = &tls.Config{
				InsecureSkipVerify: c.Node.insecureSkipVerify(),
				ServerName:         c.Node.serverName,
			}
		}

		conn := gosocks5.ClientConn(c.conn, selector)
		if err := conn.Handleshake(); err != nil {
			return err
		}
		c.conn = conn
	case "ss": // shadowsocks
		// nothing to do
	case "http", "http2":
		fallthrough
	default:
	}

	c.handshaked = true

	return nil
}

// Connect connect to addr through this proxy node
func (c *ProxyConn) Connect(addr string) error {
	switch c.Node.Protocol {
	case "ss": // shadowsocks
		rawaddr, err := ss.RawAddr(addr)
		if err != nil {
			return err
		}

		var method, password string
		if len(c.Node.Users) > 0 {
			method = c.Node.Users[0].Username()
			password, _ = c.Node.Users[0].Password()
		}
		if c.Node.getBool("ota") && !strings.HasSuffix(method, "-auth") {
			method += "-auth"
		}

		cipher, err := ss.NewCipher(method, password)
		if err != nil {
			return err
		}

		ssc, err := ss.DialWithRawAddrConn(rawaddr, c.conn, cipher)
		if err != nil {
			return err
		}
		c.conn = &shadowConn{conn: ssc}
		return nil
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
		if err := req.Write(c); err != nil {
			return err
		}
		glog.V(LDEBUG).Infoln("[socks5]", req)

		reply, err := gosocks5.ReadReply(c)
		if err != nil {
			return err
		}
		glog.V(LDEBUG).Infoln("[socks5]", reply)
		if reply.Rep != gosocks5.Succeeded {
			return errors.New("Service unavailable")
		}
	case "socks4", "socks4a":
		atype := gosocks4.AddrDomain
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return err
		}
		p, _ := strconv.Atoi(port)

		if c.Node.Protocol == "socks4" {
			taddr, err := net.ResolveTCPAddr("tcp4", addr)
			if err != nil {
				return err
			}
			host = taddr.IP.String()
			p = taddr.Port
			atype = gosocks4.AddrIPv4
		}
		req := gosocks4.NewRequest(gosocks4.CmdConnect,
			&gosocks4.Addr{Type: atype, Host: host, Port: uint16(p)}, nil)
		if err := req.Write(c); err != nil {
			return err
		}
		glog.V(LDEBUG).Infof("[%s] %s", c.Node.Protocol, req)

		reply, err := gosocks4.ReadReply(c)
		if err != nil {
			return err
		}
		glog.V(LDEBUG).Infof("[%s] %s", c.Node.Protocol, reply)

		if reply.Code != gosocks4.Granted {
			return errors.New(fmt.Sprintf("%s: code=%d", c.Node.Protocol, reply.Code))
		}
	case "http":
		fallthrough
	default:
		req := &http.Request{
			Method:     http.MethodConnect,
			URL:        &url.URL{Host: addr},
			Host:       addr,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     make(http.Header),
		}
		req.Header.Set("Proxy-Connection", "keep-alive")
		if len(c.Node.Users) > 0 {
			user := c.Node.Users[0]
			s := user.String()
			if _, set := user.Password(); !set {
				s += ":"
			}
			req.Header.Set("Proxy-Authorization",
				"Basic "+base64.StdEncoding.EncodeToString([]byte(s)))
		}
		if err := req.Write(c); err != nil {
			return err
		}
		if glog.V(LDEBUG) {
			dump, _ := httputil.DumpRequest(req, false)
			glog.Infoln(string(dump))
		}

		resp, err := http.ReadResponse(bufio.NewReader(c), req)
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

func (c *ProxyConn) Read(b []byte) (n int, err error) {
	return c.conn.Read(b)
}

func (c *ProxyConn) Write(b []byte) (n int, err error) {
	return c.conn.Write(b)
}

func (c *ProxyConn) Close() error {
	return c.conn.Close()
}

func (c *ProxyConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *ProxyConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *ProxyConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *ProxyConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *ProxyConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}
