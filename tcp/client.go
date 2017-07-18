package tcp

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"

	"github.com/ginuerzh/gosocks4"
	"github.com/ginuerzh/gosocks5"
	"github.com/ginuerzh/gost"
	"github.com/ginuerzh/gost/socks"
	"github.com/go-log/log"
	ss "github.com/shadowsocks/shadowsocks-go/shadowsocks"
)

type nodeClient struct {
	options *nodeOptions
}

func (c *nodeClient) Connect() (net.Conn, error) {
	return net.Dial("tcp", c.options.BaseOptions().Addr)
}

func (c *nodeClient) Handshake(conn net.Conn) (net.Conn, error) {
	return conn, nil
}

func (c *nodeClient) Dial(conn net.Conn, addr string) (net.Conn, error) {
	if c.options.BaseOptions().Protocol == "socks5" {
		selector := &socks.ClientSelector{
			TLSConfig: &tls.Config{
				InsecureSkipVerify: !c.options.secureVerify,
				ServerName:         c.options.serverName,
			},
		}
		selector.AddMethod(
			gosocks5.MethodNoAuth,
			gosocks5.MethodUserPass,
			socks.MethodTLS,
		)
		users := c.options.BaseOptions().Users
		if len(users) > 0 {
			selector.User = &users[0]
		}

		cc := gosocks5.ClientConn(conn, selector)
		if err := cc.Handleshake(); err != nil {
			return nil, err
		}
		conn = cc
	}

	return c.dial(conn, addr)
}

func (c *nodeClient) dial(conn net.Conn, addr string) (net.Conn, error) {
	protocol := c.options.BaseOptions().Protocol
	switch protocol {
	case "ss": // shadowsocks
		rawaddr, err := ss.RawAddr(addr)
		if err != nil {
			return nil, err
		}

		var method, password string
		users := c.options.BaseOptions().Users
		if len(users) > 0 {
			method = users[0].Username()
			password, _ = users[0].Password()
		}

		cipher, err := ss.NewCipher(method, password)
		if err != nil {
			return nil, err
		}

		sc, err := ss.DialWithRawAddrConn(rawaddr, conn, cipher)
		if err != nil {
			return nil, err
		}
		conn = gost.ShadowConn(sc)

	case "socks5":
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		p, _ := strconv.Atoi(port)
		req := gosocks5.NewRequest(gosocks5.CmdConnect, &gosocks5.Addr{
			Type: gosocks5.AddrDomain,
			Host: host,
			Port: uint16(p),
		})
		if err := req.Write(conn); err != nil {
			return nil, err
		}
		log.Log("[socks5]", req)

		reply, err := gosocks5.ReadReply(conn)
		if err != nil {
			return nil, err
		}
		log.Log("[socks5]", reply)
		if reply.Rep != gosocks5.Succeeded {
			return nil, errors.New("Service unavailable")
		}

	case "socks4", "socks4a":
		atype := gosocks4.AddrDomain
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		p, _ := strconv.Atoi(port)

		if protocol == "socks4" {
			taddr, err := net.ResolveTCPAddr("tcp4", addr)
			if err != nil {
				return nil, err
			}
			host = taddr.IP.String()
			p = taddr.Port
			atype = gosocks4.AddrIPv4
		}
		req := gosocks4.NewRequest(gosocks4.CmdConnect,
			&gosocks4.Addr{Type: atype, Host: host, Port: uint16(p)}, nil)
		if err := req.Write(conn); err != nil {
			return nil, err
		}
		log.Logf("[%s] %s", protocol, req)

		reply, err := gosocks4.ReadReply(conn)
		if err != nil {
			return nil, err
		}
		log.Logf("[%s] %s", protocol, reply)

		if reply.Code != gosocks4.Granted {
			return nil, fmt.Errorf("%s: code=%d", protocol, reply.Code)
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
		users := c.options.BaseOptions().Users
		if len(users) > 0 {
			user := users[0]
			s := user.String()
			if _, set := user.Password(); !set {
				s += ":"
			}
			req.Header.Set("Proxy-Authorization",
				"Basic "+base64.StdEncoding.EncodeToString([]byte(s)))
		}
		if err := req.Write(conn); err != nil {
			return nil, err
		}
		//if glog.V(LDEBUG) {
		dump, _ := httputil.DumpRequest(req, false)
		log.Log(string(dump))
		//}

		resp, err := http.ReadResponse(bufio.NewReader(conn), req)
		if err != nil {
			return nil, err
		}
		//if glog.V(LDEBUG) {
		dump, _ = httputil.DumpResponse(resp, false)
		log.Log(string(dump))
		//}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("%d %s", resp.StatusCode, resp.Status)
		}
	}

	return conn, nil
}
