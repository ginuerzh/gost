package gost

import (
	"bufio"
	"context"
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
	"github.com/go-log/log"
	ss "github.com/shadowsocks/shadowsocks-go/shadowsocks"
)

type Client struct {
	Protocol  string
	Transport *Transport
	User      *url.Userinfo
}

func (c *Client) Dial(ctx context.Context, addr string) (net.Conn, error) {
	return c.Transport.Dial(ctx, addr)
}

func (c *Client) Connect(ctx context.Context, conn net.Conn, addr string) (net.Conn, error) {
	protocol := c.Protocol

	switch protocol {
	case "ss": // shadowsocks
		rawaddr, err := ss.RawAddr(addr)
		if err != nil {
			return nil, err
		}

		var method, password string
		if c.User != nil {
			method = c.User.Username()
			password, _ = c.User.Password()
		}

		cipher, err := ss.NewCipher(method, password)
		if err != nil {
			return nil, err
		}

		sc, err := ss.DialWithRawAddrConn(rawaddr, conn, cipher)
		if err != nil {
			return nil, err
		}
		conn = ShadowConn(sc)

	case "socks", "socks5":
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
		if c.User != nil {
			s := c.User.String()
			if _, set := c.User.Password(); !set {
				s += ":"
			}
			req.Header.Set("Proxy-Authorization",
				"Basic "+base64.StdEncoding.EncodeToString([]byte(s)))
		}
		if err := req.Write(conn); err != nil {
			return nil, err
		}

		if Debug {
			dump, _ := httputil.DumpRequest(req, false)
			log.Log(string(dump))
		}

		resp, err := http.ReadResponse(bufio.NewReader(conn), req)
		if err != nil {
			return nil, err
		}

		if Debug {
			dump, _ := httputil.DumpResponse(resp, false)
			log.Log(string(dump))
		}

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("%d %s", resp.StatusCode, resp.Status)
		}
	}

	return conn, nil
}

type Transport struct {
	Dial            func(ctx context.Context, addr string) (net.Conn, error)
	TLSClientConfig *tls.Config
}
