package gost

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"

	"github.com/ginuerzh/gosocks4"
	"github.com/ginuerzh/gosocks5"
	"github.com/go-log/log"
)

const (
	MethodTLS     uint8 = 0x80 // extended method for tls
	MethodTLSAuth uint8 = 0x82 // extended method for tls+auth
)

const (
	CmdUdpTun uint8 = 0xF3 // extended method for udp over tcp
)

type ClientSelector struct {
	methods   []uint8
	User      *url.Userinfo
	TLSConfig *tls.Config
}

func (selector *ClientSelector) Methods() []uint8 {
	return selector.methods
}

func (selector *ClientSelector) AddMethod(methods ...uint8) {
	selector.methods = append(selector.methods, methods...)
}

func (selector *ClientSelector) Select(methods ...uint8) (method uint8) {
	return
}

func (selector *ClientSelector) OnSelected(method uint8, conn net.Conn) (net.Conn, error) {
	switch method {
	case MethodTLS:
		conn = tls.Client(conn, selector.TLSConfig)

	case gosocks5.MethodUserPass, MethodTLSAuth:
		if method == MethodTLSAuth {
			conn = tls.Client(conn, selector.TLSConfig)
		}

		var username, password string
		if selector.User != nil {
			username = selector.User.Username()
			password, _ = selector.User.Password()
		}

		req := gosocks5.NewUserPassRequest(gosocks5.UserPassVer, username, password)
		if err := req.Write(conn); err != nil {
			log.Log("[socks5]", err)
			return nil, err
		}
		if Debug {
			log.Log("[socks5]", req)
		}
		resp, err := gosocks5.ReadUserPassResponse(conn)
		if err != nil {
			log.Log("[socks5]", err)
			return nil, err
		}
		if Debug {
			log.Log("[socks5]", resp)
		}
		if resp.Status != gosocks5.Succeeded {
			return nil, gosocks5.ErrAuthFailure
		}
	case gosocks5.MethodNoAcceptable:
		return nil, gosocks5.ErrBadMethod
	}

	return conn, nil
}

type socks5Connector struct {
	User *url.Userinfo
}

func SOCKS5Connector(user *url.Userinfo) Connector {
	return &socks5Connector{User: user}
}

func (c *socks5Connector) Connect(ctx context.Context, conn net.Conn, addr string) (net.Conn, error) {
	selector := &ClientSelector{
		TLSConfig: &tls.Config{InsecureSkipVerify: true},
		User:      c.User,
	}
	selector.AddMethod(
		gosocks5.MethodNoAuth,
		gosocks5.MethodUserPass,
		MethodTLS,
	)

	cc := gosocks5.ClientConn(conn, selector)
	if err := cc.Handleshake(); err != nil {
		return nil, err
	}
	conn = cc

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

	if Debug {
		log.Log("[socks5]", req)
	}

	reply, err := gosocks5.ReadReply(conn)
	if err != nil {
		return nil, err
	}

	if Debug {
		log.Log("[socks5]", reply)
	}

	if reply.Rep != gosocks5.Succeeded {
		return nil, errors.New("Service unavailable")
	}

	return conn, nil
}

type socks4Connector struct{}

func SOCKS4Connector() Connector {
	return &socks4Connector{}
}

func (c *socks4Connector) Connect(ctx context.Context, conn net.Conn, addr string) (net.Conn, error) {
	taddr, err := net.ResolveTCPAddr("tcp4", addr)
	if err != nil {
		return nil, err
	}

	req := gosocks4.NewRequest(gosocks4.CmdConnect,
		&gosocks4.Addr{
			Type: gosocks4.AddrIPv4,
			Host: taddr.IP.String(),
			Port: uint16(taddr.Port),
		}, nil,
	)
	if err := req.Write(conn); err != nil {
		return nil, err
	}

	if Debug {
		log.Logf("[socks4] %s", req)
	}

	reply, err := gosocks4.ReadReply(conn)
	if err != nil {
		return nil, err
	}

	if Debug {
		log.Logf("[socks4] %s", reply)
	}

	if reply.Code != gosocks4.Granted {
		return nil, fmt.Errorf("[socks4] %d", reply.Code)
	}

	return conn, nil
}

type socks4aConnector struct{}

func SOCKS4AConnector() Connector {
	return &socks4aConnector{}
}

func (c *socks4aConnector) Connect(ctx context.Context, conn net.Conn, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	p, _ := strconv.Atoi(port)

	req := gosocks4.NewRequest(gosocks4.CmdConnect,
		&gosocks4.Addr{Type: gosocks4.AddrDomain, Host: host, Port: uint16(p)}, nil)
	if err := req.Write(conn); err != nil {
		return nil, err
	}

	if Debug {
		log.Logf("[socks4] %s", req)
	}

	reply, err := gosocks4.ReadReply(conn)
	if err != nil {
		return nil, err
	}

	if Debug {
		log.Logf("[socks4] %s", reply)
	}

	if reply.Code != gosocks4.Granted {
		return nil, fmt.Errorf("[socks4] %d", reply.Code)
	}

	return conn, nil
}
