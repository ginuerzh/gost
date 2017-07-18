package socks

import (
	"crypto/tls"
	"net"
	"net/url"

	"github.com/ginuerzh/gosocks5"
	"github.com/golang/glog"
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
			glog.Infoln("socks5 auth:", err)
			return nil, err
		}
		glog.Infoln(req)

		resp, err := gosocks5.ReadUserPassResponse(conn)
		if err != nil {
			glog.Infoln("socks5 auth:", err)
			return nil, err
		}
		glog.Infoln(resp)

		if resp.Status != gosocks5.Succeeded {
			return nil, gosocks5.ErrAuthFailure
		}
	case gosocks5.MethodNoAcceptable:
		return nil, gosocks5.ErrBadMethod
	}

	return conn, nil
}

type ServerSelector struct {
	methods   []uint8
	users     []*url.Userinfo
	tlsConfig *tls.Config
}

func (selector *ServerSelector) Methods() []uint8 {
	return selector.methods
}

func (selector *ServerSelector) Select(methods ...uint8) (method uint8) {
	glog.Infof("%d %d %v", gosocks5.Ver5, len(methods), methods)

	method = gosocks5.MethodNoAuth
	for _, m := range methods {
		if m == MethodTLS {
			method = m
			break
		}
	}

	// when user/pass is set, auth is mandatory
	if selector.users != nil {
		if method == gosocks5.MethodNoAuth {
			method = gosocks5.MethodUserPass
		}
		if method == MethodTLS {
			method = MethodTLSAuth
		}
	}

	return
}

func (selector *ServerSelector) OnSelected(method uint8, conn net.Conn) (net.Conn, error) {
	glog.Infof("%d %d", gosocks5.Ver5, method)

	switch method {
	case MethodTLS:
		conn = tls.Server(conn, selector.tlsConfig)

	case gosocks5.MethodUserPass, MethodTLSAuth:
		if method == MethodTLSAuth {
			conn = tls.Server(conn, selector.tlsConfig)
		}

		req, err := gosocks5.ReadUserPassRequest(conn)
		if err != nil {
			glog.Infoln("[socks5-auth]", err)
			return nil, err
		}
		glog.Infoln("[socks5]", req.String())

		valid := false
		for _, user := range selector.users {
			username := user.Username()
			password, _ := user.Password()
			if (req.Username == username && req.Password == password) ||
				(req.Username == username && password == "") ||
				(username == "" && req.Password == password) {
				valid = true
				break
			}
		}
		if len(selector.users) > 0 && !valid {
			resp := gosocks5.NewUserPassResponse(gosocks5.UserPassVer, gosocks5.Failure)
			if err := resp.Write(conn); err != nil {
				glog.Infoln("[socks5-auth]", err)
				return nil, err
			}
			glog.Infoln("[socks5]", resp)
			glog.Infoln("[socks5-auth] proxy authentication required")

			return nil, gosocks5.ErrAuthFailure
		}

		resp := gosocks5.NewUserPassResponse(gosocks5.UserPassVer, gosocks5.Succeeded)
		if err := resp.Write(conn); err != nil {
			glog.Infoln("[socks5-auth]", err)
			return nil, err
		}
		glog.Infoln(resp)

	case gosocks5.MethodNoAcceptable:
		return nil, gosocks5.ErrBadMethod
	}

	return conn, nil
}
