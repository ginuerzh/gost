package gost

import (
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

type clientSelector struct {
	methods   []uint8
	User      *url.Userinfo
	TLSConfig *tls.Config
}

func (selector *clientSelector) Methods() []uint8 {
	return selector.methods
}

func (selector *clientSelector) AddMethod(methods ...uint8) {
	selector.methods = append(selector.methods, methods...)
}

func (selector *clientSelector) Select(methods ...uint8) (method uint8) {
	return
}

func (selector *clientSelector) OnSelected(method uint8, conn net.Conn) (net.Conn, error) {
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

type serverSelector struct {
	methods   []uint8
	Users     []*url.Userinfo
	TLSConfig *tls.Config
}

func (selector *serverSelector) Methods() []uint8 {
	return selector.methods
}

func (selector *serverSelector) AddMethod(methods ...uint8) {
	selector.methods = append(selector.methods, methods...)
}

func (selector *serverSelector) Select(methods ...uint8) (method uint8) {
	if Debug {
		log.Logf("[socks5] %d %d %v", gosocks5.Ver5, len(methods), methods)
	}
	method = gosocks5.MethodNoAuth
	for _, m := range methods {
		if m == MethodTLS {
			method = m
			break
		}
	}

	// when user/pass is set, auth is mandatory
	if len(selector.Users) > 0 {
		if method == gosocks5.MethodNoAuth {
			method = gosocks5.MethodUserPass
		}
		if method == MethodTLS {
			method = MethodTLSAuth
		}
	}

	return
}

func (selector *serverSelector) OnSelected(method uint8, conn net.Conn) (net.Conn, error) {
	if Debug {
		log.Logf("[socks5] %d %d", gosocks5.Ver5, method)
	}
	switch method {
	case MethodTLS:
		conn = tls.Server(conn, selector.TLSConfig)

	case gosocks5.MethodUserPass, MethodTLSAuth:
		if method == MethodTLSAuth {
			conn = tls.Server(conn, selector.TLSConfig)
		}

		req, err := gosocks5.ReadUserPassRequest(conn)
		if err != nil {
			log.Log("[socks5]", err)
			return nil, err
		}
		if Debug {
			log.Log("[socks5]", req.String())
		}
		valid := false
		for _, user := range selector.Users {
			username := user.Username()
			password, _ := user.Password()
			if (req.Username == username && req.Password == password) ||
				(req.Username == username && password == "") ||
				(username == "" && req.Password == password) {
				valid = true
				break
			}
		}
		if len(selector.Users) > 0 && !valid {
			resp := gosocks5.NewUserPassResponse(gosocks5.UserPassVer, gosocks5.Failure)
			if err := resp.Write(conn); err != nil {
				log.Log("[socks5]", err)
				return nil, err
			}
			if Debug {
				log.Log("[socks5]", resp)
			}
			log.Log("[socks5] proxy authentication required")
			return nil, gosocks5.ErrAuthFailure
		}

		resp := gosocks5.NewUserPassResponse(gosocks5.UserPassVer, gosocks5.Succeeded)
		if err := resp.Write(conn); err != nil {
			log.Log("[socks5]", err)
			return nil, err
		}
		if Debug {
			log.Log("[socks5]", resp)
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

func (c *socks5Connector) Connect(conn net.Conn, addr string) (net.Conn, error) {
	selector := &clientSelector{
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

func (c *socks4Connector) Connect(conn net.Conn, addr string) (net.Conn, error) {
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

func (c *socks4aConnector) Connect(conn net.Conn, addr string) (net.Conn, error) {
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

type socks5Handler struct {
	selector *serverSelector
	options  *HandlerOptions
}

func SOCKS5Handler(opts ...HandlerOption) Handler {
	options := &HandlerOptions{
		Chain: new(Chain),
	}
	for _, opt := range opts {
		opt(options)
	}

	selector := &serverSelector{ // socks5 server selector
		Users:     options.Users,
		TLSConfig: options.TLSConfig,
	}
	// methods that socks5 server supported
	selector.AddMethod(
		gosocks5.MethodNoAuth,
		gosocks5.MethodUserPass,
		MethodTLS,
		MethodTLSAuth,
	)
	return &socks5Handler{
		options:  options,
		selector: selector,
	}
}

func (h *socks5Handler) Handle(conn net.Conn) {
	conn = gosocks5.ServerConn(conn, h.selector)
	req, err := gosocks5.ReadRequest(conn)
	if err != nil {
		log.Log("[socks5]", err)
		return
	}

	if Debug {
		log.Logf("[socks5] %s -> %s\n%s", conn.RemoteAddr(), req.Addr, req)
	}
	switch req.Cmd {
	case gosocks5.CmdConnect:
		log.Logf("[socks5-connect] %s -> %s", conn.RemoteAddr(), req.Addr)
		h.handleConnect(conn, req)

	case gosocks5.CmdBind:
		log.Logf("[socks5-bind] %s - %s", conn.RemoteAddr(), req.Addr)
		h.handleBind(conn, req)

	case gosocks5.CmdUdp:
		log.Logf("[socks5-udp] %s - %s", conn.RemoteAddr(), req.Addr)
		//s.handleUDPRelay(req)

	case CmdUdpTun:
		log.Logf("[socks5-rudp] %s - %s", conn.RemoteAddr(), req.Addr)
		//s.handleUDPTunnel(req)

	default:
		log.Log("[socks5] Unrecognized request:", req.Cmd)
	}
}

func (h *socks5Handler) handleConnect(conn net.Conn, req *gosocks5.Request) {
	addr := req.Addr.String()

	//! if !s.Base.Node.Can("tcp", addr) {
	//! 	glog.Errorf("Unauthorized to tcp connect to %s", addr)
	//! 	rep := gosocks5.NewReply(gosocks5.NotAllowed, nil)
	//! 	rep.Write(s.conn)
	//! 	return
	//! }

	cc, err := h.options.Chain.Dial(addr)
	if err != nil {
		log.Logf("[socks5-connect] %s -> %s : %s", conn.RemoteAddr(), req.Addr, err)
		rep := gosocks5.NewReply(gosocks5.HostUnreachable, nil)
		rep.Write(conn)
		if Debug {
			log.Logf("[socks5-connect] %s <- %s\n%s", conn.RemoteAddr(), req.Addr, rep)
		}
		return
	}
	defer cc.Close()

	rep := gosocks5.NewReply(gosocks5.Succeeded, nil)
	if err := rep.Write(conn); err != nil {
		log.Logf("[socks5-connect] %s <- %s : %s", conn.RemoteAddr(), req.Addr, err)
		return
	}
	if Debug {
		log.Logf("[socks5-connect] %s <- %s\n%s", conn.RemoteAddr(), req.Addr, rep)
	}
	log.Logf("[socks5-connect] %s <-> %s", conn.RemoteAddr(), req.Addr)
	transport(conn, cc)
	log.Logf("[socks5-connect] %s >-< %s", conn.RemoteAddr(), req.Addr)
}

func (h *socks5Handler) handleBind(conn net.Conn, req *gosocks5.Request) {
	// TODO: socks5 bind
}
