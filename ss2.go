package gost

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/url"
	"time"

	"github.com/ginuerzh/gosocks5"
	"github.com/go-log/log"
	"github.com/shadowsocks/go-shadowsocks2/core"
)

type shadow2Connector struct {
	Cipher *url.Userinfo
}

// Shadow2Connector creates a Connector for go-shadowsocks2 proxy client.
// It accepts a cipher info for shadowsocks data encryption/decryption.
// The cipher must not be nil.
func Shadow2Connector(cipher *url.Userinfo) Connector {
	return &shadow2Connector{Cipher: cipher}
}

func (c *shadow2Connector) Connect(conn net.Conn, addr string, options ...ConnectOption) (net.Conn, error) {
	opts := &ConnectOptions{}
	for _, option := range options {
		option(opts)
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = ConnectTimeout
	}

	conn.SetDeadline(time.Now().Add(timeout))
	defer conn.SetDeadline(time.Time{})

	socksAddr, err := gosocks5.NewAddr(addr)
	if err != nil {
		return nil, err
	}

	rawaddr := sPool.Get().([]byte)
	defer sPool.Put(rawaddr)

	n, err := socksAddr.Encode(rawaddr)
	if err != nil {
		return nil, err
	}

	var method, password string
	cp := opts.User
	if cp == nil {
		cp = c.Cipher
	}
	if cp != nil {
		method = cp.Username()
		password, _ = cp.Password()
	}

	cipher, err := core.PickCipher(method, nil, password)
	if err != nil {
		return nil, err
	}
	conn = cipher.StreamConn(conn)
	if _, err := conn.Write(rawaddr[:n]); err != nil {
		return nil, err
	}

	return conn, nil
}

type shadow2Handler struct {
	options *HandlerOptions
}

// Shadow2Handler creates a server Handler for go-shadowsocks2 proxy server.
func Shadow2Handler(opts ...HandlerOption) Handler {
	h := &shadow2Handler{}
	h.Init(opts...)

	return h
}

func (h *shadow2Handler) Init(options ...HandlerOption) {
	if h.options == nil {
		h.options = &HandlerOptions{}
	}

	for _, opt := range options {
		opt(h.options)
	}
}

func (h *shadow2Handler) Handle(conn net.Conn) {
	defer conn.Close()

	var method, password string
	users := h.options.Users
	if len(users) > 0 {
		method = users[0].Username()
		password, _ = users[0].Password()
	}

	cipher, err := core.PickCipher(method, nil, password)
	if err != nil {
		log.Logf("[ss2] %s -> %s : %s",
			conn.RemoteAddr(), conn.LocalAddr(), err)
		return
	}

	conn = cipher.StreamConn(conn)
	conn.SetReadDeadline(time.Now().Add(ReadTimeout))

	addr, err := readAddr(conn)
	if err != nil {
		log.Logf("[ss2] %s -> %s : %s",
			conn.RemoteAddr(), conn.LocalAddr(), err)
		return
	}

	// clear timer
	conn.SetReadDeadline(time.Time{})

	host := addr.String()
	log.Logf("[ss2] %s -> %s -> %s",
		conn.RemoteAddr(), h.options.Node.String(), host)

	if !Can("tcp", host, h.options.Whitelist, h.options.Blacklist) {
		log.Logf("[ss2] %s - %s : Unauthorized to tcp connect to %s",
			conn.RemoteAddr(), conn.LocalAddr(), host)
		return
	}

	if h.options.Bypass.Contains(host) {
		log.Logf("[ss2] %s - %s : Bypass %s",
			conn.RemoteAddr(), conn.LocalAddr(), host)
		return
	}

	retries := 1
	if h.options.Chain != nil && h.options.Chain.Retries > 0 {
		retries = h.options.Chain.Retries
	}
	if h.options.Retries > 0 {
		retries = h.options.Retries
	}

	var cc net.Conn
	var route *Chain
	for i := 0; i < retries; i++ {
		route, err = h.options.Chain.selectRouteFor(host)
		if err != nil {
			log.Logf("[ss2] %s -> %s : %s",
				conn.RemoteAddr(), conn.LocalAddr(), err)
			continue
		}

		buf := bytes.Buffer{}
		fmt.Fprintf(&buf, "%s -> %s -> ",
			conn.RemoteAddr(), h.options.Node.String())
		for _, nd := range route.route {
			fmt.Fprintf(&buf, "%d@%s -> ", nd.ID, nd.String())
		}
		fmt.Fprintf(&buf, "%s", host)
		log.Log("[route]", buf.String())

		cc, err = route.Dial(host,
			TimeoutChainOption(h.options.Timeout),
			HostsChainOption(h.options.Hosts),
			ResolverChainOption(h.options.Resolver),
		)
		if err == nil {
			break
		}
		log.Logf("[ss2] %s -> %s : %s",
			conn.RemoteAddr(), conn.LocalAddr(), err)
	}

	if err != nil {
		return
	}
	defer cc.Close()

	log.Logf("[ss2] %s <-> %s", conn.RemoteAddr(), host)
	transport(conn, cc)
	log.Logf("[ss2] %s >-< %s", conn.RemoteAddr(), host)
}

func readAddr(r io.Reader) (*gosocks5.Addr, error) {
	addr := &gosocks5.Addr{}
	b := sPool.Get().([]byte)
	defer sPool.Put(b)

	_, err := io.ReadFull(r, b[:1])
	if err != nil {
		return nil, err
	}
	addr.Type = b[0]

	switch addr.Type {
	case gosocks5.AddrIPv4:
		_, err = io.ReadFull(r, b[:net.IPv4len])
		addr.Host = net.IP(b[0:net.IPv4len]).String()
	case gosocks5.AddrIPv6:
		_, err = io.ReadFull(r, b[:net.IPv6len])
		addr.Host = net.IP(b[0:net.IPv6len]).String()
	case gosocks5.AddrDomain:
		if _, err = io.ReadFull(r, b[:1]); err != nil {
			return nil, err
		}
		addrlen := int(b[0])
		_, err = io.ReadFull(r, b[:addrlen])
		addr.Host = string(b[:addrlen])
	default:
		return nil, gosocks5.ErrBadAddrType
	}
	if err != nil {
		return nil, err
	}

	_, err = io.ReadFull(r, b[:2])
	addr.Port = binary.BigEndian.Uint16(b[:2])
	return addr, err
}
