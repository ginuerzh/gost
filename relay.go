package gost

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/go-gost/relay"
	"github.com/go-log/log"
)

type relayConnector struct {
	user       *url.Userinfo
	remoteAddr string
}

// RelayConnector creates a Connector for TCP/UDP data relay.
func RelayConnector(user *url.Userinfo) Connector {
	return &relayConnector{
		user: user,
	}
}

func (c *relayConnector) Connect(conn net.Conn, address string, options ...ConnectOption) (net.Conn, error) {
	return conn, nil
}

func (c *relayConnector) ConnectContext(ctx context.Context, conn net.Conn, network, address string, options ...ConnectOption) (net.Conn, error) {
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

	var udp bool
	if network == "udp" || network == "udp4" || network == "udp6" {
		udp = true
	}

	req := &relay.Request{
		Version: relay.Version1,
	}
	if udp {
		req.Flags |= relay.FUDP
	}

	if c.user != nil {
		pwd, _ := c.user.Password()
		req.Features = append(req.Features, &relay.UserAuthFeature{
			Username: c.user.Username(),
			Password: pwd,
		})
	}
	if address != "" {
		host, port, _ := net.SplitHostPort(address)
		nport, _ := strconv.ParseUint(port, 10, 16)
		if host == "" {
			host = net.IPv4zero.String()
		}

		if nport > 0 {
			var atype uint8
			ip := net.ParseIP(host)
			if ip == nil {
				atype = relay.AddrDomain
			} else if ip.To4() == nil {
				atype = relay.AddrIPv6
			} else {
				atype = relay.AddrIPv4
			}

			req.Features = append(req.Features, &relay.AddrFeature{
				AType: atype,
				Host:  host,
				Port:  uint16(nport),
			})
		}
	}

	rc := &relayConn{
		udp:  udp,
		Conn: conn,
	}

	// write the header at once.
	if opts.NoDelay {
		if _, err := req.WriteTo(rc); err != nil {
			return nil, err
		}
	} else {
		if _, err := req.WriteTo(&rc.wbuf); err != nil {
			return nil, err
		}
	}

	return rc, nil
}

type relayHandler struct {
	*baseForwardHandler
}

// RelayHandler creates a server Handler for TCP/UDP relay server.
func RelayHandler(raddr string, opts ...HandlerOption) Handler {
	h := &relayHandler{
		baseForwardHandler: &baseForwardHandler{
			raddr:   raddr,
			group:   NewNodeGroup(),
			options: &HandlerOptions{},
		},
	}
	for _, opt := range opts {
		opt(h.options)
	}
	return h
}

func (h *relayHandler) Init(options ...HandlerOption) {
	h.baseForwardHandler.Init(options...)
}

func (h *relayHandler) Handle(conn net.Conn) {
	defer conn.Close()

	req := &relay.Request{}
	if _, err := req.ReadFrom(conn); err != nil {
		log.Logf("[relay] %s - %s : %s", conn.RemoteAddr(), conn.LocalAddr(), err)
		return
	}

	if req.Version != relay.Version1 {
		log.Logf("[relay] %s - %s : bad version", conn.RemoteAddr(), conn.LocalAddr())
		return
	}

	var user, pass string
	var raddr string
	for _, f := range req.Features {
		if f.Type() == relay.FeatureUserAuth {
			feature := f.(*relay.UserAuthFeature)
			user, pass = feature.Username, feature.Password
		}
		if f.Type() == relay.FeatureAddr {
			feature := f.(*relay.AddrFeature)
			raddr = net.JoinHostPort(feature.Host, strconv.Itoa(int(feature.Port)))
		}
	}

	resp := &relay.Response{
		Version: relay.Version1,
		Status:  relay.StatusOK,
	}
	if h.options.Authenticator != nil && !h.options.Authenticator.Authenticate(user, pass) {
		resp.Status = relay.StatusUnauthorized
		resp.WriteTo(conn)
		log.Logf("[relay] %s -> %s : %s unauthorized", conn.RemoteAddr(), conn.LocalAddr(), user)
		return
	}

	if raddr != "" {
		if len(h.group.Nodes()) > 0 {
			resp.Status = relay.StatusForbidden
			resp.WriteTo(conn)
			log.Logf("[relay] %s -> %s : relay to %s is forbidden",
				conn.RemoteAddr(), conn.LocalAddr(), raddr)
			return
		}
	} else {
		if len(h.group.Nodes()) == 0 {
			resp.Status = relay.StatusBadRequest
			resp.WriteTo(conn)
			log.Logf("[relay] %s -> %s : bad request, target addr is needed",
				conn.RemoteAddr(), conn.LocalAddr())
			return
		}
	}

	udp := (req.Flags & relay.FUDP) == relay.FUDP
	retries := 1
	if h.options.Chain != nil && h.options.Chain.Retries > 0 {
		retries = h.options.Chain.Retries
	}
	if h.options.Retries > 0 {
		retries = h.options.Retries
	}

	network := "tcp"
	if udp {
		network = "udp"
	}
	if !Can(network, raddr, h.options.Whitelist, h.options.Blacklist) {
		resp.Status = relay.StatusForbidden
		resp.WriteTo(conn)
		log.Logf("[relay] %s -> %s : relay to %s is forbidden",
			conn.RemoteAddr(), conn.LocalAddr(), raddr)
		return
	}

	ctx := context.TODO()
	var cc net.Conn
	var node Node
	var err error
	for i := 0; i < retries; i++ {
		if len(h.group.Nodes()) > 0 {
			node, err = h.group.Next()
			if err != nil {
				resp.Status = relay.StatusServiceUnavailable
				resp.WriteTo(conn)
				log.Logf("[relay] %s - %s : %s", conn.RemoteAddr(), conn.LocalAddr(), err)
				return
			}
			raddr = node.Addr
		}

		log.Logf("[relay] %s -> %s -> %s", conn.RemoteAddr(), conn.LocalAddr(), raddr)
		cc, err = h.options.Chain.DialContext(ctx,
			network, raddr,
			RetryChainOption(h.options.Retries),
			TimeoutChainOption(h.options.Timeout),
		)
		if err != nil {
			log.Logf("[relay] %s -> %s : %s", conn.RemoteAddr(), raddr, err)
			node.MarkDead()
		} else {
			break
		}
	}
	if err != nil {
		resp.Status = relay.StatusServiceUnavailable
		resp.WriteTo(conn)
		return
	}

	node.ResetDead()
	defer cc.Close()

	sc := &relayConn{
		Conn:     conn,
		isServer: true,
		udp:      udp,
	}
	resp.WriteTo(&sc.wbuf)
	conn = sc

	log.Logf("[relay] %s <-> %s", conn.RemoteAddr(), raddr)
	transport(conn, cc)
	log.Logf("[relay] %s >-< %s", conn.RemoteAddr(), raddr)
}

type relayConn struct {
	net.Conn
	isServer   bool
	udp        bool
	wbuf       bytes.Buffer
	once       sync.Once
	headerSent bool
}

func (c *relayConn) Read(b []byte) (n int, err error) {
	c.once.Do(func() {
		if c.isServer {
			return
		}
		resp := new(relay.Response)
		_, err = resp.ReadFrom(c.Conn)
		if err != nil {
			return
		}
		if resp.Version != relay.Version1 {
			err = relay.ErrBadVersion
			return
		}
		if resp.Status != relay.StatusOK {
			err = fmt.Errorf("status %d", resp.Status)
			return
		}
	})

	if err != nil {
		log.Logf("[relay] %s <- %s: %s", c.Conn.LocalAddr(), c.Conn.RemoteAddr(), err)
		return
	}

	if !c.udp {
		return c.Conn.Read(b)
	}
	var bb [2]byte
	_, err = io.ReadFull(c.Conn, bb[:])
	if err != nil {
		return
	}
	dlen := int(binary.BigEndian.Uint16(bb[:]))
	if len(b) >= dlen {
		return io.ReadFull(c.Conn, b[:dlen])
	}
	buf := make([]byte, dlen)
	_, err = io.ReadFull(c.Conn, buf)
	n = copy(b, buf)
	return
}

func (c *relayConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	n, err = c.Read(b)
	addr = c.Conn.RemoteAddr()
	return
}

func (c *relayConn) Write(b []byte) (n int, err error) {
	if len(b) > 0xFFFF {
		err = errors.New("write: data maximum exceeded")
		return
	}
	n = len(b) // force byte length consistent
	if c.wbuf.Len() > 0 {
		if c.udp {
			var bb [2]byte
			binary.BigEndian.PutUint16(bb[:2], uint16(len(b)))
			c.wbuf.Write(bb[:])
			c.headerSent = true
		}
		c.wbuf.Write(b) // append the data to the cached header
		// _, err = c.Conn.Write(c.wbuf.Bytes())
		// c.wbuf.Reset()
		_, err = c.wbuf.WriteTo(c.Conn)
		return
	}

	if !c.udp {
		return c.Conn.Write(b)
	}
	if !c.headerSent {
		c.headerSent = true
		b2 := make([]byte, len(b)+2)
		copy(b2, b)
		_, err = c.Conn.Write(b2)
		return
	}
	nsize := 2 + len(b)
	var buf []byte
	if nsize <= mediumBufferSize {
		buf = mPool.Get().([]byte)
		defer mPool.Put(buf)
	} else {
		buf = make([]byte, nsize)
	}
	binary.BigEndian.PutUint16(buf[:2], uint16(len(b)))
	n = copy(buf[2:], b)
	_, err = c.Conn.Write(buf[:nsize])
	return
}

func (c *relayConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	return c.Write(b)
}
