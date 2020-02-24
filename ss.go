package gost

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/url"
	"time"

	"github.com/ginuerzh/gosocks5"
	"github.com/go-log/log"
	"github.com/shadowsocks/go-shadowsocks2/core"
	ss "github.com/shadowsocks/shadowsocks-go/shadowsocks"
)

const (
	maxSocksAddrLen = 259
)

var (
	_ net.Conn       = (*shadowConn)(nil)
	_ net.PacketConn = (*shadowUDPPacketConn)(nil)
)

type shadowConnector struct {
	cipher core.Cipher
}

// ShadowConnector creates a Connector for shadowsocks proxy client.
// It accepts an optional cipher info for shadowsocks data encryption/decryption.
func ShadowConnector(info *url.Userinfo) Connector {
	return &shadowConnector{
		cipher: initShadowCipher(info),
	}
}

func (c *shadowConnector) Connect(conn net.Conn, address string, options ...ConnectOption) (net.Conn, error) {
	return c.ConnectContext(context.Background(), conn, "tcp", address, options...)
}

func (c *shadowConnector) ConnectContext(ctx context.Context, conn net.Conn, network, address string, options ...ConnectOption) (net.Conn, error) {
	switch network {
	case "udp", "udp4", "udp6":
		return nil, fmt.Errorf("%s unsupported", network)
	}

	opts := &ConnectOptions{}
	for _, option := range options {
		option(opts)
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = ConnectTimeout
	}

	socksAddr, err := gosocks5.NewAddr(address)
	if err != nil {
		return nil, err
	}
	rawaddr := sPool.Get().([]byte)
	defer sPool.Put(rawaddr)

	n, err := socksAddr.Encode(rawaddr)
	if err != nil {
		return nil, err
	}

	conn.SetDeadline(time.Now().Add(timeout))
	defer conn.SetDeadline(time.Time{})

	if c.cipher != nil {
		conn = c.cipher.StreamConn(conn)
	}

	sc := &shadowConn{
		Conn: conn,
	}

	// write the addr at once.
	if opts.NoDelay {
		if _, err := sc.Write(rawaddr[:n]); err != nil {
			return nil, err
		}
	} else {
		sc.wbuf.Write(rawaddr[:n]) // cache the header
	}

	return sc, nil
}

type shadowHandler struct {
	cipher  core.Cipher
	options *HandlerOptions
}

// ShadowHandler creates a server Handler for shadowsocks proxy server.
func ShadowHandler(opts ...HandlerOption) Handler {
	h := &shadowHandler{}
	h.Init(opts...)

	return h
}

func (h *shadowHandler) Init(options ...HandlerOption) {
	if h.options == nil {
		h.options = &HandlerOptions{}
	}

	for _, opt := range options {
		opt(h.options)
	}
	if len(h.options.Users) > 0 {
		h.cipher = initShadowCipher(h.options.Users[0])
	}
}

func (h *shadowHandler) Handle(conn net.Conn) {
	defer conn.Close()

	if h.cipher != nil {
		conn = &shadowConn{
			Conn: h.cipher.StreamConn(conn),
		}
	}

	conn.SetReadDeadline(time.Now().Add(ReadTimeout))

	addr, err := readSocksAddr(conn)
	if err != nil {
		log.Logf("[ss] %s -> %s : %s",
			conn.RemoteAddr(), conn.LocalAddr(), err)
		return
	}

	conn.SetReadDeadline(time.Time{})

	host := addr.String()
	log.Logf("[ss] %s -> %s",
		conn.RemoteAddr(), host)

	if !Can("tcp", host, h.options.Whitelist, h.options.Blacklist) {
		log.Logf("[ss] %s - %s : Unauthorized to tcp connect to %s",
			conn.RemoteAddr(), conn.LocalAddr(), host)
		return
	}

	if h.options.Bypass.Contains(host) {
		log.Logf("[ss] %s - %s : Bypass %s",
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
			log.Logf("[ss] %s -> %s : %s",
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
		log.Logf("[ss] %s -> %s : %s",
			conn.RemoteAddr(), conn.LocalAddr(), err)
	}

	if err != nil {
		return
	}
	defer cc.Close()

	log.Logf("[ss] %s <-> %s", conn.RemoteAddr(), host)
	transport(conn, cc)
	log.Logf("[ss] %s >-< %s", conn.RemoteAddr(), host)
}

type shadowUDPConnector struct {
	cipher core.Cipher
}

// ShadowUDPConnector creates a Connector for shadowsocks UDP client.
// It accepts an optional cipher info for shadowsocks data encryption/decryption.
func ShadowUDPConnector(info *url.Userinfo) Connector {
	return &shadowUDPConnector{
		cipher: initShadowCipher(info),
	}
}

func (c *shadowUDPConnector) Connect(conn net.Conn, address string, options ...ConnectOption) (net.Conn, error) {
	return c.ConnectContext(context.Background(), conn, "udp", address, options...)
}

func (c *shadowUDPConnector) ConnectContext(ctx context.Context, conn net.Conn, network, address string, options ...ConnectOption) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
		return nil, fmt.Errorf("%s unsupported", network)
	}

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

	taddr, _ := net.ResolveUDPAddr(network, address)
	if taddr == nil {
		taddr = &net.UDPAddr{}
	}

	pc, ok := conn.(net.PacketConn)
	if ok {
		if c.cipher != nil {
			pc = c.cipher.PacketConn(pc)
		}

		return &shadowUDPPacketConn{
			PacketConn: pc,
			raddr:      conn.RemoteAddr(),
			taddr:      taddr,
		}, nil
	}

	if c.cipher != nil {
		conn = &shadowConn{
			Conn: c.cipher.StreamConn(conn),
		}
	}

	return &socks5UDPTunnelConn{
		Conn:  conn,
		taddr: taddr,
	}, nil
}

type shadowUDPHandler struct {
	cipher  core.Cipher
	options *HandlerOptions
}

// ShadowUDPHandler creates a server Handler for shadowsocks UDP relay server.
func ShadowUDPHandler(opts ...HandlerOption) Handler {
	h := &shadowUDPHandler{}
	h.Init(opts...)

	return h
}

func (h *shadowUDPHandler) Init(options ...HandlerOption) {
	if h.options == nil {
		h.options = &HandlerOptions{}
	}
	for _, opt := range options {
		opt(h.options)
	}
	if len(h.options.Users) > 0 {
		h.cipher = initShadowCipher(h.options.Users[0])
	}
}

func (h *shadowUDPHandler) Handle(conn net.Conn) {
	defer conn.Close()

	var cc net.PacketConn
	c, err := h.options.Chain.DialContext(context.Background(), "udp", "")
	if err != nil {
		log.Logf("[ssu] %s: %s", conn.LocalAddr(), err)
		return
	}
	cc = c.(net.PacketConn)
	defer cc.Close()

	pc, ok := conn.(net.PacketConn)
	if ok {
		if h.cipher != nil {
			pc = h.cipher.PacketConn(pc)
		}
		log.Logf("[ssu] %s <-> %s", conn.RemoteAddr(), conn.LocalAddr())
		h.transportPacket(pc, cc)
		log.Logf("[ssu] %s >-< %s", conn.RemoteAddr(), conn.LocalAddr())
		return
	}

	if h.cipher != nil {
		conn = &shadowConn{
			Conn: h.cipher.StreamConn(conn),
		}
	}

	log.Logf("[ssu] %s <-> %s", conn.RemoteAddr(), conn.LocalAddr())
	h.transportUDP(conn, cc)
	log.Logf("[ssu] %s >-< %s", conn.RemoteAddr(), conn.LocalAddr())
}

func (h *shadowUDPHandler) transportPacket(conn, cc net.PacketConn) (err error) {
	errc := make(chan error, 1)
	var clientAddr net.Addr

	go func() {
		for {
			err := func() error {
				b := mPool.Get().([]byte)
				defer mPool.Put(b)

				n, addr, err := conn.ReadFrom(b)
				if err != nil {
					return err
				}
				if clientAddr == nil {
					clientAddr = addr
				}

				r := bytes.NewBuffer(b[:n])
				saddr, err := readSocksAddr(r)
				if err != nil {
					return err
				}
				taddr, err := net.ResolveUDPAddr("udp", saddr.String())
				if err != nil {
					return err
				}
				if Debug {
					log.Logf("[ssu] %s >>> %s length: %d", addr, taddr, r.Len())
				}
				_, err = cc.WriteTo(r.Bytes(), taddr)
				return err
			}()

			if err != nil {
				errc <- err
				return
			}
		}
	}()

	go func() {
		for {
			err := func() error {
				b := mPool.Get().([]byte)
				defer mPool.Put(b)

				n, addr, err := cc.ReadFrom(b)
				if err != nil {
					return err
				}
				if clientAddr == nil {
					return nil
				}

				if Debug {
					log.Logf("[ssu] %s <<< %s length: %d", clientAddr, addr, n)
				}

				dgram := gosocks5.NewUDPDatagram(gosocks5.NewUDPHeader(0, 0, toSocksAddr(addr)), b[:n])
				buf := bytes.Buffer{}
				if err = dgram.Write(&buf); err != nil {
					return err
				}
				_, err = conn.WriteTo(buf.Bytes()[3:], clientAddr)
				return err
			}()

			if err != nil {
				errc <- err
				return
			}
		}
	}()

	select {
	case err = <-errc:
	}

	return
}

func (h *shadowUDPHandler) transportUDP(conn net.Conn, cc net.PacketConn) error {
	errc := make(chan error, 1)

	go func() {
		for {
			er := func() (err error) {
				dgram, err := gosocks5.ReadUDPDatagram(conn)
				if err != nil {
					// log.Logf("[ssu] %s - %s : %s", conn.RemoteAddr(), conn.LocalAddr(), err)
					return
				}
				if Debug {
					log.Logf("[ssu] %s >>> %s length: %d",
						conn.RemoteAddr(), dgram.Header.Addr.String(), len(dgram.Data))
				}
				addr, err := net.ResolveUDPAddr("udp", dgram.Header.Addr.String())
				if err != nil {
					return
				}
				if h.options.Bypass.Contains(addr.String()) {
					log.Log("[ssu] bypass", addr)
					return // bypass
				}
				_, err = cc.WriteTo(dgram.Data, addr)
				return
			}()

			if er != nil {
				errc <- er
				return
			}
		}
	}()

	go func() {
		for {
			er := func() (err error) {
				b := mPool.Get().([]byte)
				defer mPool.Put(b)

				n, addr, err := cc.ReadFrom(b)
				if err != nil {
					return
				}
				if Debug {
					log.Logf("[ssu] %s <<< %s length: %d", conn.RemoteAddr(), addr, n)
				}
				if h.options.Bypass.Contains(addr.String()) {
					log.Log("[ssu] bypass", addr)
					return // bypass
				}
				dgram := gosocks5.NewUDPDatagram(
					gosocks5.NewUDPHeader(uint16(n), 0, toSocksAddr(addr)), b[:n])
				buf := bytes.Buffer{}
				dgram.Write(&buf)
				_, err = conn.Write(buf.Bytes())
				return
			}()

			if er != nil {
				errc <- er
				return
			}
		}
	}()

	err := <-errc
	if err != nil && err == io.EOF {
		err = nil
	}
	return err
}

// Due to in/out byte length is inconsistent of the shadowsocks.Conn.Write,
// we wrap around it to make io.Copy happy.
type shadowConn struct {
	net.Conn
	wbuf bytes.Buffer
}

func (c *shadowConn) Write(b []byte) (n int, err error) {
	n = len(b) // force byte length consistent
	if c.wbuf.Len() > 0 {
		c.wbuf.Write(b) // append the data to the cached header
		_, err = c.Conn.Write(c.wbuf.Bytes())
		c.wbuf.Reset()
		return
	}
	_, err = c.Conn.Write(b)
	return
}

type shadowUDPPacketConn struct {
	net.PacketConn
	raddr net.Addr
	taddr net.Addr
}

func (c *shadowUDPPacketConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	buf := mPool.Get().([]byte)
	defer mPool.Put(buf)

	buf[0] = 0
	buf[1] = 0
	buf[2] = 0

	n, _, err = c.PacketConn.ReadFrom(buf[3:])
	if err != nil {
		return
	}

	dgram, err := gosocks5.ReadUDPDatagram(bytes.NewReader(buf[:n+3]))
	if err != nil {
		return
	}
	n = copy(b, dgram.Data)
	addr, err = net.ResolveUDPAddr("udp", dgram.Header.Addr.String())

	return

}

func (c *shadowUDPPacketConn) Read(b []byte) (n int, err error) {
	n, _, err = c.ReadFrom(b)
	return
}

func (c *shadowUDPPacketConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	sa, err := gosocks5.NewAddr(addr.String())
	if err != nil {
		return
	}
	var rawaddr [maxSocksAddrLen]byte
	nn, err := sa.Encode(rawaddr[:])
	if err != nil {
		return
	}

	buf := mPool.Get().([]byte)
	defer mPool.Put(buf)

	copy(buf, rawaddr[:nn])
	n = copy(buf[nn:], b)
	_, err = c.PacketConn.WriteTo(buf[:n+nn], c.raddr)

	return
}

func (c *shadowUDPPacketConn) Write(b []byte) (n int, err error) {
	return c.WriteTo(b, c.taddr)
}

func (c *shadowUDPPacketConn) RemoteAddr() net.Addr {
	return c.raddr
}

type shadowCipher struct {
	cipher *ss.Cipher
}

func (c *shadowCipher) StreamConn(conn net.Conn) net.Conn {
	return ss.NewConn(conn, c.cipher.Copy())
}

func (c *shadowCipher) PacketConn(conn net.PacketConn) net.PacketConn {
	return ss.NewSecurePacketConn(conn, c.cipher.Copy(), false)
}

func initShadowCipher(info *url.Userinfo) (cipher core.Cipher) {
	var method, password string
	if info != nil {
		method = info.Username()
		password, _ = info.Password()
	}

	if method == "" || password == "" {
		return
	}

	cp, _ := ss.NewCipher(method, password)
	if cp != nil {
		cipher = &shadowCipher{cipher: cp}
	}
	if cipher == nil {
		var err error
		cipher, err = core.PickCipher(method, nil, password)
		if err != nil {
			log.Logf("[ss] %s", err)
			return
		}
	}
	return
}

func readSocksAddr(r io.Reader) (*gosocks5.Addr, error) {
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
