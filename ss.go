package gost

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"time"

	"github.com/ginuerzh/gosocks5"
	"github.com/go-log/log"
	"github.com/shadowsocks/go-shadowsocks2/core"
	ss "github.com/shadowsocks/shadowsocks-go/shadowsocks"
)

type shadowConnector struct {
	Cipher *url.Userinfo
}

// ShadowConnector creates a Connector for shadowsocks proxy client.
// It accepts a cipher info for shadowsocks data encryption/decryption.
// The cipher must not be nil.
func ShadowConnector(cipher *url.Userinfo) Connector {
	return &shadowConnector{Cipher: cipher}
}

func (c *shadowConnector) Connect(conn net.Conn, addr string, options ...ConnectOption) (net.Conn, error) {
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

	rawaddr, err := ss.RawAddr(addr)
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

	cipher, err := ss.NewCipher(method, password)
	if err != nil {
		return nil, err
	}

	sc := &shadowConn{
		Conn: ss.NewConn(conn, cipher),
	}
	_, err = sc.Write(rawaddr)
	return sc, err
}

type shadowHandler struct {
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
}

func (h *shadowHandler) Handle(conn net.Conn) {
	defer conn.Close()

	var method, password string
	users := h.options.Users
	if len(users) > 0 {
		method = users[0].Username()
		password, _ = users[0].Password()
	}
	cipher, err := ss.NewCipher(method, password)
	if err != nil {
		log.Logf("[ss] %s -> %s : %s",
			conn.RemoteAddr(), conn.LocalAddr(), err)
		return
	}
	conn = &shadowConn{Conn: ss.NewConn(conn, cipher)}

	conn.SetReadDeadline(time.Now().Add(ReadTimeout))
	host, err := h.getRequest(conn)
	if err != nil {
		log.Logf("[ss] %s -> %s : %s",
			conn.RemoteAddr(), conn.LocalAddr(), err)
		return
	}
	// clear timer
	conn.SetReadDeadline(time.Time{})

	log.Logf("[ss] %s -> %s -> %s",
		conn.RemoteAddr(), h.options.Node.String(), host)

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

const (
	idType  = 0 // address type index
	idIP0   = 1 // ip address start index
	idDmLen = 1 // domain address length index
	idDm0   = 2 // domain address start index

	typeIPv4 = 1 // type is ipv4 address
	typeDm   = 3 // type is domain address
	typeIPv6 = 4 // type is ipv6 address

	lenIPv4     = net.IPv4len + 2 // ipv4 + 2port
	lenIPv6     = net.IPv6len + 2 // ipv6 + 2port
	lenDmBase   = 2               // 1addrLen + 2port, plus addrLen
	lenHmacSha1 = 10
)

// This function is copied from shadowsocks library with some modification.
func (h *shadowHandler) getRequest(r io.Reader) (host string, err error) {
	// buf size should at least have the same size with the largest possible
	// request size (when addrType is 3, domain name has at most 256 bytes)
	// 1(addrType) + 1(lenByte) + 256(max length address) + 2(port)
	buf := make([]byte, smallBufferSize)

	// read till we get possible domain length field
	if _, err = io.ReadFull(r, buf[:idType+1]); err != nil {
		return
	}

	var reqStart, reqEnd int
	addrType := buf[idType]
	switch addrType & ss.AddrMask {
	case typeIPv4:
		reqStart, reqEnd = idIP0, idIP0+lenIPv4
	case typeIPv6:
		reqStart, reqEnd = idIP0, idIP0+lenIPv6
	case typeDm:
		if _, err = io.ReadFull(r, buf[idType+1:idDmLen+1]); err != nil {
			return
		}
		reqStart, reqEnd = idDm0, idDm0+int(buf[idDmLen])+lenDmBase
	default:
		err = fmt.Errorf("addr type %d not supported", addrType&ss.AddrMask)
		return
	}

	if _, err = io.ReadFull(r, buf[reqStart:reqEnd]); err != nil {
		return
	}

	// Return string for typeIP is not most efficient, but browsers (Chrome,
	// Safari, Firefox) all seems using typeDm exclusively. So this is not a
	// big problem.
	switch addrType & ss.AddrMask {
	case typeIPv4:
		host = net.IP(buf[idIP0 : idIP0+net.IPv4len]).String()
	case typeIPv6:
		host = net.IP(buf[idIP0 : idIP0+net.IPv6len]).String()
	case typeDm:
		host = string(buf[idDm0 : idDm0+int(buf[idDmLen])])
	}
	// parse port
	port := binary.BigEndian.Uint16(buf[reqEnd-2 : reqEnd])
	host = net.JoinHostPort(host, strconv.Itoa(int(port)))
	return
}

type shadowUDPConnector struct {
	cipher core.Cipher
}

// ShadowUDPConnector creates a Connector for shadowsocks UDP client.
// It accepts a cipher info for shadowsocks data encryption/decryption.
// The cipher must not be nil.
func ShadowUDPConnector(info *url.Userinfo) Connector {
	c := &shadowUDPConnector{}
	c.initCipher(info)
	return c
}

func (c *shadowUDPConnector) initCipher(info *url.Userinfo) {
	var method, password string
	if info != nil {
		method = info.Username()
		password, _ = info.Password()
	}

	if method == "" || password == "" {
		return
	}

	c.cipher, _ = core.PickCipher(method, nil, password)
	if c.cipher == nil {
		cp, err := ss.NewCipher(method, password)
		if err != nil {
			log.Logf("[ssu] %s", err)
			return
		}
		c.cipher = &shadowCipher{cipher: cp}
	}
}

func (c *shadowUDPConnector) Connect(conn net.Conn, addr string, options ...ConnectOption) (net.Conn, error) {
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

	pc, ok := conn.(net.PacketConn)
	if ok {
		rawaddr, err := ss.RawAddr(addr)
		if err != nil {
			return nil, err
		}

		if c.cipher != nil {
			pc = c.cipher.PacketConn(pc)
		}

		return &shadowUDPPacketConn{
			PacketConn: pc,
			raddr:      conn.RemoteAddr(),
			header:     rawaddr,
		}, nil
	}

	taddr, err := gosocks5.NewAddr(addr)
	if err != nil {
		return nil, err
	}

	if c.cipher != nil {
		conn = c.cipher.StreamConn(conn)
	}

	return &shadowUDPStreamConn{
		Conn: conn,
		addr: taddr,
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

	h.initCipher()
}

func (h *shadowUDPHandler) initCipher() {
	var method, password string
	users := h.options.Users
	if len(users) > 0 {
		method = users[0].Username()
		password, _ = users[0].Password()
	}

	if method == "" || password == "" {
		return
	}
	h.cipher, _ = core.PickCipher(method, nil, password)
	if h.cipher == nil {
		cp, err := ss.NewCipher(method, password)
		if err != nil {
			log.Logf("[ssu] %s", err)
			return
		}
		h.cipher = &shadowCipher{cipher: cp}
	}
}

func (h *shadowUDPHandler) Handle(conn net.Conn) {
	defer conn.Close()

	var err error
	var cc net.PacketConn
	if h.options.Chain.IsEmpty() {
		cc, err = net.ListenUDP("udp", nil)
		if err != nil {
			log.Logf("[ssu] %s - : %s", conn.LocalAddr(), err)
			return
		}
	} else {
		var c net.Conn
		c, err = getSOCKS5UDPTunnel(h.options.Chain, nil)
		if err != nil {
			log.Logf("[ssu] %s - : %s", conn.LocalAddr(), err)
			return
		}
		cc = &udpTunnelConn{Conn: c}
	}
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
		conn = h.cipher.StreamConn(conn)
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
}

func (c *shadowConn) Write(b []byte) (n int, err error) {
	n = len(b) // force byte length consistent
	_, err = c.Conn.Write(b)
	return
}

type shadowUDPPacketConn struct {
	net.PacketConn
	raddr  net.Addr
	header []byte
}

func (c *shadowUDPPacketConn) Write(b []byte) (n int, err error) {
	n = len(b) // force byte length consistent
	buf := bytes.Buffer{}
	if _, err = buf.Write(c.header); err != nil {
		return
	}
	if _, err = buf.Write(b); err != nil {
		return
	}
	_, err = c.PacketConn.WriteTo(buf.Bytes(), c.raddr)
	return
}

func (c *shadowUDPPacketConn) Read(b []byte) (n int, err error) {
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
	return
}

func (c *shadowUDPPacketConn) RemoteAddr() net.Addr {
	return c.raddr
}

type shadowUDPStreamConn struct {
	net.Conn
	addr *gosocks5.Addr
}

func (c *shadowUDPStreamConn) Read(b []byte) (n int, err error) {
	dgram, err := gosocks5.ReadUDPDatagram(c.Conn)
	if err != nil {
		return
	}
	n = copy(b, dgram.Data)
	return
}

func (c *shadowUDPStreamConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	n, err = c.Read(b)
	addr = c.Conn.RemoteAddr()

	return
}

func (c *shadowUDPStreamConn) Write(b []byte) (n int, err error) {
	n = len(b) // force byte length consistent
	dgram := gosocks5.NewUDPDatagram(gosocks5.NewUDPHeader(uint16(len(b)), 0, c.addr), b)
	buf := bytes.Buffer{}
	dgram.Write(&buf)
	_, err = c.Conn.Write(buf.Bytes())
	return
}

func (c *shadowUDPStreamConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	return c.Write(b)
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
