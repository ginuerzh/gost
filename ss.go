package gost

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"time"

	"github.com/ginuerzh/gosocks5"
	"github.com/go-log/log"
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
	sc.wbuf.Write(rawaddr) // cache the header

	return sc, nil
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
	Cipher *url.Userinfo
}

// ShadowUDPConnector creates a Connector for shadowsocks UDP client.
// It accepts a cipher info for shadowsocks data encryption/decryption.
// The cipher must not be nil.
func ShadowUDPConnector(cipher *url.Userinfo) Connector {
	return &shadowUDPConnector{Cipher: cipher}
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

	rawaddr, err := ss.RawAddr(addr)
	if err != nil {
		return nil, err
	}

	var method, password string
	if c.Cipher != nil {
		method = c.Cipher.Username()
		password, _ = c.Cipher.Password()
	}

	cipher, err := ss.NewCipher(method, password)
	if err != nil {
		return nil, err
	}

	sc := ss.NewSecurePacketConn(&shadowPacketConn{conn}, cipher, false)
	return &shadowUDPConn{
		PacketConn: sc,
		raddr:      conn.RemoteAddr(),
		header:     rawaddr,
	}, nil
}

type shadowUDPListener struct {
	ln       net.PacketConn
	conns    map[string]*udpServerConn
	connChan chan net.Conn
	errChan  chan error
	ttl      time.Duration
}

// ShadowUDPListener creates a Listener for shadowsocks UDP relay server.
func ShadowUDPListener(addr string, cipher *url.Userinfo, ttl time.Duration) (Listener, error) {
	laddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	ln, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return nil, err
	}

	var method, password string
	if cipher != nil {
		method = cipher.Username()
		password, _ = cipher.Password()
	}
	cp, err := ss.NewCipher(method, password)
	if err != nil {
		ln.Close()
		return nil, err
	}
	l := &shadowUDPListener{
		ln:       ss.NewSecurePacketConn(ln, cp, false),
		conns:    make(map[string]*udpServerConn),
		connChan: make(chan net.Conn, 1024),
		errChan:  make(chan error, 1),
		ttl:      ttl,
	}
	go l.listenLoop()
	return l, nil
}

func (l *shadowUDPListener) listenLoop() {
	for {
		b := make([]byte, mediumBufferSize)
		n, raddr, err := l.ln.ReadFrom(b)
		if err != nil {
			log.Logf("[ssu] peer -> %s : %s", l.Addr(), err)
			l.ln.Close()
			l.errChan <- err
			close(l.errChan)
			return
		}
		if Debug {
			log.Logf("[ssu] %s >>> %s : length %d", raddr, l.Addr(), n)
		}

		conn, ok := l.conns[raddr.String()]
		if !ok || conn.Closed() {
			conn = newUDPServerConn(l.ln, raddr, l.ttl)
			l.conns[raddr.String()] = conn

			select {
			case l.connChan <- conn:
			default:
				conn.Close()
				log.Logf("[ssu] %s - %s: connection queue is full", raddr, l.Addr())
			}
		}

		select {
		case conn.rChan <- b[:n]: // we keep the addr info so that the handler can identify the destination.
		default:
			log.Logf("[ssu] %s -> %s : read queue is full", raddr, l.Addr())
		}
	}
}

func (l *shadowUDPListener) Accept() (conn net.Conn, err error) {
	var ok bool
	select {
	case conn = <-l.connChan:
	case err, ok = <-l.errChan:
		if !ok {
			err = errors.New("accpet on closed listener")
		}
	}
	return
}

func (l *shadowUDPListener) Addr() net.Addr {
	return l.ln.LocalAddr()
}

func (l *shadowUDPListener) Close() error {
	return l.ln.Close()
}

type shadowUDPdHandler struct {
	ttl     time.Duration
	options *HandlerOptions
}

// ShadowUDPdHandler creates a server Handler for shadowsocks UDP relay server.
func ShadowUDPdHandler(opts ...HandlerOption) Handler {
	h := &shadowUDPdHandler{}
	h.Init(opts...)

	return h
}

func (h *shadowUDPdHandler) Init(options ...HandlerOption) {
	if h.options == nil {
		h.options = &HandlerOptions{}
	}

	for _, opt := range options {
		opt(h.options)
	}
}

func (h *shadowUDPdHandler) Handle(conn net.Conn) {
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

	log.Logf("[ssu] %s <-> %s", conn.RemoteAddr(), conn.LocalAddr())
	h.transportUDP(conn, cc)
	log.Logf("[ssu] %s >-< %s", conn.RemoteAddr(), conn.LocalAddr())
}

func (h *shadowUDPdHandler) transportUDP(sc net.Conn, cc net.PacketConn) error {
	errc := make(chan error, 1)
	go func() {
		for {
			b := mPool.Get().([]byte)
			defer mPool.Put(b)

			b[0] = 0
			b[1] = 0
			b[2] = 0

			n, err := sc.Read(b[3:]) // add rsv and frag fields to make it the standard SOCKS5 UDP datagram
			if err != nil {
				// log.Logf("[ssu] %s - %s : %s", sc.RemoteAddr(), sc.LocalAddr(), err)
				errc <- err
				return
			}
			dgram, err := gosocks5.ReadUDPDatagram(bytes.NewReader(b[:n+3]))
			if err != nil {
				log.Logf("[ssu] %s - %s : %s", sc.RemoteAddr(), sc.LocalAddr(), err)
				errc <- err
				return
			}
			if Debug {
				log.Logf("[ssu] %s >>> %s length: %d", sc.RemoteAddr(), dgram.Header.Addr.String(), len(dgram.Data))
			}
			addr, err := net.ResolveUDPAddr("udp", dgram.Header.Addr.String())
			if err != nil {
				errc <- err
				return
			}
			if h.options.Bypass.Contains(addr.String()) {
				log.Log("[ssu] [bypass] write to", addr)
				continue // bypass
			}
			if _, err := cc.WriteTo(dgram.Data, addr); err != nil {
				errc <- err
				return
			}
		}
	}()

	go func() {
		for {
			b := mPool.Get().([]byte)
			defer mPool.Put(b)

			n, addr, err := cc.ReadFrom(b)
			if err != nil {
				errc <- err
				return
			}
			if Debug {
				log.Logf("[ssu] %s <<< %s length: %d", sc.RemoteAddr(), addr, n)
			}
			if h.options.Bypass.Contains(addr.String()) {
				log.Log("[ssu] [bypass] read from", addr)
				continue // bypass
			}
			dgram := gosocks5.NewUDPDatagram(gosocks5.NewUDPHeader(0, 0, toSocksAddr(addr)), b[:n])
			buf := bytes.Buffer{}
			dgram.Write(&buf)
			if buf.Len() < 10 {
				log.Logf("[ssu] %s <- %s : invalid udp datagram", sc.RemoteAddr(), addr)
				continue
			}
			if _, err := sc.Write(buf.Bytes()[3:]); err != nil {
				errc <- err
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
	wbuf bytes.Buffer
	net.Conn
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

type shadowUDPConn struct {
	net.PacketConn
	raddr  net.Addr
	header []byte
}

func (c *shadowUDPConn) Write(b []byte) (n int, err error) {
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

func (c *shadowUDPConn) Read(b []byte) (n int, err error) {
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

func (c *shadowUDPConn) RemoteAddr() net.Addr {
	return c.raddr
}

type shadowPacketConn struct {
	net.Conn
}

func (c *shadowPacketConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	n, err = c.Conn.Read(b)
	addr = c.Conn.RemoteAddr()
	return
}

func (c *shadowPacketConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	return c.Conn.Write(b)
}
