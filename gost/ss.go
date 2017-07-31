package gost

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"time"

	"github.com/go-log/log"
	ss "github.com/shadowsocks/shadowsocks-go/shadowsocks"
)

// Due to in/out byte length is inconsistent of the shadowsocks.Conn.Write,
// we wrap around it to make io.Copy happy.
type shadowConn struct {
	conn net.Conn
}

func (c *shadowConn) Read(b []byte) (n int, err error) {
	return c.conn.Read(b)
}

func (c *shadowConn) Write(b []byte) (n int, err error) {
	n = len(b) // force byte length consistent
	_, err = c.conn.Write(b)
	return
}

func (c *shadowConn) Close() error {
	return c.conn.Close()
}

func (c *shadowConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *shadowConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *shadowConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *shadowConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *shadowConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

type shadowConnector struct {
	Cipher *url.Userinfo
}

// ShadowConnector creates a Connector for shadowsocks proxy client.
// It accepts a cipher info for shadowsocks data encryption/decryption.
// The cipher must not be nil.
func ShadowConnector(cipher *url.Userinfo) Connector {
	return &shadowConnector{Cipher: cipher}
}

func (c *shadowConnector) Connect(conn net.Conn, addr string) (net.Conn, error) {
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

	sc, err := ss.DialWithRawAddrConn(rawaddr, conn, cipher)
	if err != nil {
		return nil, err
	}
	return &shadowConn{conn: sc}, nil
}

type shadowHandler struct {
	options *HandlerOptions
}

// ShadowHandler creates a server Handler for shadowsocks proxy server.
func ShadowHandler(opts ...HandlerOption) Handler {
	h := &shadowHandler{
		options: &HandlerOptions{},
	}
	for _, opt := range opts {
		opt(h.options)
	}
	return h
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
		log.Log("[ss]", err)
		return
	}
	conn = &shadowConn{conn: ss.NewConn(conn, cipher)}

	log.Logf("[ss] %s - %s", conn.RemoteAddr(), conn.LocalAddr())

	addr, err := h.getRequest(conn)
	if err != nil {
		log.Logf("[ss] %s - %s : %s", conn.RemoteAddr(), conn.LocalAddr(), err)
		return
	}
	log.Logf("[ss] %s -> %s", conn.RemoteAddr(), addr)

	cc, err := h.options.Chain.Dial(addr)
	if err != nil {
		log.Logf("[ss] %s -> %s : %s", conn.RemoteAddr(), addr, err)
		return
	}
	defer cc.Close()

	log.Logf("[ss] %s <-> %s", conn.RemoteAddr(), addr)
	transport(conn, cc)
	log.Logf("[ss] %s >-< %s", conn.RemoteAddr(), addr)
}

const (
	idType  = 0 // address type index
	idIP0   = 1 // ip addres start index
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
func (h *shadowHandler) getRequest(conn net.Conn) (host string, err error) {
	// buf size should at least have the same size with the largest possible
	// request size (when addrType is 3, domain name has at most 256 bytes)
	// 1(addrType) + 1(lenByte) + 256(max length address) + 2(port)
	buf := make([]byte, smallBufferSize)

	// read till we get possible domain length field
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	if _, err = io.ReadFull(conn, buf[:idType+1]); err != nil {
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
		if _, err = io.ReadFull(conn, buf[idType+1:idDmLen+1]); err != nil {
			return
		}
		reqStart, reqEnd = idDm0, int(idDm0+buf[idDmLen]+lenDmBase)
	default:
		err = fmt.Errorf("addr type %d not supported", addrType&ss.AddrMask)
		return
	}

	if _, err = io.ReadFull(conn, buf[reqStart:reqEnd]); err != nil {
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
		host = string(buf[idDm0 : idDm0+buf[idDmLen]])
	}
	// parse port
	port := binary.BigEndian.Uint16(buf[reqEnd-2 : reqEnd])
	host = net.JoinHostPort(host, strconv.Itoa(int(port)))
	return
}
