package gost

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/ginuerzh/gosocks5"
	"github.com/go-log/log"
	"github.com/golang/glog"
	ss "github.com/shadowsocks/shadowsocks-go/shadowsocks"
)

// Due to in/out byte length is inconsistent of the shadowsocks.Conn.Write,
// we wrap around it to make io.Copy happy
type shadowConn struct {
	conn net.Conn
}

func ShadowConn(conn net.Conn) net.Conn {
	return &shadowConn{conn: conn}
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

type shadowHandler struct {
	server Server
}

func ShadowHandler(server Server) Handler {
	return &shadowHandler{server: server}
}

func (h *shadowHandler) Handle(conn net.Conn) {
	var method, password string

	users := h.server.Options().BaseOptions().Users
	if len(users) > 0 {
		method = users[0].Username()
		password, _ = users[0].Password()
	}
	cipher, err := ss.NewCipher(method, password)
	if err != nil {
		log.Log("[ss]", err)
		return
	}
	conn = ShadowConn(ss.NewConn(conn, cipher))

	log.Logf("[ss] %s - %s", conn.RemoteAddr(), conn.LocalAddr())

	addr, err := h.getRequest(conn)
	if err != nil {
		log.Logf("[ss] %s - %s : %s", conn.RemoteAddr(), conn.LocalAddr(), err)
		return
	}
	log.Logf("[ss] %s -> %s", conn.RemoteAddr(), addr)

	cc, err := h.server.Chain().Dial(addr)
	if err != nil {
		log.Logf("[ss] %s -> %s : %s", conn.RemoteAddr(), addr, err)
		return
	}
	defer cc.Close()

	log.Logf("[ss] %s <-> %s", conn.RemoteAddr(), addr)
	defer log.Logf("[ss] %s >-< %s", conn.RemoteAddr(), addr)

	Transport(conn, cc)
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
	buf := make([]byte, SmallBufferSize)

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

type ShadowUdpServer struct {
	Base *ProxyServer
	TTL  int
}

func NewShadowUdpServer(base *ProxyServer, ttl int) *ShadowUdpServer {
	return &ShadowUdpServer{Base: base, TTL: ttl}
}

func (s *ShadowUdpServer) ListenAndServe() error {
	laddr, err := net.ResolveUDPAddr("udp", s.Base.Node.Addr)
	if err != nil {
		return err
	}
	lconn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return err
	}
	defer lconn.Close()

	conn := ss.NewSecurePacketConn(lconn, s.Base.cipher.Copy(), true) // force OTA on

	rChan, wChan := make(chan *packet, 128), make(chan *packet, 128)
	// start send queue
	go func(ch chan<- *packet) {
		for {
			b := make([]byte, MediumBufferSize)
			n, addr, err := conn.ReadFrom(b[3:]) // add rsv and frag fields to make it the standard SOCKS5 UDP datagram
			if err != nil {
				glog.V(LWARNING).Infof("[ssu] %s -> %s : %s", addr, laddr, err)
				continue
			}

			b[3] &= ss.AddrMask // remove OTA flag
			dgram, err := gosocks5.ReadUDPDatagram(bytes.NewReader(b[:n+3]))
			if err != nil {
				glog.V(LWARNING).Infof("[ssu] %s -> %s : %s", addr, laddr, err)
				continue
			}

			select {
			case ch <- &packet{srcAddr: addr.String(), dstAddr: dgram.Header.Addr.String(), data: dgram.Data}:
			case <-time.After(time.Second * 3):
				glog.V(LWARNING).Infof("[ssu] %s -> %s : %s", addr, dgram.Header.Addr.String(), "send queue is full, discard")
			}
		}
	}(wChan)
	// start recv queue
	go func(ch <-chan *packet) {
		for pkt := range ch {
			srcAddr, err := net.ResolveUDPAddr("udp", pkt.srcAddr)
			if err != nil {
				glog.V(LWARNING).Infof("[ssu] %s <- %s : %s", pkt.dstAddr, pkt.srcAddr, err)
				continue
			}
			dstAddr, err := net.ResolveUDPAddr("udp", pkt.dstAddr)
			if err != nil {
				glog.V(LWARNING).Infof("[ssu] %s <- %s : %s", pkt.dstAddr, pkt.srcAddr, err)
				continue
			}

			dgram := gosocks5.NewUDPDatagram(gosocks5.NewUDPHeader(0, 0, ToSocksAddr(srcAddr)), pkt.data)
			b := bytes.Buffer{}
			dgram.Write(&b)
			if b.Len() < 10 {
				glog.V(LWARNING).Infof("[ssu] %s <- %s : invalid udp datagram", pkt.dstAddr, pkt.srcAddr)
				continue
			}

			if _, err := conn.WriteTo(b.Bytes()[3:], dstAddr); err != nil { // remove rsv and frag fields to make it standard shadowsocks UDP datagram
				glog.V(LWARNING).Infof("[ssu] %s <- %s : %s", pkt.dstAddr, pkt.srcAddr, err)
				return
			}
		}
	}(rChan)

	// mapping client to node
	m := make(map[string]*cnode)

	// start dispatcher
	for pkt := range wChan {
		// clear obsolete nodes
		for k, node := range m {
			if node != nil && node.err != nil {
				close(node.wChan)
				delete(m, k)
				glog.V(LINFO).Infof("[ssu] clear node %s", k)
			}
		}

		node, ok := m[pkt.srcAddr]
		if !ok {
			node = &cnode{
				chain:   s.Base.Chain,
				srcAddr: pkt.srcAddr,
				dstAddr: pkt.dstAddr,
				rChan:   rChan,
				wChan:   make(chan *packet, 32),
				ttl:     time.Duration(s.TTL) * time.Second,
			}
			m[pkt.srcAddr] = node
			go node.run()
			glog.V(LINFO).Infof("[ssu] %s -> %s : new client (%d)", pkt.srcAddr, pkt.dstAddr, len(m))
		}

		select {
		case node.wChan <- pkt:
		case <-time.After(time.Second * 3):
			glog.V(LWARNING).Infof("[ssu] %s -> %s : %s", pkt.srcAddr, pkt.dstAddr, "node send queue is full, discard")
		}
	}

	return nil
}
