package gost

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/ginuerzh/gosocks5"
	"github.com/golang/glog"
	ss "github.com/shadowsocks/shadowsocks-go/shadowsocks"
)

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

type ShadowServer struct {
	conn *ss.Conn
	Base *ProxyServer
	OTA  bool // one time auth
}

func NewShadowServer(conn *ss.Conn, base *ProxyServer) *ShadowServer {
	return &ShadowServer{conn: conn, Base: base}
}

func (s *ShadowServer) Serve() {
	glog.V(LINFO).Infof("[ss] %s - %s", s.conn.RemoteAddr(), s.conn.LocalAddr())

	addr, ota, err := s.getRequest()
	if err != nil {
		glog.V(LWARNING).Infof("[ss] %s - %s : %s", s.conn.RemoteAddr(), s.conn.LocalAddr(), err)
		return
	}
	glog.V(LINFO).Infof("[ss] %s -> %s, ota: %v", s.conn.RemoteAddr(), addr, ota)

	cc, err := s.Base.Chain.Dial(addr)
	if err != nil {
		glog.V(LWARNING).Infof("[ss] %s -> %s : %s", s.conn.RemoteAddr(), addr, err)
		return
	}
	defer cc.Close()

	glog.V(LINFO).Infof("[ss] %s <-> %s", s.conn.RemoteAddr(), addr)
	if ota {
		s.transportOTA(s.conn, cc)
	} else {
		s.Base.transport(&shadowConn{conn: s.conn}, cc)
	}
	glog.V(LINFO).Infof("[ss] %s >-< %s", s.conn.RemoteAddr(), addr)
}

// This function is copied from shadowsocks library with some modification.
func (s *ShadowServer) getRequest() (host string, ota bool, err error) {
	// buf size should at least have the same size with the largest possible
	// request size (when addrType is 3, domain name has at most 256 bytes)
	// 1(addrType) + 1(lenByte) + 256(max length address) + 2(port)
	buf := make([]byte, SmallBufferSize)

	// read till we get possible domain length field
	s.conn.SetReadDeadline(time.Now().Add(ReadTimeout))
	if _, err = io.ReadFull(s.conn, buf[:idType+1]); err != nil {
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
		if _, err = io.ReadFull(s.conn, buf[idType+1:idDmLen+1]); err != nil {
			return
		}
		reqStart, reqEnd = idDm0, int(idDm0+buf[idDmLen]+lenDmBase)
	default:
		err = fmt.Errorf("addr type %d not supported", addrType&ss.AddrMask)
		return
	}

	if _, err = io.ReadFull(s.conn, buf[reqStart:reqEnd]); err != nil {
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
	// if specified one time auth enabled, we should verify this
	if s.OTA || addrType&ss.OneTimeAuthMask > 0 {
		ota = true
		if _, err = io.ReadFull(s.conn, buf[reqEnd:reqEnd+lenHmacSha1]); err != nil {
			return
		}
		iv := s.conn.GetIv()
		key := s.conn.GetKey()
		actualHmacSha1Buf := ss.HmacSha1(append(iv, key...), buf[:reqEnd])
		if !bytes.Equal(buf[reqEnd:reqEnd+lenHmacSha1], actualHmacSha1Buf) {
			err = fmt.Errorf("verify one time auth failed, iv=%v key=%v data=%v", iv, key, buf[:reqEnd])
			return
		}
	}
	return
}

const (
	dataLenLen  = 2
	hmacSha1Len = 10
	idxData0    = dataLenLen + hmacSha1Len
)

// copyOta copies data from src to dst with ota verification.
//
// This function is copied from shadowsocks library with some modification.
func (s *ShadowServer) copyOta(dst net.Conn, src *ss.Conn) (int64, error) {
	// sometimes it have to fill large block
	buf := make([]byte, LargeBufferSize)
	for {
		src.SetReadDeadline(time.Now().Add(ReadTimeout))
		if n, err := io.ReadFull(src, buf[:dataLenLen+hmacSha1Len]); err != nil {
			return int64(n), err
		}
		src.SetReadDeadline(time.Time{})

		dataLen := binary.BigEndian.Uint16(buf[:dataLenLen])
		expectedHmacSha1 := buf[dataLenLen:idxData0]

		var dataBuf []byte
		if len(buf) < int(idxData0+dataLen) {
			dataBuf = make([]byte, dataLen)
		} else {
			dataBuf = buf[idxData0 : idxData0+dataLen]
		}
		if n, err := io.ReadFull(src, dataBuf); err != nil {
			return int64(n), err
		}
		chunkIdBytes := make([]byte, 4)
		chunkId := src.GetAndIncrChunkId()
		binary.BigEndian.PutUint32(chunkIdBytes, chunkId)
		actualHmacSha1 := ss.HmacSha1(append(src.GetIv(), chunkIdBytes...), dataBuf)
		if !bytes.Equal(expectedHmacSha1, actualHmacSha1) {
			return 0, errors.New("ota error: mismatch")
		}

		if n, err := dst.Write(dataBuf); err != nil {
			return int64(n), err
		}
	}
}

func (s *ShadowServer) transportOTA(sc *ss.Conn, cc net.Conn) (err error) {
	errc := make(chan error, 2)

	go func() {
		_, err := io.Copy(&shadowConn{conn: sc}, cc)
		errc <- err
	}()

	go func() {
		_, err := s.copyOta(cc, sc)
		errc <- err
	}()

	select {
	case err = <-errc:
		//glog.V(LWARNING).Infoln("transport exit", err)
	}

	return
}

// Due to in/out byte length is inconsistent of the shadowsocks.Conn.Write,
// we wrap around it to make io.Copy happy
type shadowConn struct {
	conn *ss.Conn
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
