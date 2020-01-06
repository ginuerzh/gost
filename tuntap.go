package gost

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/go-log/log"
	"github.com/shadowsocks/go-shadowsocks2/core"
	"github.com/songgao/water"
	"github.com/songgao/water/waterutil"
	"github.com/xtaci/tcpraw"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

var mIPProts = map[waterutil.IPProtocol]string{
	waterutil.HOPOPT:     "HOPOPT",
	waterutil.ICMP:       "ICMP",
	waterutil.IGMP:       "IGMP",
	waterutil.GGP:        "GGP",
	waterutil.TCP:        "TCP",
	waterutil.UDP:        "UDP",
	waterutil.IPv6_Route: "IPv6-Route",
	waterutil.IPv6_Frag:  "IPv6-Frag",
	waterutil.IPv6_ICMP:  "IPv6-ICMP",
}

func ipProtocol(p waterutil.IPProtocol) string {
	if v, ok := mIPProts[p]; ok {
		return v
	}
	return fmt.Sprintf("unknown(%d)", p)
}

type TunConfig struct {
	Name    string
	Addr    string
	MTU     int
	Routes  []string
	Gateway string
}

type tunRouteKey [16]byte

func ipToTunRouteKey(ip net.IP) (key tunRouteKey) {
	copy(key[:], ip.To16())
	return
}

type tunHandler struct {
	raddr   string
	options *HandlerOptions
	ifce    *net.Interface
	routes  sync.Map
}

// TunHandler creates a handler for tun tunnel.
func TunHandler(raddr string, opts ...HandlerOption) Handler {
	h := &tunHandler{
		raddr:   raddr,
		options: &HandlerOptions{},
	}
	for _, opt := range opts {
		opt(h.options)
	}

	return h
}

func (h *tunHandler) Init(options ...HandlerOption) {
	if h.options == nil {
		h.options = &HandlerOptions{}
	}
	for _, opt := range options {
		opt(h.options)
	}
}

func (h *tunHandler) Handle(conn net.Conn) {
	defer os.Exit(0)
	defer conn.Close()

	uc, ok := conn.(net.PacketConn)
	if !ok {
		log.Log("[tun] wrong connection type, must be PacketConn")
		return
	}

	tc, err := h.createTun()
	if err != nil {
		log.Logf("[tun] %s create tun: %v", conn.LocalAddr(), err)
		return
	}
	defer tc.Close()

	addrs, _ := h.ifce.Addrs()
	log.Logf("[tun] %s - %s: name: %s, mtu: %d, addrs: %s",
		tc.LocalAddr(), conn.LocalAddr(), h.ifce.Name, h.ifce.MTU, addrs)

	var raddr net.Addr
	if h.raddr != "" {
		raddr, err = net.ResolveUDPAddr("udp", h.raddr)
		if err != nil {
			log.Logf("[tun] %s - %s remote addr: %v", tc.LocalAddr(), conn.LocalAddr(), err)
			return
		}
	}

	if len(h.options.Users) > 0 && h.options.Users[0] != nil {
		passwd, _ := h.options.Users[0].Password()
		cipher, err := core.PickCipher(h.options.Users[0].Username(), nil, passwd)
		if err != nil {
			log.Logf("[tun] %s - %s cipher: %v", tc.LocalAddr(), conn.LocalAddr(), err)
			return
		}
		uc = cipher.PacketConn(uc)
	}

	h.transportTun(tc, uc, raddr)
}

func (h *tunHandler) createTun() (conn net.Conn, err error) {
	conn, h.ifce, err = createTun(h.options.TunConfig)
	return
}

func (h *tunHandler) transportTun(tun net.Conn, conn net.PacketConn, raddr net.Addr) error {
	errc := make(chan error, 1)

	go func() {
		for {
			err := func() error {
				b := sPool.Get().([]byte)
				defer sPool.Put(b)

				n, err := tun.Read(b)
				if err != nil {
					return err
				}

				var src, dst net.IP
				if waterutil.IsIPv4(b[:n]) {
					header, err := ipv4.ParseHeader(b[:n])
					if err != nil {
						log.Logf("[tun] %s: %v", tun.LocalAddr(), err)
						return nil
					}
					if Debug {
						log.Logf("[tun] %s -> %s %-4s %d/%-4d %-4x %d",
							header.Src, header.Dst, ipProtocol(waterutil.IPv4Protocol(b[:n])),
							header.Len, header.TotalLen, header.ID, header.Flags)
					}
					src, dst = header.Src, header.Dst
				} else if waterutil.IsIPv6(b[:n]) {
					header, err := ipv6.ParseHeader(b[:n])
					if err != nil {
						log.Logf("[tun] %s: %v", tun.LocalAddr(), err)
						return nil
					}
					if Debug {
						log.Logf("[tun] %s -> %s %s %d %d",
							header.Src, header.Dst,
							ipProtocol(waterutil.IPProtocol(header.NextHeader)),
							header.PayloadLen, header.TrafficClass)
					}
					src, dst = header.Src, header.Dst
				} else {
					log.Logf("[tun] unknown packet")
					return nil
				}

				// client side, deliver packet directly.
				if raddr != nil {
					_, err := conn.WriteTo(b[:n], raddr)
					return err
				}

				var addr net.Addr
				if v, ok := h.routes.Load(ipToTunRouteKey(dst)); ok {
					addr = v.(net.Addr)
				}
				if addr == nil {
					log.Logf("[tun] no route for %s -> %s", src, dst)
					return nil
				}

				if _, err := conn.WriteTo(b[:n], addr); err != nil {
					return err
				}
				return nil
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
				b := sPool.Get().([]byte)
				defer mPool.Put(b)

				n, addr, err := conn.ReadFrom(b)
				if err != nil {
					return err
				}

				var src, dst net.IP
				if waterutil.IsIPv4(b[:n]) {
					header, err := ipv4.ParseHeader(b[:n])
					if err != nil {
						log.Logf("[tun] %s: %v", tun.LocalAddr(), err)
						return nil
					}
					if Debug {
						log.Logf("[tun] %s -> %s %-4s %d/%-4d %-4x %d",
							header.Src, header.Dst, ipProtocol(waterutil.IPv4Protocol(b[:n])),
							header.Len, header.TotalLen, header.ID, header.Flags)
					}
					src, dst = header.Src, header.Dst
				} else if waterutil.IsIPv6(b[:n]) {
					header, err := ipv6.ParseHeader(b[:n])
					if err != nil {
						log.Logf("[tun] %s: %v", tun.LocalAddr(), err)
						return nil
					}
					if Debug {
						log.Logf("[tun] %s -> %s %s %d %d",
							header.Src, header.Dst,
							ipProtocol(waterutil.IPProtocol(header.NextHeader)),
							header.PayloadLen, header.TrafficClass)
					}
					src, dst = header.Src, header.Dst
				} else {
					log.Logf("[tun] unknown packet")
					return nil
				}

				// client side, deliver packet to tun device.
				if raddr != nil {
					_, err := tun.Write(b[:n])
					return err
				}

				rkey := ipToTunRouteKey(src)
				if actual, loaded := h.routes.LoadOrStore(rkey, addr); loaded {
					if actual.(net.Addr).String() != addr.String() {
						log.Logf("[tun] update route: %s -> %s (old %s)",
							src, addr, actual.(net.Addr))
						h.routes.Store(rkey, addr)
					}
				} else {
					log.Logf("[tun] new route: %s -> %s", src, addr)
				}

				if v, ok := h.routes.Load(ipToTunRouteKey(dst)); ok {
					if Debug {
						log.Logf("[tun] find route: %s -> %s", dst, v)
					}
					_, err := conn.WriteTo(b[:n], v.(net.Addr))
					return err
				}

				if _, err := tun.Write(b[:n]); err != nil {
					return err
				}
				return nil
			}()

			if err != nil {
				errc <- err
				return
			}
		}
	}()

	err := <-errc
	if err != nil && err == io.EOF {
		err = nil
	}
	log.Logf("[tun] %s - %s: %v", tun.LocalAddr(), conn.LocalAddr(), err)
	return err
}

type TunListenConfig struct {
	TCP        bool
	RemoteAddr string
}

type tunListener struct {
	addr   net.Addr
	conns  chan net.Conn
	closed chan struct{}
	config TunListenConfig
}

// TunListener creates a listener for tun tunnel.
func TunListener(addr string, cfg TunListenConfig) (Listener, error) {
	laddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}

	threads := 1
	ln := &tunListener{
		addr:   laddr,
		conns:  make(chan net.Conn, threads),
		closed: make(chan struct{}),
		config: cfg,
	}

	for i := 0; i < threads; i++ {
		var conn net.Conn
		if cfg.TCP {
			var c *tcpraw.TCPConn
			if cfg.RemoteAddr != "" {
				c, err = tcpraw.Dial("tcp", cfg.RemoteAddr)
			} else {
				c, err = tcpraw.Listen("tcp", addr)
			}
			conn = &rawTCPConn{c}
		} else {
			conn, err = net.ListenUDP("udp", laddr)
		}
		if err != nil {
			return nil, err
		}
		ln.conns <- conn
	}

	return ln, nil
}

func (l *tunListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.conns:
		return conn, nil
	case <-l.closed:
	}

	return nil, errors.New("accept on closed listener")
}

func (l *tunListener) Addr() net.Addr {
	return l.addr
}

func (l *tunListener) Close() error {
	select {
	case <-l.closed:
		return errors.New("listener has been closed")
	default:
		close(l.closed)
	}
	return nil
}

var mEtherTypes = map[waterutil.Ethertype]string{
	waterutil.IPv4: "ip",
	waterutil.ARP:  "arp",
	waterutil.RARP: "rarp",
	waterutil.IPv6: "ip6",
}

func etherType(et waterutil.Ethertype) string {
	if s, ok := mEtherTypes[et]; ok {
		return s
	}
	return fmt.Sprintf("unknown(%v)", et)
}

type TapConfig struct {
	Name    string
	Addr    string
	MTU     int
	Routes  []string
	Gateway string
}

type tapRouteKey [6]byte

func hwAddrToTapRouteKey(addr net.HardwareAddr) (key tapRouteKey) {
	copy(key[:], addr)
	return
}

type tapHandler struct {
	raddr   string
	options *HandlerOptions
	ifce    *net.Interface
	routes  sync.Map
}

// TapHandler creates a handler for tap tunnel.
func TapHandler(raddr string, opts ...HandlerOption) Handler {
	h := &tapHandler{
		raddr:   raddr,
		options: &HandlerOptions{},
	}
	for _, opt := range opts {
		opt(h.options)
	}

	return h
}

func (h *tapHandler) Init(options ...HandlerOption) {
	if h.options == nil {
		h.options = &HandlerOptions{}
	}
	for _, opt := range options {
		opt(h.options)
	}
}

func (h *tapHandler) Handle(conn net.Conn) {
	defer os.Exit(0)
	defer conn.Close()

	uc, ok := conn.(net.PacketConn)
	if !ok {
		log.Log("[tap] wrong connection type, must be PacketConn")
		return
	}

	tc, err := h.createTap()
	if err != nil {
		log.Logf("[tap] %s create tap: %v", conn.LocalAddr(), err)
		return
	}
	defer tc.Close()

	addrs, _ := h.ifce.Addrs()
	log.Logf("[tap] %s - %s: name: %s, mac: %s, mtu: %d, addrs: %s",
		tc.LocalAddr(), conn.LocalAddr(),
		h.ifce.Name, h.ifce.HardwareAddr, h.ifce.MTU, addrs)

	var raddr net.Addr
	if h.raddr != "" {
		raddr, err = net.ResolveUDPAddr("udp", h.raddr)
		if err != nil {
			log.Logf("[tap] %s - %s remote addr: %v", tc.LocalAddr(), conn.LocalAddr(), err)
			return
		}
	}

	if len(h.options.Users) > 0 && h.options.Users[0] != nil {
		passwd, _ := h.options.Users[0].Password()
		cipher, err := core.PickCipher(h.options.Users[0].Username(), nil, passwd)
		if err != nil {
			log.Logf("[tap] %s - %s cipher: %v", tc.LocalAddr(), conn.LocalAddr(), err)
			return
		}
		uc = cipher.PacketConn(uc)
	}

	h.transportTap(tc, uc, raddr)
}

func (h *tapHandler) createTap() (conn net.Conn, err error) {
	conn, h.ifce, err = createTap(h.options.TapConfig)
	return
}

func (h *tapHandler) transportTap(tap net.Conn, conn net.PacketConn, raddr net.Addr) error {
	errc := make(chan error, 1)

	go func() {
		for {
			err := func() error {
				b := sPool.Get().([]byte)
				defer sPool.Put(b)

				n, err := tap.Read(b)
				if err != nil {
					return err
				}

				src := waterutil.MACSource(b[:n])
				dst := waterutil.MACDestination(b[:n])
				eType := etherType(waterutil.MACEthertype(b[:n]))

				if Debug {
					log.Logf("[tap] %s -> %s %s %d", src, dst, eType, n)
				}

				// client side, deliver frame directly.
				if raddr != nil {
					_, err := conn.WriteTo(b[:n], raddr)
					return err
				}

				// server side, broadcast.
				if waterutil.IsBroadcast(dst) {
					go h.routes.Range(func(k, v interface{}) bool {
						conn.WriteTo(b[:n], v.(net.Addr))
						return true
					})
					return nil
				}

				var addr net.Addr
				if v, ok := h.routes.Load(hwAddrToTapRouteKey(dst)); ok {
					addr = v.(net.Addr)
				}
				if addr == nil {
					log.Logf("[tap] no route for %s -> %s %s %d", src, dst, eType, n)
					return nil
				}

				if _, err := conn.WriteTo(b[:n], addr); err != nil {
					return err
				}
				return nil
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
				b := sPool.Get().([]byte)
				defer mPool.Put(b)

				n, addr, err := conn.ReadFrom(b)
				if err != nil {
					return err
				}

				src := waterutil.MACSource(b[:n])
				dst := waterutil.MACDestination(b[:n])
				eType := etherType(waterutil.MACEthertype(b[:n]))

				// ignore the frame send by myself
				if bytes.Equal(src, h.ifce.HardwareAddr) {
					log.Logf("[tap] %s -> %s %s %d ignored", src, dst, eType, n)
					return nil
				}

				if Debug {
					log.Logf("[tap] %s -> %s %s %d", src, dst, eType, n)
				}

				// client side, deliver frame to tap device.
				if raddr != nil {
					_, err := tap.Write(b[:n])
					return err
				}

				// server side, record route.
				rkey := hwAddrToTapRouteKey(src)
				if actual, loaded := h.routes.LoadOrStore(rkey, addr); loaded {
					if actual.(net.Addr).String() != addr.String() {
						log.Logf("[tap] update route: %s -> %s (old %s)",
							src, addr, actual.(net.Addr))
						h.routes.Store(rkey, addr)
					}
				} else {
					log.Logf("[tap] new route: %s -> %s", src, addr)
				}

				if waterutil.IsBroadcast(dst) {
					go h.routes.Range(func(k, v interface{}) bool {
						if k.(tapRouteKey) != rkey {
							conn.WriteTo(b[:n], v.(net.Addr))
						}
						return true
					})
				}

				if v, ok := h.routes.Load(hwAddrToTapRouteKey(dst)); ok {
					if Debug {
						log.Logf("[tap] find route: %s -> %s", dst, v)
					}
					_, err := conn.WriteTo(b[:n], v.(net.Addr))
					return err
				}

				if _, err := tap.Write(b[:n]); err != nil {
					return err
				}
				return nil
			}()

			if err != nil {
				errc <- err
				return
			}
		}
	}()

	err := <-errc
	if err != nil && err == io.EOF {
		err = nil
	}
	log.Logf("[tap] %s - %s: %v", tap.LocalAddr(), conn.LocalAddr(), err)
	return err
}

type TapListenConfig struct {
	TCP        bool
	RemoteAddr string
}

type tapListener struct {
	addr   net.Addr
	conns  chan net.Conn
	closed chan struct{}
	config TapListenConfig
}

// TapListener creates a listener for tap tunnel.
func TapListener(addr string, cfg TapListenConfig) (Listener, error) {
	laddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}

	threads := 1
	ln := &tapListener{
		addr:   laddr,
		conns:  make(chan net.Conn, threads),
		closed: make(chan struct{}),
		config: cfg,
	}

	for i := 0; i < threads; i++ {
		var conn net.Conn
		if cfg.TCP {
			var c *tcpraw.TCPConn
			if cfg.RemoteAddr != "" {
				c, err = tcpraw.Dial("tcp", cfg.RemoteAddr)
			} else {
				c, err = tcpraw.Listen("tcp", addr)
			}
			conn = &rawTCPConn{c}
		} else {
			conn, err = net.ListenUDP("udp", laddr)
		}
		if err != nil {
			return nil, err
		}
		ln.conns <- conn
	}

	return ln, nil
}

func (l *tapListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.conns:
		return conn, nil
	case <-l.closed:
	}

	return nil, errors.New("accept on closed listener")
}

func (l *tapListener) Addr() net.Addr {
	return l.addr
}

func (l *tapListener) Close() error {
	select {
	case <-l.closed:
		return errors.New("listener has been closed")
	default:
		close(l.closed)
	}
	return nil
}

type tunTapConn struct {
	ifce *water.Interface
	addr net.Addr
}

func (c *tunTapConn) Read(b []byte) (n int, err error) {
	return c.ifce.Read(b)
}

func (c *tunTapConn) Write(b []byte) (n int, err error) {
	return c.ifce.Write(b)
}

func (c *tunTapConn) Close() (err error) {
	return c.ifce.Close()
}

func (c *tunTapConn) LocalAddr() net.Addr {
	return c.addr
}

func (c *tunTapConn) RemoteAddr() net.Addr {
	return &net.IPAddr{}
}

func (c *tunTapConn) SetDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "tuntap", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

func (c *tunTapConn) SetReadDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "tuntap", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

func (c *tunTapConn) SetWriteDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "tuntap", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

type rawTCPConn struct {
	*tcpraw.TCPConn
}

func (c *rawTCPConn) Read(b []byte) (n int, err error) {
	err = &net.OpError{Op: "read", Net: "rawtcp", Source: nil, Addr: nil, Err: errors.New("read not supported")}
	return
}

func (c *rawTCPConn) Write(b []byte) (n int, err error) {
	err = &net.OpError{Op: "write", Net: "rawtcp", Source: nil, Addr: nil, Err: errors.New("write not supported")}
	return
}

func (c *rawTCPConn) RemoteAddr() net.Addr {
	return &net.IPAddr{}
}

func IsIPv6Multicast(addr net.HardwareAddr) bool {
	return addr[0] == 0x33 && addr[1] == 0x33
}
