package gost

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/go-log/log"
	"github.com/shadowsocks/go-shadowsocks2/core"
	"github.com/shadowsocks/go-shadowsocks2/shadowaead"
	"github.com/shadowsocks/go-shadowsocks2/shadowstream"
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

// IPRoute is an IP routing entry.
type IPRoute struct {
	Dest    *net.IPNet
	Gateway net.IP
}

// TunConfig is the config for TUN device.
type TunConfig struct {
	Name    string
	Addr    string
	Peer    string // peer addr of point-to-point on MacOS
	MTU     int
	Routes  []IPRoute
	Gateway string
}

type tunRouteKey [16]byte

func ipToTunRouteKey(ip net.IP) (key tunRouteKey) {
	copy(key[:], ip.To16())
	return
}

type tunListener struct {
	addr   net.Addr
	conns  chan net.Conn
	closed chan struct{}
	config TunConfig
}

// TunListener creates a listener for tun tunnel.
func TunListener(cfg TunConfig) (Listener, error) {
	threads := 1
	ln := &tunListener{
		conns:  make(chan net.Conn, threads),
		closed: make(chan struct{}),
		config: cfg,
	}

	for i := 0; i < threads; i++ {
		conn, ifce, err := createTun(cfg)
		if err != nil {
			return nil, err
		}
		ln.addr = conn.LocalAddr()

		addrs, _ := ifce.Addrs()
		log.Logf("[tun] %s: name: %s, mtu: %d, addrs: %s",
			conn.LocalAddr(), ifce.Name, ifce.MTU, addrs)

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

type tunHandler struct {
	options *HandlerOptions
	routes  sync.Map
	chExit  chan struct{}
}

// TunHandler creates a handler for tun tunnel.
func TunHandler(opts ...HandlerOption) Handler {
	h := &tunHandler{
		options: &HandlerOptions{},
		chExit:  make(chan struct{}, 1),
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

	var err error
	var raddr net.Addr
	if addr := h.options.Node.Remote; addr != "" {
		raddr, err = net.ResolveUDPAddr("udp", addr)
		if err != nil {
			log.Logf("[tun] %s: remote addr: %v", conn.LocalAddr(), err)
			return
		}
	}

	var tempDelay time.Duration
	for {
		err := func() error {
			var err error
			var pc net.PacketConn
			// fake tcp mode will be ignored when the client specifies a chain.
			if raddr != nil && !h.options.Chain.IsEmpty() {
				cc, err := h.options.Chain.DialContext(context.Background(), "udp", raddr.String())
				if err != nil {
					return err
				}
				pc = cc.(net.PacketConn)
			} else {
				if h.options.TCPMode {
					if raddr != nil {
						pc, err = tcpraw.Dial("tcp", raddr.String())
					} else {
						pc, err = tcpraw.Listen("tcp", h.options.Node.Addr)
					}
				} else {
					laddr, _ := net.ResolveUDPAddr("udp", h.options.Node.Addr)
					pc, err = net.ListenUDP("udp", laddr)
				}
			}
			if err != nil {
				return err
			}

			pc, err = h.initTunnelConn(pc)
			if err != nil {
				return err
			}

			return h.transportTun(conn, pc, raddr)
		}()
		if err != nil {
			log.Logf("[tun] %s: %v", conn.LocalAddr(), err)
		}

		select {
		case <-h.chExit:
			return
		default:
		}

		if err != nil {
			if tempDelay == 0 {
				tempDelay = 1000 * time.Millisecond
			} else {
				tempDelay *= 2
			}
			if max := 6 * time.Second; tempDelay > max {
				tempDelay = max
			}
			time.Sleep(tempDelay)
			continue
		}
		tempDelay = 0
	}
}

func (h *tunHandler) initTunnelConn(pc net.PacketConn) (net.PacketConn, error) {
	if len(h.options.Users) > 0 && h.options.Users[0] != nil {
		passwd, _ := h.options.Users[0].Password()
		cipher, err := core.PickCipher(h.options.Users[0].Username(), nil, passwd)
		if err != nil {
			return nil, err
		}
		pc = cipher.PacketConn(pc)
	}
	return pc, nil
}

func (h *tunHandler) findRouteFor(dst net.IP) net.Addr {
	if v, ok := h.routes.Load(ipToTunRouteKey(dst)); ok {
		return v.(net.Addr)
	}
	for _, route := range h.options.IPRoutes {
		if route.Dest.Contains(dst) && route.Gateway != nil {
			if v, ok := h.routes.Load(ipToTunRouteKey(route.Gateway)); ok {
				return v.(net.Addr)
			}
		}
	}
	return nil
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
					select {
					case h.chExit <- struct{}{}:
					default:
					}
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

				addr := h.findRouteFor(dst)
				if addr == nil {
					log.Logf("[tun] no route for %s -> %s", src, dst)
					return nil
				}

				if Debug {
					log.Logf("[tun] find route: %s -> %s", dst, addr)
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
				if err != nil &&
					err != shadowaead.ErrShortPacket && err != shadowstream.ErrShortPacket {
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

				if addr := h.findRouteFor(dst); addr != nil {
					if Debug {
						log.Logf("[tun] find route: %s -> %s", dst, addr)
					}
					_, err := conn.WriteTo(b[:n], addr)
					return err
				}

				if _, err := tun.Write(b[:n]); err != nil {
					select {
					case h.chExit <- struct{}{}:
					default:
					}
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
	return err
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

// TapConfig is the config for TAP device.
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

type tapListener struct {
	addr   net.Addr
	conns  chan net.Conn
	closed chan struct{}
	config TapConfig
}

// TapListener creates a listener for tap tunnel.
func TapListener(cfg TapConfig) (Listener, error) {
	threads := 1
	ln := &tapListener{
		conns:  make(chan net.Conn, threads),
		closed: make(chan struct{}),
		config: cfg,
	}

	for i := 0; i < threads; i++ {
		conn, ifce, err := createTap(cfg)
		if err != nil {
			return nil, err
		}
		ln.addr = conn.LocalAddr()

		addrs, _ := ifce.Addrs()
		log.Logf("[tap] %s: name: %s, mac: %s, mtu: %d, addrs: %s",
			conn.LocalAddr(), ifce.Name, ifce.HardwareAddr, ifce.MTU, addrs)

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

type tapHandler struct {
	options *HandlerOptions
	routes  sync.Map
	chExit  chan struct{}
}

// TapHandler creates a handler for tap tunnel.
func TapHandler(opts ...HandlerOption) Handler {
	h := &tapHandler{
		options: &HandlerOptions{},
		chExit:  make(chan struct{}, 1),
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

	var err error
	var raddr net.Addr
	if addr := h.options.Node.Remote; addr != "" {
		raddr, err = net.ResolveUDPAddr("udp", addr)
		if err != nil {
			log.Logf("[tap] %s: remote addr: %v", conn.LocalAddr(), err)
			return
		}
	}

	var tempDelay time.Duration
	for {
		err := func() error {
			var err error
			var pc net.PacketConn
			// fake tcp mode will be ignored when the client specifies a chain.
			if raddr != nil && !h.options.Chain.IsEmpty() {
				cc, err := h.options.Chain.DialContext(context.Background(), "udp", raddr.String())
				if err != nil {
					return err
				}
				pc = cc.(net.PacketConn)
			} else {
				if h.options.TCPMode {
					if raddr != nil {
						pc, err = tcpraw.Dial("tcp", raddr.String())
					} else {
						pc, err = tcpraw.Listen("tcp", h.options.Node.Addr)
					}
				} else {
					laddr, _ := net.ResolveUDPAddr("udp", h.options.Node.Addr)
					pc, err = net.ListenUDP("udp", laddr)
				}
			}
			if err != nil {
				return err
			}

			pc, err = h.initTunnelConn(pc)
			if err != nil {
				return err
			}

			return h.transportTap(conn, pc, raddr)
		}()
		if err != nil {
			log.Logf("[tap] %s: %v", conn.LocalAddr(), err)
		}

		select {
		case <-h.chExit:
			return
		default:
		}

		if err != nil {
			if tempDelay == 0 {
				tempDelay = 1000 * time.Millisecond
			} else {
				tempDelay *= 2
			}
			if max := 6 * time.Second; tempDelay > max {
				tempDelay = max
			}
			time.Sleep(tempDelay)
			continue
		}
		tempDelay = 0
	}
}

func (h *tapHandler) initTunnelConn(pc net.PacketConn) (net.PacketConn, error) {
	if len(h.options.Users) > 0 && h.options.Users[0] != nil {
		passwd, _ := h.options.Users[0].Password()
		cipher, err := core.PickCipher(h.options.Users[0].Username(), nil, passwd)
		if err != nil {
			return nil, err
		}
		pc = cipher.PacketConn(pc)
	}
	return pc, nil
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
					select {
					case h.chExit <- struct{}{}:
					default:
					}
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
				if err != nil &&
					err != shadowaead.ErrShortPacket && err != shadowstream.ErrShortPacket {
					return err
				}

				src := waterutil.MACSource(b[:n])
				dst := waterutil.MACDestination(b[:n])
				eType := etherType(waterutil.MACEthertype(b[:n]))

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
					select {
					case h.chExit <- struct{}{}:
					default:
					}
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
	return err
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

// IsIPv6Multicast reports whether the address addr is an IPv6 multicast address.
func IsIPv6Multicast(addr net.HardwareAddr) bool {
	return addr[0] == 0x33 && addr[1] == 0x33
}
