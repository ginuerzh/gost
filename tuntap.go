package gost

import (
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/go-log/log"
	"github.com/shadowsocks/go-shadowsocks2/core"
	"github.com/songgao/water"
	"github.com/songgao/water/waterutil"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type TunConfig struct {
	Name   string
	Addr   string
	MTU    int
	Routes []string
}

type tunHandler struct {
	raddr   string
	options *HandlerOptions
	ipNet   *net.IPNet
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

	log.Logf("[tun] %s - %s: tun creation successful", tc.LocalAddr(), conn.LocalAddr())

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
	conn, h.ipNet, err = createTun(h.options.TunConfig)
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

				header, err := ipv4.ParseHeader(b[:n])
				if err != nil {
					log.Logf("[tun] %s: %v", tun.LocalAddr(), err)
					return err
				}

				if header.Version != ipv4.Version {
					if Debug && header.Version == ipv6.Version {
						if hdr, _ := ipv6.ParseHeader(b[:n]); hdr != nil {
							log.Logf("[tun] %s: %s -> %s %d %d",
								tun.LocalAddr(), hdr.Src, hdr.Dst, hdr.PayloadLen, hdr.TrafficClass)
						}
					}
					log.Logf("[tun] %s: v%d ignored, only support ipv4",
						tun.LocalAddr(), header.Version)
					return nil
				}

				addr := raddr
				if v, ok := h.routes.Load(header.Dst.String()); ok {
					addr = v.(net.Addr)
				}
				if addr == nil {
					log.Logf("[tun] %s: no route for %s -> %s %d/%d %x %d %d",
						tun.LocalAddr(), header.Src, header.Dst,
						header.Len, header.TotalLen, header.ID, header.Flags, header.Protocol)
					return nil
				}

				if Debug {
					log.Logf("[tun] %s >>> %s: %s -> %s %d/%d %x %d %d",
						tun.LocalAddr(), addr, header.Src, header.Dst,
						header.Len, header.TotalLen, header.ID, header.Flags, header.Protocol)
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

				header, err := ipv4.ParseHeader(b[:n])
				if err != nil {
					log.Logf("[tun] %s <- %s: %v", tun.LocalAddr(), addr, err)
					return err
				}

				if header.Version != ipv4.Version {
					if Debug && header.Version == ipv6.Version {
						if hdr, _ := ipv6.ParseHeader(b[:n]); hdr != nil {
							log.Logf("[tun] %s <<< %s: %s -> %s %d %d",
								tun.LocalAddr(), addr, hdr.Src, hdr.Dst, hdr.PayloadLen, hdr.TrafficClass)
						}
					}
					log.Logf("[tun] %s <- %s: v%d ignored, only support ipv4",
						tun.LocalAddr(), addr, header.Version)
					return nil
				}

				if Debug {
					log.Logf("[tun] %s <<< %s: %s -> %s %d/%d %x %d %d",
						tun.LocalAddr(), addr, header.Src, header.Dst,
						header.Len, header.TotalLen, header.ID, header.Flags, header.Protocol)
				}

				if h.ipNet != nil && h.ipNet.IP.Equal(header.Src.Mask(h.ipNet.Mask)) {
					if actual, loaded := h.routes.LoadOrStore(header.Src.String(), addr); loaded {
						if actual.(net.Addr).String() != addr.String() {
							log.Logf("[tun] %s <- %s: update route: %s -> %s (old %s)",
								tun.LocalAddr(), addr, header.Src, addr, actual.(net.Addr))
							h.routes.Store(header.Src.String(), addr)
						}
					} else {
						log.Logf("[tun] %s: new route: %s -> %s", tun.LocalAddr(), header.Src, addr)
					}
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

type tunListener struct {
	addr   net.Addr
	conns  chan net.Conn
	closed chan struct{}
}

// TunListener creates a listener for tun tunnel.
func TunListener(addr string) (Listener, error) {
	laddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}

	threads := 1
	ln := &tunListener{
		addr:   laddr,
		conns:  make(chan net.Conn, threads),
		closed: make(chan struct{}),
	}

	for i := 0; i < threads; i++ {
		conn, err := net.ListenUDP("udp", laddr)
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

type TapConfig struct {
	Name   string
	Addr   string
	MTU    int
	Routes []string
}

type tapHandler struct {
	raddr   string
	options *HandlerOptions
	ipNet   *net.IPNet
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

	log.Logf("[tap] %s - %s: tap creation successful", tc.LocalAddr(), conn.LocalAddr())

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
	conn, h.ipNet, err = createTap(h.options.TapConfig)
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

				macSrc := waterutil.MACSource(b[:n])
				macDst := waterutil.MACDestination(b[:n])

				addr := raddr
				if v, ok := h.routes.Load(macDst.String()); ok {
					addr = v.(net.Addr)
				}
				if addr == nil {
					log.Logf("[tap] %s: no route for %s -> %s %d %d",
						tap.LocalAddr(), macSrc, macDst, n, waterutil.MACEthertype(b[:n]))
					return nil
				}

				if Debug {
					log.Logf("[tap] %s >>> %s: %s -> %s %d %d",
						tap.LocalAddr(), addr, macSrc, macDst, n, waterutil.MACEthertype(b[:n]))
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

				macSrc := waterutil.MACSource(b[:n])
				macDst := waterutil.MACDestination(b[:n])

				if Debug {
					log.Logf("[tap] %s <<< %s: %s -> %s %d %d",
						tap.LocalAddr(), addr, macSrc, macDst, n, waterutil.MACEthertype(b[:n]))
				}

				if actual, loaded := h.routes.LoadOrStore(macSrc.String(), addr); loaded {
					if actual.(net.Addr).String() != addr.String() {
						log.Logf("[tap] %s <- %s: update route: %s -> %s (old %s)",
							tap.LocalAddr(), addr, macSrc, addr, actual.(net.Addr))
						h.routes.Store(macSrc.String(), addr)
					}
				} else {
					log.Logf("[tap] %s: new route: %s -> %s", tap.LocalAddr(), macSrc, addr)
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

type tapListener struct {
	addr   net.Addr
	conns  chan net.Conn
	closed chan struct{}
}

// TapListener creates a listener for tap tunnel.
func TapListener(addr string) (Listener, error) {
	laddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}

	threads := 1
	ln := &tapListener{
		addr:   laddr,
		conns:  make(chan net.Conn, threads),
		closed: make(chan struct{}),
	}

	for i := 0; i < threads; i++ {
		conn, err := net.ListenUDP("udp", laddr)
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
