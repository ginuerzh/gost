package gost

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-log/log"
)

// udpTransporter is a raw UDP transporter.
type udpTransporter struct{}

// UDPTransporter creates a Transporter for UDP client.
func UDPTransporter() Transporter {
	return &udpTransporter{}
}

func (tr *udpTransporter) Dial(addr string, options ...DialOption) (net.Conn, error) {
	taddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}

	conn, err := net.DialUDP("udp", nil, taddr)
	if err != nil {
		return nil, err
	}
	return &udpClientConn{
		UDPConn: conn,
	}, nil
}

func (tr *udpTransporter) Handshake(conn net.Conn, options ...HandshakeOption) (net.Conn, error) {
	return conn, nil
}

func (tr *udpTransporter) Multiplex() bool {
	return false
}

// UDPListenConfig is the config for UDP Listener.
type UDPListenConfig struct {
	TTL       time.Duration // timeout per connection
	Backlog   int           // connection backlog
	QueueSize int           // recv queue size per connection
}

type udpListener struct {
	ln       net.PacketConn
	connChan chan net.Conn
	errChan  chan error
	connMap  *udpConnMap
	config   *UDPListenConfig
}

// UDPListener creates a Listener for UDP server.
func UDPListener(addr string, cfg *UDPListenConfig) (Listener, error) {
	laddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	ln, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return nil, err
	}

	if cfg == nil {
		cfg = &UDPListenConfig{}
	}

	backlog := cfg.Backlog
	if backlog <= 0 {
		backlog = defaultBacklog
	}

	l := &udpListener{
		ln:       ln,
		connChan: make(chan net.Conn, backlog),
		errChan:  make(chan error, 1),
		connMap:  new(udpConnMap),
		config:   cfg,
	}
	go l.listenLoop()
	return l, nil
}

func (l *udpListener) listenLoop() {
	for {
		b := make([]byte, mediumBufferSize)
		n, raddr, err := l.ln.ReadFrom(b)
		if err != nil {
			log.Logf("[udp] peer -> %s : %s", l.Addr(), err)
			l.Close()
			l.errChan <- err
			close(l.errChan)
			return
		}

		conn, ok := l.connMap.Get(raddr.String())
		if !ok {
			conn = newUDPServerConn(l.ln, raddr, &udpServerConnConfig{
				ttl:   l.config.TTL,
				qsize: l.config.QueueSize,
				onClose: func() {
					l.connMap.Delete(raddr.String())
					log.Logf("[udp] %s closed (%d)", raddr, l.connMap.Size())
				},
			})

			select {
			case l.connChan <- conn:
				l.connMap.Set(raddr.String(), conn)
				log.Logf("[udp] %s -> %s (%d)", raddr, l.Addr(), l.connMap.Size())
			default:
				conn.Close()
				log.Logf("[udp] %s - %s: connection queue is full (%d)", raddr, l.Addr(), cap(l.connChan))
			}
		}

		select {
		case conn.rChan <- b[:n]:
			if Debug {
				log.Logf("[udp] %s >>> %s : length %d", raddr, l.Addr(), n)
			}
		default:
			log.Logf("[udp] %s -> %s : recv queue is full (%d)", raddr, l.Addr(), cap(conn.rChan))
		}
	}
}

func (l *udpListener) Accept() (conn net.Conn, err error) {
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

func (l *udpListener) Addr() net.Addr {
	return l.ln.LocalAddr()
}

func (l *udpListener) Close() error {
	err := l.ln.Close()
	l.connMap.Range(func(k interface{}, v *udpServerConn) bool {
		v.Close()
		return true
	})

	return err
}

type udpConnMap struct {
	size int64
	m    sync.Map
}

func (m *udpConnMap) Get(key interface{}) (conn *udpServerConn, ok bool) {
	v, ok := m.m.Load(key)
	if ok {
		conn, ok = v.(*udpServerConn)
	}
	return
}

func (m *udpConnMap) Set(key interface{}, conn *udpServerConn) {
	m.m.Store(key, conn)
	atomic.AddInt64(&m.size, 1)
}

func (m *udpConnMap) Delete(key interface{}) {
	m.m.Delete(key)
	atomic.AddInt64(&m.size, -1)
}

func (m *udpConnMap) Range(f func(key interface{}, value *udpServerConn) bool) {
	m.m.Range(func(k, v interface{}) bool {
		return f(k, v.(*udpServerConn))
	})
}

func (m *udpConnMap) Size() int64 {
	return atomic.LoadInt64(&m.size)
}

// udpServerConn is a server side connection for UDP client peer, it implements net.Conn and net.PacketConn.
type udpServerConn struct {
	conn       net.PacketConn
	raddr      net.Addr
	rChan      chan []byte
	closed     chan struct{}
	closeMutex sync.Mutex
	nopChan    chan int
	config     *udpServerConnConfig
}

type udpServerConnConfig struct {
	ttl     time.Duration
	qsize   int
	onClose func()
}

func newUDPServerConn(conn net.PacketConn, raddr net.Addr, cfg *udpServerConnConfig) *udpServerConn {
	if conn == nil || raddr == nil {
		return nil
	}

	if cfg == nil {
		cfg = &udpServerConnConfig{}
	}
	qsize := cfg.qsize
	if qsize <= 0 {
		qsize = defaultQueueSize
	}
	c := &udpServerConn{
		conn:    conn,
		raddr:   raddr,
		rChan:   make(chan []byte, qsize),
		closed:  make(chan struct{}),
		nopChan: make(chan int),
		config:  cfg,
	}
	go c.ttlWait()
	return c
}

func (c *udpServerConn) Read(b []byte) (n int, err error) {
	n, _, err = c.ReadFrom(b)
	return
}

func (c *udpServerConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	select {
	case bb := <-c.rChan:
		n = copy(b, bb)
	case <-c.closed:
		err = errors.New("read from closed connection")
		return
	}

	select {
	case c.nopChan <- n:
	default:
	}

	addr = c.raddr

	return
}

func (c *udpServerConn) Write(b []byte) (n int, err error) {
	return c.WriteTo(b, c.raddr)
}

func (c *udpServerConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	n, err = c.conn.WriteTo(b, addr)

	if n > 0 {
		if Debug {
			log.Logf("[udp] %s <<< %s : length %d", addr, c.LocalAddr(), n)
		}

		select {
		case c.nopChan <- n:
		default:
		}
	}

	return
}

func (c *udpServerConn) Close() error {
	c.closeMutex.Lock()
	defer c.closeMutex.Unlock()

	select {
	case <-c.closed:
		return errors.New("connection is closed")
	default:
		if c.config.onClose != nil {
			c.config.onClose()
		}
		close(c.closed)
	}
	return nil
}

func (c *udpServerConn) ttlWait() {
	ttl := c.config.ttl
	if ttl == 0 {
		ttl = defaultTTL
	}
	timer := time.NewTimer(ttl)
	defer timer.Stop()

	for {
		select {
		case <-c.nopChan:
			if !timer.Stop() {
				<-timer.C
			}
			timer.Reset(ttl)
		case <-timer.C:
			c.Close()
			return
		case <-c.closed:
			return
		}
	}
}

func (c *udpServerConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *udpServerConn) RemoteAddr() net.Addr {
	return c.raddr
}

func (c *udpServerConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *udpServerConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *udpServerConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

type udpClientConn struct {
	*net.UDPConn
}

func (c *udpClientConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	return c.UDPConn.Write(b)
}

func (c *udpClientConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	n, err = c.UDPConn.Read(b)
	addr = c.RemoteAddr()
	return
}
