package gost

import (
	"errors"
	"net"
	"time"

	"github.com/go-log/log"
	"github.com/xtaci/tcpraw"
)

type fakeTCPTransporter struct{}

// FakeTCPTransporter creates a Transporter that is used by fake tcp client.
func FakeTCPTransporter() Transporter {
	return &fakeTCPTransporter{}
}

func (tr *fakeTCPTransporter) Dial(addr string, options ...DialOption) (conn net.Conn, err error) {
	opts := &DialOptions{}
	for _, option := range options {
		option(opts)
	}

	raddr, er := net.ResolveTCPAddr("tcp", addr)
	if er != nil {
		return nil, er
	}
	c, err := tcpraw.Dial("tcp", addr)
	if err != nil {
		return
	}
	conn = &fakeTCPConn{
		raddr:      raddr,
		PacketConn: c,
	}
	return conn, nil
}

func (tr *fakeTCPTransporter) Handshake(conn net.Conn, options ...HandshakeOption) (net.Conn, error) {
	return conn, nil
}

func (tr *fakeTCPTransporter) Multiplex() bool {
	return false
}

// FakeTCPListenConfig is config for fake TCP Listener.
type FakeTCPListenConfig struct {
	TTL       time.Duration
	Backlog   int
	QueueSize int
}

type fakeTCPListener struct {
	ln       net.PacketConn
	connChan chan net.Conn
	errChan  chan error
	connMap  udpConnMap
	config   *FakeTCPListenConfig
}

// FakeTCPListener creates a Listener for fake TCP server.
func FakeTCPListener(addr string, cfg *FakeTCPListenConfig) (Listener, error) {
	ln, err := tcpraw.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	if cfg == nil {
		cfg = &FakeTCPListenConfig{}
	}

	backlog := cfg.Backlog
	if backlog <= 0 {
		backlog = defaultBacklog
	}

	l := &fakeTCPListener{
		ln:       ln,
		connChan: make(chan net.Conn, backlog),
		errChan:  make(chan error, 1),
		config:   cfg,
	}
	go l.listenLoop()
	return l, nil
}

func (l *fakeTCPListener) listenLoop() {
	for {
		b := make([]byte, mediumBufferSize)
		n, raddr, err := l.ln.ReadFrom(b)
		if err != nil {
			log.Logf("[ftcp] peer -> %s : %s", l.Addr(), err)
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
					log.Logf("[ftcp] %s closed (%d)", raddr, l.connMap.Size())
				},
			})

			select {
			case l.connChan <- conn:
				l.connMap.Set(raddr.String(), conn)
				log.Logf("[ftcp] %s -> %s (%d)", raddr, l.Addr(), l.connMap.Size())
			default:
				conn.Close()
				log.Logf("[ftcp] %s - %s: connection queue is full (%d)", raddr, l.Addr(), cap(l.connChan))
			}
		}

		select {
		case conn.rChan <- b[:n]:
			if Debug {
				log.Logf("[ftcp] %s >>> %s : length %d", raddr, l.Addr(), n)
			}
		default:
			log.Logf("[ftcp] %s -> %s : recv queue is full (%d)", raddr, l.Addr(), cap(conn.rChan))
		}
	}
}

func (l *fakeTCPListener) Accept() (conn net.Conn, err error) {
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

func (l *fakeTCPListener) Addr() net.Addr {
	return l.ln.LocalAddr()
}

func (l *fakeTCPListener) Close() error {
	err := l.ln.Close()
	l.connMap.Range(func(k interface{}, v *udpServerConn) bool {
		v.Close()
		return true
	})

	return err
}

type fakeTCPConn struct {
	raddr net.Addr
	net.PacketConn
}

func (c *fakeTCPConn) Read(b []byte) (n int, err error) {
	n, _, err = c.ReadFrom(b)
	return
}

func (c *fakeTCPConn) Write(b []byte) (n int, err error) {
	return c.WriteTo(b, c.raddr)
}

func (c *fakeTCPConn) RemoteAddr() net.Addr {
	return c.raddr
}
