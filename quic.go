package gost

import (
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/go-log/log"
	quic "github.com/lucas-clemente/quic-go"
)

type quicSession struct {
	conn    net.Conn
	session quic.Session
}

func (session *quicSession) GetConn() (*quicConn, error) {
	stream, err := session.session.OpenStream()
	if err != nil {
		return nil, err
	}
	return &quicConn{
		Stream: stream,
		laddr:  session.session.LocalAddr(),
		raddr:  session.session.RemoteAddr(),
	}, nil
}

func (session *quicSession) Close() error {
	return session.session.Close(nil)
}

type quicTransporter struct {
	config       *QUICConfig
	sessionMutex sync.Mutex
	sessions     map[string]*quicSession
}

// QUICTransporter creates a Transporter that is used by QUIC proxy client.
func QUICTransporter(config *QUICConfig) Transporter {
	if config == nil {
		config = &QUICConfig{}
	}
	return &quicTransporter{
		config:   config,
		sessions: make(map[string]*quicSession),
	}
}

func (tr *quicTransporter) Dial(addr string, options ...DialOption) (conn net.Conn, err error) {
	tr.sessionMutex.Lock()
	defer tr.sessionMutex.Unlock()

	session, ok := tr.sessions[addr]
	if !ok {
		conn, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
		if err != nil {
			return
		}
		session = &quicSession{conn: conn}
		tr.sessions[addr] = session
	}
	return session.conn, nil
}

func (tr *quicTransporter) Handshake(conn net.Conn, options ...HandshakeOption) (net.Conn, error) {
	opts := &HandshakeOptions{}
	for _, option := range options {
		option(opts)
	}
	config := tr.config
	if opts.QUICConfig != nil {
		config = opts.QUICConfig
	}
	if config.TLSConfig == nil {
		config.TLSConfig = &tls.Config{InsecureSkipVerify: true}
	}

	tr.sessionMutex.Lock()
	defer tr.sessionMutex.Unlock()

	session, ok := tr.sessions[opts.Addr]
	if session != nil && session.conn != conn {
		conn.Close()
		return nil, errors.New("quic: unrecognized connection")
	}
	if !ok || session.session == nil {
		s, err := tr.initSession(opts.Addr, conn, config)
		if err != nil {
			conn.Close()
			delete(tr.sessions, opts.Addr)
			return nil, err
		}
		session = s
		tr.sessions[opts.Addr] = session
	}
	cc, err := session.GetConn()
	if err != nil {
		session.Close()
		delete(tr.sessions, opts.Addr)
		return nil, err
	}

	return cc, nil
}

func (tr *quicTransporter) initSession(addr string, conn net.Conn, config *QUICConfig) (*quicSession, error) {
	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		return nil, errors.New("quic: wrong connection type")
	}
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	quicConfig := &quic.Config{
		HandshakeTimeout: config.Timeout,
		KeepAlive:        config.KeepAlive,
	}
	session, err := quic.Dial(udpConn, udpAddr, addr, config.TLSConfig, quicConfig)
	if err != nil {
		log.Log("quic dial", err)
		return nil, err
	}
	return &quicSession{conn: conn, session: session}, nil
}

func (tr *quicTransporter) Multiplex() bool {
	return true
}

type QUICConfig struct {
	TLSConfig *tls.Config
	Timeout   time.Duration
	KeepAlive bool
}

type quicListener struct {
	ln       quic.Listener
	connChan chan net.Conn
	errChan  chan error
}

// QUICListener creates a Listener for QUIC proxy server.
func QUICListener(addr string, config *QUICConfig) (Listener, error) {
	if config == nil {
		config = &QUICConfig{}
	}
	quicConfig := &quic.Config{
		HandshakeTimeout: config.Timeout,
		KeepAlive:        config.KeepAlive,
	}

	tlsConfig := config.TLSConfig
	if tlsConfig == nil {
		tlsConfig = DefaultTLSConfig
	}
	ln, err := quic.ListenAddr(addr, tlsConfig, quicConfig)
	if err != nil {
		return nil, err
	}

	l := &quicListener{
		ln:       ln,
		connChan: make(chan net.Conn, 1024),
		errChan:  make(chan error, 1),
	}
	go l.listenLoop()

	return l, nil
}

func (l *quicListener) listenLoop() {
	for {
		session, err := l.ln.Accept()
		if err != nil {
			log.Log("[quic] accept:", err)
			l.errChan <- err
			close(l.errChan)
			return
		}
		go l.sessionLoop(session)
	}
}

func (l *quicListener) sessionLoop(session quic.Session) {
	log.Logf("[quic] %s <-> %s", session.RemoteAddr(), session.LocalAddr())
	defer log.Logf("[quic] %s >-< %s", session.RemoteAddr(), session.LocalAddr())

	for {
		stream, err := session.AcceptStream()
		if err != nil {
			log.Log("[quic] accept stream:", err)
			return
		}

		cc := &quicConn{Stream: stream, laddr: session.LocalAddr(), raddr: session.RemoteAddr()}
		select {
		case l.connChan <- cc:
		default:
			cc.Close()
			log.Logf("[quic] %s - %s: connection queue is full", session.RemoteAddr(), session.LocalAddr())
		}
	}
}

func (l *quicListener) Accept() (conn net.Conn, err error) {
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

func (l *quicListener) Addr() net.Addr {
	return l.ln.Addr()
}

func (l *quicListener) Close() error {
	return l.ln.Close()
}

type quicConn struct {
	quic.Stream
	laddr net.Addr
	raddr net.Addr
}

func (c *quicConn) LocalAddr() net.Addr {
	return c.laddr
}

func (c *quicConn) RemoteAddr() net.Addr {
	return c.raddr
}
