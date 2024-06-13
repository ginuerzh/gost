package gost

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/go-log/log"
	quic "github.com/quic-go/quic-go"
)

type quicSession struct {
	session quic.EarlyConnection
}

func (session *quicSession) GetConn() (*quicConn, error) {
	stream, err := session.session.OpenStreamSync(context.Background())
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
	return session.session.CloseWithError(quic.ApplicationErrorCode(0), "closed")
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
	opts := &DialOptions{}
	for _, option := range options {
		option(opts)
	}

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}

	tr.sessionMutex.Lock()
	defer tr.sessionMutex.Unlock()

	session, ok := tr.sessions[addr]
	if !ok {
		var pc net.PacketConn
		pc, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
		if err != nil {
			return
		}

		if tr.config != nil && tr.config.Key != nil {
			pc = &quicCipherConn{PacketConn: pc, key: tr.config.Key}
		}

		session, err = tr.initSession(udpAddr, pc)
		if err != nil {
			pc.Close()
			return nil, err
		}
		tr.sessions[addr] = session
	}

	conn, err = session.GetConn()
	if err != nil {
		session.Close()
		delete(tr.sessions, addr)
		return nil, err
	}
	return conn, nil
}

func (tr *quicTransporter) Handshake(conn net.Conn, options ...HandshakeOption) (net.Conn, error) {
	return conn, nil
}

func (tr *quicTransporter) initSession(addr net.Addr, conn net.PacketConn) (*quicSession, error) {
	config := tr.config
	if config == nil {
		config = &QUICConfig{}
	}
	if config.TLSConfig == nil {
		config.TLSConfig = &tls.Config{InsecureSkipVerify: true}
	}

	quicConfig := &quic.Config{
		HandshakeIdleTimeout: config.Timeout,
		MaxIdleTimeout:       config.IdleTimeout,
		KeepAlivePeriod:      config.KeepAlivePeriod,
		Versions: []quic.VersionNumber{
			quic.Version1,
			quic.Version2,
		},
	}
	session, err := quic.DialEarly(context.Background(), conn, addr, tlsConfigQUICALPN(config.TLSConfig), quicConfig)
	if err != nil {
		log.Logf("quic dial %s: %v", addr, err)
		return nil, err
	}
	return &quicSession{session: session}, nil
}

func (tr *quicTransporter) Multiplex() bool {
	return true
}

// QUICConfig is the config for QUIC client and server
type QUICConfig struct {
	TLSConfig       *tls.Config
	Timeout         time.Duration
	KeepAlive       bool
	KeepAlivePeriod time.Duration
	IdleTimeout     time.Duration
	Key             []byte
}

type quicListener struct {
	ln       quic.EarlyListener
	connChan chan net.Conn
	errChan  chan error
}

// QUICListener creates a Listener for QUIC proxy server.
func QUICListener(addr string, config *QUICConfig) (Listener, error) {
	if config == nil {
		config = &QUICConfig{}
	}
	quicConfig := &quic.Config{
		HandshakeIdleTimeout: config.Timeout,
		KeepAlivePeriod:      config.KeepAlivePeriod,
		MaxIdleTimeout:       config.IdleTimeout,
		Versions: []quic.VersionNumber{
			quic.Version1,
			quic.Version2,
		},
	}

	tlsConfig := config.TLSConfig
	if tlsConfig == nil {
		tlsConfig = DefaultTLSConfig
	}
	var conn net.PacketConn

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	conn, err = net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}

	if config.Key != nil {
		conn = &quicCipherConn{PacketConn: conn, key: config.Key}
	}

	ln, err := quic.ListenEarly(conn, tlsConfigQUICALPN(tlsConfig), quicConfig)
	if err != nil {
		return nil, err
	}

	l := &quicListener{
		ln:       *ln,
		connChan: make(chan net.Conn, 1024),
		errChan:  make(chan error, 1),
	}
	go l.listenLoop()

	return l, nil
}

func (l *quicListener) listenLoop() {
	for {
		session, err := l.ln.Accept(context.Background())
		if err != nil {
			log.Log("[quic] accept:", err)
			l.errChan <- err
			close(l.errChan)
			return
		}
		go l.sessionLoop(session)
	}
}

func (l *quicListener) sessionLoop(session quic.Connection) {
	log.Logf("[quic] %s <-> %s", session.RemoteAddr(), session.LocalAddr())
	defer log.Logf("[quic] %s >-< %s", session.RemoteAddr(), session.LocalAddr())

	for {
		stream, err := session.AcceptStream(context.Background())
		if err != nil {
			log.Log("[quic] accept stream:", err)
			session.CloseWithError(quic.ApplicationErrorCode(0), "closed")
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

type quicCipherConn struct {
	net.PacketConn
	key []byte
}

func (conn *quicCipherConn) ReadFrom(data []byte) (n int, addr net.Addr, err error) {
	n, addr, err = conn.PacketConn.ReadFrom(data)
	if err != nil {
		return
	}
	b, err := conn.decrypt(data[:n])
	if err != nil {
		return
	}

	copy(data, b)

	return len(b), addr, nil
}

func (conn *quicCipherConn) WriteTo(data []byte, addr net.Addr) (n int, err error) {
	b, err := conn.encrypt(data)
	if err != nil {
		return
	}

	_, err = conn.PacketConn.WriteTo(b, addr)
	if err != nil {
		return
	}

	return len(b), nil
}

func (conn *quicCipherConn) encrypt(data []byte) ([]byte, error) {
	c, err := aes.NewCipher(conn.key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, data, nil), nil
}

func (conn *quicCipherConn) decrypt(data []byte) ([]byte, error) {
	c, err := aes.NewCipher(conn.key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func tlsConfigQUICALPN(tlsConfig *tls.Config) *tls.Config {
	if tlsConfig == nil {
		panic("quic: tlsconfig is nil")
	}
	tlsConfigQUIC := tlsConfig.Clone()
	tlsConfigQUIC.NextProtos = []string{"http/3", "quic/v1"}
	return tlsConfigQUIC
}
