package gost

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/go-log/log"

	smux "gopkg.in/xtaci/smux.v1"
)

type tlsTransporter struct {
	tcpTransporter
}

// TLSTransporter creates a Transporter that is used by TLS proxy client.
func TLSTransporter() Transporter {
	return &tlsTransporter{}
}

func (tr *tlsTransporter) Handshake(conn net.Conn, options ...HandshakeOption) (net.Conn, error) {
	opts := &HandshakeOptions{}
	for _, option := range options {
		option(opts)
	}
	if opts.TLSConfig == nil {
		opts.TLSConfig = &tls.Config{InsecureSkipVerify: true}
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = HandshakeTimeout
	}

	return wrapTLSClient(conn, opts.TLSConfig, timeout)
}

type mtlsTransporter struct {
	tcpTransporter
	sessions     map[string]*muxSession
	sessionMutex sync.Mutex
}

// MTLSTransporter creates a Transporter that is used by multiplex-TLS proxy client.
func MTLSTransporter() Transporter {
	return &mtlsTransporter{
		sessions: make(map[string]*muxSession),
	}
}

func (tr *mtlsTransporter) Dial(addr string, options ...DialOption) (conn net.Conn, err error) {
	opts := &DialOptions{}
	for _, option := range options {
		option(opts)
	}

	tr.sessionMutex.Lock()
	defer tr.sessionMutex.Unlock()

	session, ok := tr.sessions[addr]
	if session != nil && session.IsClosed() {
		delete(tr.sessions, addr)
		ok = false // session is dead
	}
	if !ok {
		timeout := opts.Timeout
		if timeout <= 0 {
			timeout = DialTimeout
		}

		if opts.Chain == nil {
			conn, err = net.DialTimeout("tcp", addr, timeout)
		} else {
			conn, err = opts.Chain.Dial(addr)
		}
		if err != nil {
			return
		}
		session = &muxSession{conn: conn}
		tr.sessions[addr] = session
	}
	return session.conn, nil
}

func (tr *mtlsTransporter) Handshake(conn net.Conn, options ...HandshakeOption) (net.Conn, error) {
	opts := &HandshakeOptions{}
	for _, option := range options {
		option(opts)
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = HandshakeTimeout
	}

	tr.sessionMutex.Lock()
	defer tr.sessionMutex.Unlock()

	conn.SetDeadline(time.Now().Add(timeout))
	defer conn.SetDeadline(time.Time{})

	session, ok := tr.sessions[opts.Addr]
	if !ok || session.session == nil {
		s, err := tr.initSession(opts.Addr, conn, opts)
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

func (tr *mtlsTransporter) initSession(addr string, conn net.Conn, opts *HandshakeOptions) (*muxSession, error) {
	if opts == nil {
		opts = &HandshakeOptions{}
	}
	if opts.TLSConfig == nil {
		opts.TLSConfig = &tls.Config{InsecureSkipVerify: true}
	}
	conn, err := wrapTLSClient(conn, opts.TLSConfig, opts.Timeout)
	if err != nil {
		return nil, err
	}

	// stream multiplex
	smuxConfig := smux.DefaultConfig()
	session, err := smux.Client(conn, smuxConfig)
	if err != nil {
		return nil, err
	}
	return &muxSession{conn: conn, session: session}, nil
}

func (tr *mtlsTransporter) Multiplex() bool {
	return true
}

type tlsListener struct {
	net.Listener
}

// TLSListener creates a Listener for TLS proxy server.
func TLSListener(addr string, config *tls.Config) (Listener, error) {
	if config == nil {
		config = DefaultTLSConfig
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	ln = tls.NewListener(tcpKeepAliveListener{ln.(*net.TCPListener)}, config)
	return &tlsListener{ln}, nil
}

type mtlsListener struct {
	ln       net.Listener
	connChan chan net.Conn
	errChan  chan error
}

// MTLSListener creates a Listener for multiplex-TLS proxy server.
func MTLSListener(addr string, config *tls.Config) (Listener, error) {
	if config == nil {
		config = DefaultTLSConfig
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	l := &mtlsListener{
		ln:       tls.NewListener(tcpKeepAliveListener{ln.(*net.TCPListener)}, config),
		connChan: make(chan net.Conn, 1024),
		errChan:  make(chan error, 1),
	}
	go l.listenLoop()

	return l, nil
}

func (l *mtlsListener) listenLoop() {
	for {
		conn, err := l.ln.Accept()
		if err != nil {
			log.Log("[mtls] accept:", err)
			l.errChan <- err
			close(l.errChan)
			return
		}
		go l.mux(conn)
	}
}

func (l *mtlsListener) mux(conn net.Conn) {
	log.Logf("[mtls] %s - %s", conn.RemoteAddr(), l.Addr())
	smuxConfig := smux.DefaultConfig()
	mux, err := smux.Server(conn, smuxConfig)
	if err != nil {
		log.Logf("[mtls] %s - %s : %s", conn.RemoteAddr(), l.Addr(), err)
		return
	}
	defer mux.Close()

	log.Logf("[mtls] %s <-> %s", conn.RemoteAddr(), l.Addr())
	defer log.Logf("[mtls] %s >-< %s", conn.RemoteAddr(), l.Addr())

	for {
		stream, err := mux.AcceptStream()
		if err != nil {
			log.Log("[mtls] accept stream:", err)
			return
		}

		cc := &muxStreamConn{Conn: conn, stream: stream}
		select {
		case l.connChan <- cc:
		default:
			cc.Close()
			log.Logf("[mtls] %s - %s: connection queue is full", conn.RemoteAddr(), conn.LocalAddr())
		}
	}
}

func (l *mtlsListener) Accept() (conn net.Conn, err error) {
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
func (l *mtlsListener) Addr() net.Addr {
	return l.ln.Addr()
}

func (l *mtlsListener) Close() error {
	return l.ln.Close()
}

// Wrap a net.Conn into a client tls connection, performing any
// additional verification as needed.
//
// As of go 1.3, crypto/tls only supports either doing no certificate
// verification, or doing full verification including of the peer's
// DNS name. For consul, we want to validate that the certificate is
// signed by a known CA, but because consul doesn't use DNS names for
// node names, we don't verify the certificate DNS names. Since go 1.3
// no longer supports this mode of operation, we have to do it
// manually.
//
// This code is taken from consul:
// https://github.com/hashicorp/consul/blob/master/tlsutil/config.go
func wrapTLSClient(conn net.Conn, tlsConfig *tls.Config, timeout time.Duration) (net.Conn, error) {
	var err error
	var tlsConn *tls.Conn

	if timeout <= 0 {
		timeout = HandshakeTimeout // default timeout
	}

	conn.SetDeadline(time.Now().Add(timeout))
	defer conn.SetDeadline(time.Time{})

	tlsConn = tls.Client(conn, tlsConfig)

	// Otherwise perform handshake, but don't verify the domain
	//
	// The following is lightly-modified from the doFullHandshake
	// method in https://golang.org/src/crypto/tls/handshake_client.go
	if err = tlsConn.Handshake(); err != nil {
		tlsConn.Close()
		return nil, err
	}

	// If crypto/tls is doing verification, there's no need to do our own.
	if tlsConfig.InsecureSkipVerify == false {
		return tlsConn, nil
	}

	// Similarly if we use host's CA, we can do full handshake
	if tlsConfig.RootCAs == nil {
		return tlsConn, nil
	}

	opts := x509.VerifyOptions{
		Roots:         tlsConfig.RootCAs,
		CurrentTime:   time.Now(),
		DNSName:       "",
		Intermediates: x509.NewCertPool(),
	}

	certs := tlsConn.ConnectionState().PeerCertificates
	for i, cert := range certs {
		if i == 0 {
			continue
		}
		opts.Intermediates.AddCert(cert)
	}

	_, err = certs[0].Verify(opts)
	if err != nil {
		tlsConn.Close()
		return nil, err
	}

	return tlsConn, err
}
