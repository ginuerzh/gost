package gost

import (
	"crypto/sha1"
	"encoding/csv"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/pbkdf2"

	"sync"

	"github.com/go-log/log"
	"github.com/klauspost/compress/snappy"
	"gopkg.in/xtaci/kcp-go.v4"
	"gopkg.in/xtaci/smux.v1"
)

var (
	// KCPSalt is the default salt for KCP cipher.
	KCPSalt = "kcp-go"
)

// KCPConfig describes the config for KCP.
type KCPConfig struct {
	Key          string `json:"key"`
	Crypt        string `json:"crypt"`
	Mode         string `json:"mode"`
	MTU          int    `json:"mtu"`
	SndWnd       int    `json:"sndwnd"`
	RcvWnd       int    `json:"rcvwnd"`
	DataShard    int    `json:"datashard"`
	ParityShard  int    `json:"parityshard"`
	DSCP         int    `json:"dscp"`
	NoComp       bool   `json:"nocomp"`
	AckNodelay   bool   `json:"acknodelay"`
	NoDelay      int    `json:"nodelay"`
	Interval     int    `json:"interval"`
	Resend       int    `json:"resend"`
	NoCongestion int    `json:"nc"`
	SockBuf      int    `json:"sockbuf"`
	KeepAlive    int    `json:"keepalive"`
	SnmpLog      string `json:"snmplog"`
	SnmpPeriod   int    `json:"snmpperiod"`
	Signal       bool   `json:"signal"` // Signal enables the signal SIGUSR1 feature.
}

// Init initializes the KCP config.
func (c *KCPConfig) Init() {
	switch c.Mode {
	case "normal":
		c.NoDelay, c.Interval, c.Resend, c.NoCongestion = 0, 40, 2, 1
	case "fast":
		c.NoDelay, c.Interval, c.Resend, c.NoCongestion = 0, 30, 2, 1
	case "fast2":
		c.NoDelay, c.Interval, c.Resend, c.NoCongestion = 1, 20, 2, 1
	case "fast3":
		c.NoDelay, c.Interval, c.Resend, c.NoCongestion = 1, 10, 2, 1
	}
}

var (
	// DefaultKCPConfig is the default KCP config.
	DefaultKCPConfig = KCPConfig{
		Key:          "it's a secrect",
		Crypt:        "aes",
		Mode:         "fast",
		MTU:          1350,
		SndWnd:       1024,
		RcvWnd:       1024,
		DataShard:    10,
		ParityShard:  3,
		DSCP:         0,
		NoComp:       false,
		AckNodelay:   false,
		NoDelay:      0,
		Interval:     50,
		Resend:       0,
		NoCongestion: 0,
		SockBuf:      4194304,
		KeepAlive:    10,
		SnmpLog:      "",
		SnmpPeriod:   60,
		Signal:       false,
	}
)

type kcpTransporter struct {
	sessions     map[string]*muxSession
	sessionMutex sync.Mutex
	config       *KCPConfig
}

// KCPTransporter creates a Transporter that is used by KCP proxy client.
func KCPTransporter(config *KCPConfig) Transporter {
	if config == nil {
		config = &KCPConfig{}
		*config = DefaultKCPConfig
	}
	config.Init()

	go snmpLogger(config.SnmpLog, config.SnmpPeriod)
	if config.Signal {
		go kcpSigHandler()
	}

	return &kcpTransporter{
		config:   config,
		sessions: make(map[string]*muxSession),
	}
}

func (tr *kcpTransporter) Dial(addr string, options ...DialOption) (conn net.Conn, err error) {
	opts := &DialOptions{}
	for _, option := range options {
		option(opts)
	}

	tr.sessionMutex.Lock()
	defer tr.sessionMutex.Unlock()

	session, ok := tr.sessions[addr]
	if session != nil && session.session != nil && session.session.IsClosed() {
		session.Close()
		delete(tr.sessions, addr) // session is dead
		ok = false
	}
	if !ok {
		timeout := opts.Timeout
		if timeout <= 0 {
			timeout = DialTimeout
		}
		conn, err = net.DialTimeout("udp", addr, timeout)
		if err != nil {
			return
		}
		session = &muxSession{conn: conn}
		tr.sessions[addr] = session
	}
	return session.conn, nil
}

func (tr *kcpTransporter) Handshake(conn net.Conn, options ...HandshakeOption) (net.Conn, error) {
	opts := &HandshakeOptions{}
	for _, option := range options {
		option(opts)
	}
	config := tr.config
	if opts.KCPConfig != nil {
		config = opts.KCPConfig
	}
	tr.sessionMutex.Lock()
	defer tr.sessionMutex.Unlock()

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = HandshakeTimeout
	}
	conn.SetDeadline(time.Now().Add(timeout))
	defer conn.SetDeadline(time.Time{})

	session, ok := tr.sessions[opts.Addr]
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

func (tr *kcpTransporter) initSession(addr string, conn net.Conn, config *KCPConfig) (*muxSession, error) {
	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		return nil, errors.New("kcp: wrong connection type")
	}

	kcpconn, err := kcp.NewConn(addr,
		blockCrypt(config.Key, config.Crypt, KCPSalt),
		config.DataShard, config.ParityShard, &connectedUDPConn{udpConn})
	if err != nil {
		return nil, err
	}

	kcpconn.SetStreamMode(true)
	kcpconn.SetWriteDelay(false)
	kcpconn.SetNoDelay(config.NoDelay, config.Interval, config.Resend, config.NoCongestion)
	kcpconn.SetWindowSize(config.SndWnd, config.RcvWnd)
	kcpconn.SetMtu(config.MTU)
	kcpconn.SetACKNoDelay(config.AckNodelay)

	// if err := kcpconn.SetDSCP(config.DSCP); err != nil {
	// 	log.Log("[kcp]", err)
	// }
	if err := kcpconn.SetReadBuffer(config.SockBuf); err != nil {
		log.Log("[kcp]", err)
	}
	if err := kcpconn.SetWriteBuffer(config.SockBuf); err != nil {
		log.Log("[kcp]", err)
	}

	// stream multiplex
	smuxConfig := smux.DefaultConfig()
	smuxConfig.MaxReceiveBuffer = config.SockBuf
	smuxConfig.KeepAliveInterval = time.Duration(config.KeepAlive) * time.Second
	var cc net.Conn = kcpconn
	if !config.NoComp {
		cc = newCompStreamConn(kcpconn)
	}
	session, err := smux.Client(cc, smuxConfig)
	if err != nil {
		return nil, err
	}
	return &muxSession{conn: conn, session: session}, nil
}

func (tr *kcpTransporter) Multiplex() bool {
	return true
}

type kcpListener struct {
	config   *KCPConfig
	ln       *kcp.Listener
	connChan chan net.Conn
	errChan  chan error
}

// KCPListener creates a Listener for KCP proxy server.
func KCPListener(addr string, config *KCPConfig) (Listener, error) {
	if config == nil {
		config = &KCPConfig{}
		*config = DefaultKCPConfig
	}
	config.Init()

	ln, err := kcp.ListenWithOptions(addr,
		blockCrypt(config.Key, config.Crypt, KCPSalt), config.DataShard, config.ParityShard)
	if err != nil {
		return nil, err
	}
	// if err = ln.SetDSCP(config.DSCP); err != nil {
	// 	log.Log("[kcp]", err)
	// }
	if err = ln.SetReadBuffer(config.SockBuf); err != nil {
		log.Log("[kcp]", err)
	}
	if err = ln.SetWriteBuffer(config.SockBuf); err != nil {
		log.Log("[kcp]", err)
	}

	go snmpLogger(config.SnmpLog, config.SnmpPeriod)
	if config.Signal {
		go kcpSigHandler()
	}

	l := &kcpListener{
		config:   config,
		ln:       ln,
		connChan: make(chan net.Conn, 1024),
		errChan:  make(chan error, 1),
	}
	go l.listenLoop()

	return l, nil
}

func (l *kcpListener) listenLoop() {
	for {
		conn, err := l.ln.AcceptKCP()
		if err != nil {
			log.Log("[kcp] accept:", err)
			l.errChan <- err
			close(l.errChan)
			return
		}
		conn.SetStreamMode(true)
		conn.SetWriteDelay(false)
		conn.SetNoDelay(l.config.NoDelay, l.config.Interval, l.config.Resend, l.config.NoCongestion)
		conn.SetMtu(l.config.MTU)
		conn.SetWindowSize(l.config.SndWnd, l.config.RcvWnd)
		conn.SetACKNoDelay(l.config.AckNodelay)
		go l.mux(conn)
	}
}

func (l *kcpListener) mux(conn net.Conn) {
	smuxConfig := smux.DefaultConfig()
	smuxConfig.MaxReceiveBuffer = l.config.SockBuf
	smuxConfig.KeepAliveInterval = time.Duration(l.config.KeepAlive) * time.Second

	log.Logf("[kcp] %s - %s", conn.RemoteAddr(), l.Addr())

	if !l.config.NoComp {
		conn = newCompStreamConn(conn)
	}

	mux, err := smux.Server(conn, smuxConfig)
	if err != nil {
		log.Log("[kcp]", err)
		return
	}
	defer mux.Close()

	log.Logf("[kcp] %s <-> %s", conn.RemoteAddr(), l.Addr())
	defer log.Logf("[kcp] %s >-< %s", conn.RemoteAddr(), l.Addr())

	for {
		stream, err := mux.AcceptStream()
		if err != nil {
			log.Log("[kcp] accept stream:", err)
			return
		}

		cc := &muxStreamConn{Conn: conn, stream: stream}
		select {
		case l.connChan <- cc:
		default:
			cc.Close()
			log.Logf("[kcp] %s - %s: connection queue is full", conn.RemoteAddr(), conn.LocalAddr())
		}
	}
}

func (l *kcpListener) Accept() (conn net.Conn, err error) {
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
func (l *kcpListener) Addr() net.Addr {
	return l.ln.Addr()
}

func (l *kcpListener) Close() error {
	return l.ln.Close()
}

func blockCrypt(key, crypt, salt string) (block kcp.BlockCrypt) {
	pass := pbkdf2.Key([]byte(key), []byte(salt), 4096, 32, sha1.New)

	switch crypt {
	case "sm4":
		block, _ = kcp.NewSM4BlockCrypt(pass[:16])
	case "tea":
		block, _ = kcp.NewTEABlockCrypt(pass[:16])
	case "xor":
		block, _ = kcp.NewSimpleXORBlockCrypt(pass)
	case "none":
		block, _ = kcp.NewNoneBlockCrypt(pass)
	case "aes-128":
		block, _ = kcp.NewAESBlockCrypt(pass[:16])
	case "aes-192":
		block, _ = kcp.NewAESBlockCrypt(pass[:24])
	case "blowfish":
		block, _ = kcp.NewBlowfishBlockCrypt(pass)
	case "twofish":
		block, _ = kcp.NewTwofishBlockCrypt(pass)
	case "cast5":
		block, _ = kcp.NewCast5BlockCrypt(pass[:16])
	case "3des":
		block, _ = kcp.NewTripleDESBlockCrypt(pass[:24])
	case "xtea":
		block, _ = kcp.NewXTEABlockCrypt(pass[:16])
	case "salsa20":
		block, _ = kcp.NewSalsa20BlockCrypt(pass)
	case "aes":
		fallthrough
	default: // aes
		block, _ = kcp.NewAESBlockCrypt(pass)
	}
	return
}

func snmpLogger(format string, interval int) {
	if format == "" || interval == 0 {
		return
	}
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			f, err := os.OpenFile(time.Now().Format(format), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
			if err != nil {
				log.Log("[kcp]", err)
				return
			}
			w := csv.NewWriter(f)
			// write header in empty file
			if stat, err := f.Stat(); err == nil && stat.Size() == 0 {
				if err := w.Write(append([]string{"Unix"}, kcp.DefaultSnmp.Header()...)); err != nil {
					log.Log("[kcp]", err)
				}
			}
			if err := w.Write(append([]string{fmt.Sprint(time.Now().Unix())}, kcp.DefaultSnmp.ToSlice()...)); err != nil {
				log.Log("[kcp]", err)
			}
			kcp.DefaultSnmp.Reset()
			w.Flush()
			f.Close()
		}
	}
}

type compStreamConn struct {
	conn net.Conn
	w    *snappy.Writer
	r    *snappy.Reader
}

func newCompStreamConn(conn net.Conn) *compStreamConn {
	c := new(compStreamConn)
	c.conn = conn
	c.w = snappy.NewBufferedWriter(conn)
	c.r = snappy.NewReader(conn)
	return c
}

func (c *compStreamConn) Read(b []byte) (n int, err error) {
	return c.r.Read(b)
}

func (c *compStreamConn) Write(b []byte) (n int, err error) {
	n, err = c.w.Write(b)
	err = c.w.Flush()
	return n, err
}

func (c *compStreamConn) Close() error {
	return c.conn.Close()
}

func (c *compStreamConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *compStreamConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *compStreamConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *compStreamConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *compStreamConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

// connectedUDPConn is a wrapper for net.UDPConn which converts WriteTo syscalls
// to Write syscalls that are 4 times faster on some OS'es. This should only be
// used for connections that were produced by a net.Dial* call.
type connectedUDPConn struct{ *net.UDPConn }

// WriteTo redirects all writes to the Write syscall, which is 4 times faster.
func (c *connectedUDPConn) WriteTo(b []byte, addr net.Addr) (int, error) { return c.Write(b) }
