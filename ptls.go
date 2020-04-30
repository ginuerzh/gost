package gost

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-log/log"
	ss_core "github.com/shadowsocks/go-shadowsocks2/core"
	"github.com/xtaci/smux"
)

const TIMESTAMP_TOLERANCE = 180 * time.Second

const CACHE_CLEAN_INTERVAL = 12 * time.Hour

type PTLSOptions struct {
	Key             string
	Host            string
	BrowserSig      string
	EnableMultiplex bool
}

type ptlsTransporter struct {
	tcpTransporter
	host string
	browser
	key             [16]byte
	enableMultiplex bool
	connCipher      ss_core.StreamConnCipher
}

func PTLSTransporter(opts PTLSOptions) (tr Transporter) {
	var browser browser
	switch opts.BrowserSig {
	case "chrome":
		browser = &Chrome{}
	case "firefox":
		browser = &Firefox{}
	default:
		browser = &Chrome{}
	}
	host, _, err := net.SplitHostPort(opts.Host)
	if err != nil {
		host = opts.Host
	}
	var key [16]byte
	copy(key[:], evpBytesToKey(opts.Key, 16))
	cipher, err := ss_core.PickCipher("AES-128-GCM", nil, opts.Key)
	if err != nil {
		panic(err)
	}
	tr = &ptlsTransporter{
		host:            host,
		browser:         browser,
		key:             key,
		enableMultiplex: opts.EnableMultiplex,
		connCipher:      cipher,
	}
	if opts.EnableMultiplex {
		tr = newMuxTransport(tr)
	}
	return tr
}

func (tr *ptlsTransporter) Handshake(conn net.Conn, options ...HandshakeOption) (net.Conn, error) {
	var random [32]byte
	cryptoRandRead(random[:])
	ai := authenticationInfo{EnableMultiplex: tr.enableMultiplex}
	authPayload := makeAuthenticationPayload(tr.key, random, ai)
	ch := tr.browser.composeClientHello(clientHelloFields{
		random:         random[:],
		sessionId:      authPayload.ciphertextWithTag[:32],
		x25519KeyShare: authPayload.ciphertextWithTag[32:],
		sni:            makeServerName(tr.host),
	})
	_, err := conn.Write(ch)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, 1024)
	_, err = readTLS(conn, buf)
	if err != nil {
		return nil, err
	}

	encrypted := append(buf[11:43], buf[89:121]...)
	nonce := encrypted[0:12]
	ciphertextWithTag := encrypted[12:60]
	_, err = aesGCMDecrypt(nonce, tr.key[:], ciphertextWithTag)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %s", err)
	}

	for i := 0; i < 2; i++ {
		// ChangeCipherSpec and EncryptedCert (in the format of application data)
		_, err = readTLS(conn, buf)
		if err != nil {
			return nil, err
		}
	}
	if Debug {
		log.Logf("[ptls] handshake completed")
	}

	return tr.connCipher.StreamConn(&ptlsConn{Conn: conn}), nil
}

type muxTransport struct {
	originTr   Transporter
	sessionsMu sync.Mutex
	sessions   map[string]*muxTransportSession
}

func newMuxTransport(tr Transporter) *muxTransport {
	if tr.Multiplex() {
		panic("cannot multiplex transport that has already support multiplex")
	}
	return &muxTransport{
		originTr: tr,
		sessions: make(map[string]*muxTransportSession),
	}
}

func (tr *muxTransport) Multiplex() bool {
	return true
}

func (tr *muxTransport) Dial(addr string, options ...DialOption) (conn net.Conn, err error) {
	tr.sessionsMu.Lock()
	defer tr.sessionsMu.Unlock()

	session, ok := tr.sessions[addr]
	if session != nil && session.IsClosed() {
		delete(tr.sessions, addr)
		ok = false // session is dead
	}
	if !ok {
		conn, err = tr.originTr.Dial(addr, options...)
		if err != nil {
			return
		}
		session = &muxTransportSession{conn: conn}
		tr.sessions[addr] = session
	}
	return session.conn, nil
}

func (tr *muxTransport) Handshake(conn net.Conn, options ...HandshakeOption) (net.Conn, error) {
	opts := &HandshakeOptions{}
	for _, option := range options {
		option(opts)
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = HandshakeTimeout
	}

	tr.sessionsMu.Lock()
	defer tr.sessionsMu.Unlock()

	conn.SetDeadline(time.Now().Add(timeout))
	defer conn.SetDeadline(time.Time{})

	session, ok := tr.sessions[opts.Addr]
	if !ok || session.session == nil {
		s, err := tr.initSession(opts.Addr, conn, options...)
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

func (tr *muxTransport) initSession(addr string, conn net.Conn, options ...HandshakeOption) (*muxTransportSession, error) {
	prepared, err := tr.originTr.Handshake(conn, options...)
	if err != nil {
		return nil, err
	}

	// stream multiplex
	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = 2
	session, err := smux.Client(prepared, smuxConfig)
	if err != nil {
		return nil, err
	}
	return &muxTransportSession{conn: prepared, session: session}, nil
}

type muxTransportSession struct {
	conn    net.Conn
	session *smux.Session
}

func (s *muxTransportSession) Close() error {
	if s.session == nil {
		return nil
	}
	return s.session.Close()
}

func (s *muxTransportSession) IsClosed() bool {
	if s.session == nil {
		return true
	}
	return s.session.IsClosed()
}

func (session *muxTransportSession) GetConn() (net.Conn, error) {
	stream, err := session.session.OpenStream()
	if err != nil {
		return nil, err
	}
	return &muxTransportStreamConn{conn: session.conn, Stream: stream}, nil
}

type muxTransportStreamConn struct {
	conn net.Conn
	*smux.Stream
}

type ptlsListener struct {
	net.Listener
	opts       PTLSOptions
	key        [16]byte
	redirHost  string
	redirPort  string
	closed     int32
	conns      chan net.Conn
	usedRandom sync.Map // map[[32]byte]int64
	connCipher ss_core.StreamConnCipher
}

func PTLSListener(addr string, opts PTLSOptions) (Listener, error) {
	tcpln, err := TCPListener(addr)
	if err != nil {
		return nil, err
	}
	redirHost, redirPort, err := parseRedirAddr(opts.Host)
	if err != nil {
		return nil, err
	}

	cipher, err := ss_core.PickCipher("AES-128-GCM", nil, opts.Key)
	if err != nil {
		return nil, err
	}

	var key [16]byte
	copy(key[:], evpBytesToKey(opts.Key, 16))
	ln := &ptlsListener{
		Listener: tcpln,
		opts:     opts, key: key,
		redirHost:  redirHost,
		redirPort:  redirPort,
		conns:      make(chan net.Conn),
		connCipher: cipher,
	}
	go ln.acceptLoop()
	return ln, nil
}

func (ln *ptlsListener) handshake(conn net.Conn) (prepared net.Conn, ai authenticationInfo, err error) {
	firstPacket, err := readFirstPacket(conn)
	if err != nil {
		conn.Close()
		err = fmt.Errorf("failed to read first packet: %s", err)
		return
	}

	ch, err := parseClientHello(firstPacket)
	if err != nil {
		go ln.redirect(conn, firstPacket)
		err = fmt.Errorf("non (or malformed) ClientHello: %s", err)
		return
	}

	ai, err = ln.auth(ch, time.Now())
	if err != nil {
		go ln.redirect(conn, firstPacket)
		return
	}

	reply, err := composeReply(ch, ln.key[:])
	if err != nil {
		err = fmt.Errorf("failed to compose TLS reply: %s", err)
		return
	}
	conn.Write(reply)
	if err != nil {
		conn.Close()
		err = fmt.Errorf("failed to write TLS reploy: %s", err)
		return
	}
	if Debug {
		log.Logf("[ptls] handshake completed")
	}
	prepared = ln.connCipher.StreamConn(&ptlsConn{Conn: conn})
	return
}

func (ln *ptlsListener) auth(ch *ClientHello, serverTime time.Time) (ai authenticationInfo, err error) {
	authPayload, err := unmarshalClientHello(ch, ln.key)
	if err != nil {
		err = fmt.Errorf("failed to unmarshal ClientHello into authenticationPayload")
		return
	}

	_, loaded := ln.usedRandom.LoadOrStore(authPayload.random, time.Now().Unix())
	if loaded {
		err = fmt.Errorf("duplicate random")
		return
	}

	var plaintext []byte
	plaintext, err = aesGCMDecrypt(authPayload.random[0:12], ln.key[:], authPayload.ciphertextWithTag[:])
	if err != nil {
		return
	}
	timestamp := int64(binary.BigEndian.Uint64(plaintext[1:9]))
	clientTime := time.Unix(timestamp, 0)
	if !(clientTime.After(serverTime.Truncate(TIMESTAMP_TOLERANCE)) && clientTime.Before(serverTime.Add(TIMESTAMP_TOLERANCE))) {
		err = fmt.Errorf("timestamp is outside of the accepting window: received timestamp %d", timestamp)
		return
	}
	flags := plaintext[10]
	ai.EnableMultiplex = flags&EnableMultiplex == EnableMultiplex
	return
}

func (ln *ptlsListener) cleanupRandoms(deadline time.Time) {

	ln.usedRandom.Range(func(key, value interface{}) bool {
		ts := value.(int64)
		if ts < deadline.Unix() {
			ln.usedRandom.Delete(key)
		}
		return true
	})
}

func (ln *ptlsListener) redirect(conn net.Conn, firstPacket []byte) {
	defer conn.Close()

	redirPort := ln.redirPort
	if redirPort == "" {
		_, redirPort, _ = net.SplitHostPort(conn.LocalAddr().String())
	}
	redirConn, err := net.Dial("tcp", net.JoinHostPort(ln.redirHost, redirPort))
	if err != nil {
		log.Logf("[ptls] Making connection to redirection server: %s", err)
		return
	}
	defer redirConn.Close()

	_, err = redirConn.Write(firstPacket)
	if err != nil {
		log.Logf("[ptls] Failed to send first packet to redirection server: %s", err)
		return
	}

	transport(conn, redirConn)
}

func (ln *ptlsListener) Accept() (c net.Conn, err error) {
	return <-ln.conns, nil
}

func (ln *ptlsListener) acceptLoop() {
	nextRandomCleanupAt := time.Now().Add(CACHE_CLEAN_INTERVAL)

	for {
		if time.Now().After(nextRandomCleanupAt) {
			ln.cleanupRandoms(nextRandomCleanupAt.Add(-CACHE_CLEAN_INTERVAL))
			nextRandomCleanupAt = nextRandomCleanupAt.Add(CACHE_CLEAN_INTERVAL)
		}

		conn, err := ln.Listener.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				delay := 50 * time.Millisecond
				log.Logf("[ptls] accept error: %v; retrying in %v", ne, delay)
				time.Sleep(delay)
				continue
			}
			if atomic.CompareAndSwapInt32(&ln.closed, 0, 1) {
				close(ln.conns)
			}
			return
		}
		log.Logf("[ptls] %s - %s", conn.RemoteAddr(), ln.Listener.Addr())
		go func(conn net.Conn) {
			preparedConn, ai, err := ln.handshake(conn)
			if err != nil {
				log.Logf("[ptls] failed to handshake conn from %s: %s", conn.RemoteAddr().String(), err)
				return
			}
			if ai.EnableMultiplex {
				conf := smux.DefaultConfig()
				conf.Version = 2
				sess, err := smux.Server(preparedConn, conf)
				if err != nil {
					panic(err)
				}
				defer sess.Close()
				if Debug {
					log.Logf("[ptls] new smux session created for %s", preparedConn.RemoteAddr())
				}
				log.Logf("[ptls] %s <-> %s", conn.RemoteAddr(), ln.Listener.Addr())
				defer log.Logf("[ptls] %s >-< %s", conn.RemoteAddr(), ln.Listener.Addr())
				for {
					if Debug {
						log.Logf("[ptls] accepting streams")
					}
					stream, err := sess.AcceptStream()
					if err != nil {
						if err != io.EOF {
							log.Logf("[ptls] failed to accept stream from %s: %s", preparedConn.RemoteAddr(), err)
						}
						return
					}
					if Debug {
						log.Logf("[ptls] accpet stream  from %s", stream.RemoteAddr())
					}
					if atomic.LoadInt32(&ln.closed) != 0 {
						return
					}
					ln.conns <- stream
				}
			} else {
				if atomic.LoadInt32(&ln.closed) != 0 {
					return
				}
				ln.conns <- preparedConn
			}
		}(conn)
	}
}

type ptlsConn struct {
	net.Conn
	buffer bytes.Buffer
}

func (c *ptlsConn) Write(b []byte) (int, error) {
	record := addRecordLayer(b, []byte{0x17}, []byte{0x03, 0x03})
	n, err := c.Conn.Write(record)
	if err != nil {
		n = 0
	} else {
		n = len(b)
	}
	return n, err
}

func (c *ptlsConn) Read(b []byte) (int, error) {
	if c.buffer.Len() > 0 {
		return c.buffer.Read(b)
	}

	buf := make([]byte, 5+65536)
	for {
		n, err := readTLS(c.Conn, buf)
		if err != nil {
			return 0, err
		}
		if buf[0] != 0x17 {
			continue
		}

		data := buf[5:n]

		copied := copy(b, data[:n])
		if copied < len(data) {
			c.buffer.Write(data[copied:])
		}

		return copied, nil
	}
}

// func (c *ptlsConn) Close() error {
// 	record := addRecordLayer(make([]byte, 26), []byte{0x15}, []byte{0x03, 0x03})
// 	c.Conn.Write(record)
// 	return c.Conn.Close()
// }

func readFirstPacket(c net.Conn) ([]byte, error) {
	buf := make([]byte, 1500)
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	i, err := io.ReadAtLeast(c, buf, 1)
	c.SetReadDeadline(time.Time{})
	return buf[:i], err
}

type authenticationPayload struct {
	random            [32]byte
	ciphertextWithTag [64]byte
}

const (
	EnableMultiplex = 0x1
)

func makeAuthenticationPayload(key [16]byte, random [32]byte, ai authenticationInfo) (payload authenticationPayload) {
	/*
		Version: 0

		Authentication data (48 bytes):
		+--------------+-------------+---------+------------+
		| _Version_    | _Timestamp_ | _Flags_ | _reserved_ |
		+--------------+-------------+---------+------------+
		| 1 byte (0x0) | 8 bytes     | 1 byte  | 38 bytes   |
		+--------------+-------------+---------+------------+

		Flags:

		Currently only EnableMultiplex are specified, that's 0x1
	*/
	timestamp := uint64(time.Now().Unix())

	plaintext := make([]byte, 48)
	plaintext[0] = 0x0                                    // Version
	binary.BigEndian.PutUint64(plaintext[1:9], timestamp) // Timestamp
	flags := byte(0x0)
	if ai.EnableMultiplex {
		flags |= EnableMultiplex
	}
	plaintext[10] = flags
	ciphertextWithTag, _ := aesGCMEncrypt(random[:12], key[:], plaintext)
	copy(payload.ciphertextWithTag[:], ciphertextWithTag[:])
	return
}

func unmarshalClientHello(ch *ClientHello, key [16]byte) (payload authenticationPayload, err error) {
	keyShare, err := parseKeyShare(ch.extensions[[2]byte{0x00, 0x33}])
	if err != nil {
		return
	}

	ciphertextWithTag := append(ch.sessionId, keyShare...)
	if len(ciphertextWithTag) != 64 {
		err = fmt.Errorf("ciphertext has the wrong length: %d", len(ciphertextWithTag))
		return
	}
	copy(payload.ciphertextWithTag[:], ciphertextWithTag)
	copy(payload.random[:], ch.random)
	return
}

type clientHelloFields struct {
	random         []byte
	sessionId      []byte
	x25519KeyShare []byte
	sni            []byte
}

type authenticationInfo struct {
	EnableMultiplex bool
}

type browser interface {
	composeClientHello(clientHelloFields) []byte
}

type Chrome struct{}

func makeGREASE() []byte {
	// see https://tools.ietf.org/html/draft-davidben-tls-grease-01
	// This is exclusive to Chrome.
	var one [1]byte
	cryptoRandRead(one[:])
	sixteenth := one[0] % 16
	monoGREASE := byte(sixteenth*16 + 0xA)
	doubleGREASE := []byte{monoGREASE, monoGREASE}
	return doubleGREASE
}

func (c *Chrome) composeExtensions(sni []byte, keyShare []byte) []byte {

	makeSupportedGroups := func() []byte {
		suppGroupListLen := []byte{0x00, 0x08}
		ret := make([]byte, 2+8)
		copy(ret[0:2], suppGroupListLen)
		copy(ret[2:4], makeGREASE())
		copy(ret[4:], []byte{0x00, 0x1d, 0x00, 0x17, 0x00, 0x18})
		return ret
	}

	makeKeyShare := func(hidden []byte) []byte {
		ret := make([]byte, 43)
		ret[0], ret[1] = 0x00, 0x29 // length 41
		copy(ret[2:4], makeGREASE())
		ret[4], ret[5] = 0x00, 0x01 // length 1
		ret[6] = 0x00
		ret[7], ret[8] = 0x00, 0x1d  // group x25519
		ret[9], ret[10] = 0x00, 0x20 // length 32
		copy(ret[11:43], hidden)
		return ret
	}

	// extension length is always 401, and server name length is variable

	var ext [17][]byte
	ext[0] = addExtRec(makeGREASE(), nil)                         // First GREASE
	ext[1] = addExtRec([]byte{0x00, 0x00}, sni)                   // server name indication
	ext[2] = addExtRec([]byte{0x00, 0x17}, nil)                   // extended_master_secret
	ext[3] = addExtRec([]byte{0xff, 0x01}, []byte{0x00})          // renegotiation_info
	ext[4] = addExtRec([]byte{0x00, 0x0a}, makeSupportedGroups()) // supported groups
	ext[5] = addExtRec([]byte{0x00, 0x0b}, []byte{0x01, 0x00})    // ec point formats
	ext[6] = addExtRec([]byte{0x00, 0x23}, nil)                   // Session tickets
	APLN, _ := hex.DecodeString("000c02683208687474702f312e31")
	ext[7] = addExtRec([]byte{0x00, 0x10}, APLN)                                 // app layer proto negotiation
	ext[8] = addExtRec([]byte{0x00, 0x05}, []byte{0x01, 0x00, 0x00, 0x00, 0x00}) // status request
	sigAlgo, _ := hex.DecodeString("0012040308040401050308050501080606010201")
	ext[9] = addExtRec([]byte{0x00, 0x0d}, sigAlgo)                 // Signature Algorithms
	ext[10] = addExtRec([]byte{0x00, 0x12}, nil)                    // signed cert timestamp
	ext[11] = addExtRec([]byte{0x00, 0x33}, makeKeyShare(keyShare)) // key share
	ext[12] = addExtRec([]byte{0x00, 0x2d}, []byte{0x01, 0x01})     // psk key exchange modes
	suppVersions, _ := hex.DecodeString("0a9A9A0304030303020301")   // 9A9A needs to be a GREASE
	copy(suppVersions[1:3], makeGREASE())
	ext[13] = addExtRec([]byte{0x00, 0x2b}, suppVersions) // supported versions
	ext[14] = addExtRec([]byte{0x00, 0x1b}, []byte{0x02, 0x00, 0x02})
	ext[15] = addExtRec(makeGREASE(), []byte{0x00}) // Last GREASE
	// len(ext[1]) + 172 + len(ext[16]) = 401
	// len(ext[16]) = 229 - len(ext[1])
	// 2+2+len(padding) = 229 - len(ext[1])
	// len(padding) = 225 - len(ext[1])
	ext[16] = addExtRec([]byte{0x00, 0x15}, make([]byte, 225-len(ext[1]))) // padding
	var ret []byte
	for _, e := range ext {
		ret = append(ret, e...)
	}
	return ret
}

func (c *Chrome) composeClientHello(hd clientHelloFields) (ch []byte) {
	var clientHello [12][]byte
	clientHello[0] = []byte{0x01}             // handshake type
	clientHello[1] = []byte{0x00, 0x01, 0xfc} // length 508
	clientHello[2] = []byte{0x03, 0x03}       // client version
	clientHello[3] = hd.random                // random
	clientHello[4] = []byte{0x20}             // session id length 32
	clientHello[5] = hd.sessionId             // session id
	clientHello[6] = []byte{0x00, 0x22}       // cipher suites length 34
	cipherSuites, _ := hex.DecodeString("130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035000a")
	clientHello[7] = append(makeGREASE(), cipherSuites...) // cipher suites
	clientHello[8] = []byte{0x01}                          // compression methods length 1
	clientHello[9] = []byte{0x00}                          // compression methods
	clientHello[11] = c.composeExtensions(hd.sni, hd.x25519KeyShare)
	clientHello[10] = []byte{0x00, 0x00} // extensions length 401
	binary.BigEndian.PutUint16(clientHello[10], uint16(len(clientHello[11])))
	var ret []byte
	for _, c := range clientHello {
		ret = append(ret, c...)
	}
	return addRecordLayer(ret, []byte{0x16}, []byte{0x03, 0x01})
}

type Firefox struct{}

func (f *Firefox) composeExtensions(SNI []byte, keyShare []byte) []byte {
	composeKeyShare := func(hidden []byte) []byte {
		ret := make([]byte, 107)
		ret[0], ret[1] = 0x00, 0x69 // length 105
		ret[2], ret[3] = 0x00, 0x1d // group x25519
		ret[4], ret[5] = 0x00, 0x20 // length 32
		copy(ret[6:38], hidden)
		ret[38], ret[39] = 0x00, 0x17 // group secp256r1
		ret[40], ret[41] = 0x00, 0x41 // length 65
		cryptoRandRead(ret[42:107])
		return ret
	}
	// extension length is always 399, and server name length is variable
	var ext [14][]byte
	ext[0] = addExtRec([]byte{0x00, 0x00}, SNI)          // server name indication
	ext[1] = addExtRec([]byte{0x00, 0x17}, nil)          // extended_master_secret
	ext[2] = addExtRec([]byte{0xff, 0x01}, []byte{0x00}) // renegotiation_info
	suppGroup, _ := hex.DecodeString("000c001d00170018001901000101")
	ext[3] = addExtRec([]byte{0x00, 0x0a}, suppGroup)          // supported groups
	ext[4] = addExtRec([]byte{0x00, 0x0b}, []byte{0x01, 0x00}) // ec point formats
	ext[5] = addExtRec([]byte{0x00, 0x23}, []byte{})           // Session tickets
	APLN, _ := hex.DecodeString("000c02683208687474702f312e31")
	ext[6] = addExtRec([]byte{0x00, 0x10}, APLN)                                 // app layer proto negotiation
	ext[7] = addExtRec([]byte{0x00, 0x05}, []byte{0x01, 0x00, 0x00, 0x00, 0x00}) // status request
	ext[8] = addExtRec([]byte{0x00, 0x33}, composeKeyShare(keyShare))            // key share
	suppVersions, _ := hex.DecodeString("080304030303020301")
	ext[9] = addExtRec([]byte{0x00, 0x2b}, suppVersions) // supported versions
	sigAlgo, _ := hex.DecodeString("001604030503060308040805080604010501060102030201")
	ext[10] = addExtRec([]byte{0x00, 0x0d}, sigAlgo)            // Signature Algorithms
	ext[11] = addExtRec([]byte{0x00, 0x2d}, []byte{0x01, 0x01}) // psk key exchange modes
	ext[12] = addExtRec([]byte{0x00, 0x1c}, []byte{0x40, 0x01}) // record size limit
	// len(ext[0]) + 237 + 4 + len(padding) = 399
	// len(padding) = 158 - len(ext[0])
	ext[13] = addExtRec([]byte{0x00, 0x15}, make([]byte, 163-len(SNI))) // padding
	var ret []byte
	for _, e := range ext {
		ret = append(ret, e...)
	}
	return ret
}

func (f *Firefox) composeClientHello(hd clientHelloFields) (ch []byte) {
	var clientHello [12][]byte
	clientHello[0] = []byte{0x01}             // handshake type
	clientHello[1] = []byte{0x00, 0x01, 0xfc} // length 508
	clientHello[2] = []byte{0x03, 0x03}       // client version
	clientHello[3] = hd.random                // random
	clientHello[4] = []byte{0x20}             // session id length 32
	clientHello[5] = hd.sessionId             // session id
	clientHello[6] = []byte{0x00, 0x24}       // cipher suites length 36
	cipherSuites, _ := hex.DecodeString("130113031302c02bc02fcca9cca8c02cc030c00ac009c013c01400330039002f0035000a")
	clientHello[7] = cipherSuites // cipher suites
	clientHello[8] = []byte{0x01} // compression methods length 1
	clientHello[9] = []byte{0x00} // compression methods

	clientHello[11] = f.composeExtensions(hd.sni, hd.x25519KeyShare)
	clientHello[10] = []byte{0x00, 0x00} // extensions length
	binary.BigEndian.PutUint16(clientHello[10], uint16(len(clientHello[11])))

	var ret []byte
	for _, c := range clientHello {
		ret = append(ret, c...)
	}
	return addRecordLayer(ret, []byte{0x16}, []byte{0x03, 0x01})
}

func makeServerName(serverName string) []byte {
	serverNameListLength := make([]byte, 2)
	binary.BigEndian.PutUint16(serverNameListLength, uint16(len(serverName)+3))
	serverNameType := []byte{0x00} // host_name
	serverNameLength := make([]byte, 2)
	binary.BigEndian.PutUint16(serverNameLength, uint16(len(serverName)))
	ret := make([]byte, 2+1+2+len(serverName))
	copy(ret[0:2], serverNameListLength)
	copy(ret[2:3], serverNameType)
	copy(ret[3:5], serverNameLength)
	copy(ret[5:], serverName)
	return ret
}

type ClientHello struct {
	handshakeType         byte
	length                int
	clientVersion         []byte
	random                []byte
	sessionIdLen          int
	sessionId             []byte
	cipherSuitesLen       int
	cipherSuites          []byte
	compressionMethodsLen int
	compressionMethods    []byte
	extensionsLen         int
	extensions            map[[2]byte][]byte
}

// parseClientHello parses everything on top of the TLS layer
// (including the record layer) into ClientHello type
func parseClientHello(data []byte) (ret *ClientHello, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.New("Malformed ClientHello")
		}
	}()

	if !bytes.Equal(data[0:3], []byte{0x16, 0x03, 0x01}) {
		return ret, errors.New("wrong TLS1.3 handshake magic bytes")
	}

	peeled := make([]byte, len(data)-5)
	copy(peeled, data[5:])
	pointer := 0
	// Handshake Type
	handshakeType := peeled[pointer]
	if handshakeType != 0x01 {
		return ret, errors.New("Not a ClientHello")
	}
	pointer += 1
	// Length
	length := int(binary.BigEndian.Uint32(append([]byte{0x00}, peeled[pointer:pointer+3]...)))
	pointer += 3
	if length != len(peeled[pointer:]) {
		return ret, errors.New("Hello length doesn't match")
	}
	// Client Version
	clientVersion := peeled[pointer : pointer+2]
	pointer += 2
	// Random
	random := peeled[pointer : pointer+32]
	pointer += 32
	// Session ID
	sessionIdLen := int(peeled[pointer])
	pointer += 1
	sessionId := peeled[pointer : pointer+sessionIdLen]
	pointer += sessionIdLen
	// Cipher Suites
	cipherSuitesLen := int(binary.BigEndian.Uint16(peeled[pointer : pointer+2]))
	pointer += 2
	cipherSuites := peeled[pointer : pointer+cipherSuitesLen]
	pointer += cipherSuitesLen
	// Compression Methods
	compressionMethodsLen := int(peeled[pointer])
	pointer += 1
	compressionMethods := peeled[pointer : pointer+compressionMethodsLen]
	pointer += compressionMethodsLen
	// Extensions
	extensionsLen := int(binary.BigEndian.Uint16(peeled[pointer : pointer+2]))
	pointer += 2
	extensions, err := parseExtensions(peeled[pointer:])
	ret = &ClientHello{
		handshakeType,
		length,
		clientVersion,
		random,
		sessionIdLen,
		sessionId,
		cipherSuitesLen,
		cipherSuites,
		compressionMethodsLen,
		compressionMethods,
		extensionsLen,
		extensions,
	}
	return
}

func parseExtensions(input []byte) (ret map[[2]byte][]byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.New("Malformed Extensions")
		}
	}()
	pointer := 0
	totalLen := len(input)
	ret = make(map[[2]byte][]byte)
	for pointer < totalLen {
		var typ [2]byte
		copy(typ[:], input[pointer:pointer+2])
		pointer += 2
		length := int(binary.BigEndian.Uint16(input[pointer : pointer+2]))
		pointer += 2
		data := input[pointer : pointer+length]
		pointer += length
		ret[typ] = data
	}
	return ret, err
}

func composeServerHello(sessionId []byte, sharedSecret []byte) ([]byte, error) {
	nonce := make([]byte, 12)
	cryptoRandRead(nonce)

	zeros := make([]byte, 32)
	encryptedKey, err := aesGCMEncrypt(nonce, sharedSecret, zeros) // 32 + 16 = 48 bytes
	if err != nil {
		return nil, err
	}

	var serverHello [11][]byte
	serverHello[0] = []byte{0x02}                               // handshake type
	serverHello[1] = []byte{0x00, 0x00, 0x76}                   // length 77
	serverHello[2] = []byte{0x03, 0x03}                         // server version
	serverHello[3] = append(nonce[0:12], encryptedKey[0:20]...) // random 32 bytes
	serverHello[4] = []byte{0x20}                               // session id length 32
	serverHello[5] = sessionId                                  // session id
	serverHello[6] = []byte{0xc0, 0x30}                         // cipher suite TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	serverHello[7] = []byte{0x00}                               // compression method null
	serverHello[8] = []byte{0x00, 0x2e}                         // extensions length 46

	keyShare, _ := hex.DecodeString("00330024001d0020")
	keyExchange := make([]byte, 32)
	copy(keyExchange, encryptedKey[20:48])
	cryptoRandRead(keyExchange[28:32])
	serverHello[9] = append(keyShare, keyExchange...)

	serverHello[10], _ = hex.DecodeString("002b00020304")
	var ret []byte
	for _, s := range serverHello {
		ret = append(ret, s...)
	}
	return ret, nil
}

// composeReply composes the ServerHello, ChangeCipherSpec and an ApplicationData messages
// together with their respective record layers into one byte slice.
func composeReply(ch *ClientHello, sharedSecret []byte) ([]byte, error) {
	TLS12 := []byte{0x03, 0x03}
	sh, err := composeServerHello(ch.sessionId, sharedSecret)
	if err != nil {
		return nil, err
	}
	shBytes := addRecordLayer(sh, []byte{0x16}, TLS12)
	ccsBytes := addRecordLayer([]byte{0x01}, []byte{0x14}, TLS12)
	cert := make([]byte, 68) // TODO: add some different lengths maybe?
	cryptoRandRead(cert)
	encryptedCertBytes := addRecordLayer(cert, []byte{0x17}, TLS12)
	ret := append(shBytes, ccsBytes...)
	ret = append(ret, encryptedCertBytes...)
	return ret, nil
}

func cryptoRandRead(buf []byte) {
	_, err := rand.Read(buf)
	if err == nil {
		return
	}
	waitDur := [10]time.Duration{5 * time.Millisecond, 10 * time.Millisecond, 30 * time.Millisecond, 50 * time.Millisecond,
		100 * time.Millisecond, 300 * time.Millisecond, 500 * time.Millisecond, 1 * time.Second,
		3 * time.Second, 5 * time.Second}
	for i := 0; i < 10; i++ {
		log.Logf("Failed to get cryptographic random bytes: %s. Retrying...", err)
		_, err = rand.Read(buf)
		if err == nil {
			return
		}
		time.Sleep(time.Millisecond * waitDur[i])
	}
	panic("Cannot get cryptographic random bytes after 10 retries")
}

func addExtRec(typ []byte, data []byte) []byte {
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(data)))
	ret := make([]byte, 2+2+len(data))
	copy(ret[0:2], typ)
	copy(ret[2:4], length)
	copy(ret[4:], data)
	return ret
}

func md5sum(d []byte) []byte {
	h := md5.New()
	h.Write(d)
	return h.Sum(nil)
}

func evpBytesToKey(password string, keyLen int) (key []byte) {
	const md5Len = 16

	cnt := (keyLen-1)/md5Len + 1
	m := make([]byte, cnt*md5Len)
	copy(m, md5sum([]byte(password)))

	// Repeatedly call md5 until bytes generated is enough.
	// Each call to md5 uses data: prev md5 sum + password.
	d := make([]byte, md5Len+len(password))
	start := 0
	for i := 1; i < cnt; i++ {
		start += md5Len
		copy(d, m[start-md5Len:start])
		copy(d[md5Len:], password)
		copy(m[start:], md5sum(d))
	}
	return m[:keyLen]
}

func aesGCMEncrypt(nonce []byte, key []byte, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aesgcm.Seal(nil, nonce, plaintext, nil), nil
}

func aesGCMDecrypt(nonce []byte, key []byte, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plain, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plain, nil
}

func addRecordLayer(input []byte, typ []byte, ver []byte) []byte {
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(input)))
	ret := make([]byte, 5+len(input))
	copy(ret[0:1], typ)
	copy(ret[1:3], ver)
	copy(ret[3:5], length)
	copy(ret[5:], input)
	return ret
}

func readTLS(conn net.Conn, buffer []byte) (n int, err error) {
	// TCP is a stream. Multiple TLS messages can arrive at the same time,
	// a single message can also be segmented due to MTU of the IP layer.
	// This function guareentees a single TLS message to be read and everything
	// else is left in the buffer.
	i, err := io.ReadFull(conn, buffer[:5])
	if err != nil {
		return
	}

	dataLength := int(binary.BigEndian.Uint16(buffer[3:5]))
	if dataLength > len(buffer) {
		err = errors.New("Reading TLS message: message size greater than buffer. message size: " + strconv.Itoa(dataLength))
		return
	}
	left := dataLength
	readPtr := 5

	for left != 0 {
		// If left > buffer size (i.e. our message got segmented), the entire MTU is read
		// if left = buffer size, the entire buffer is all there left to read
		// if left < buffer size (i.e. multiple messages came together),
		// only the message we want is read

		i, err = conn.Read(buffer[readPtr : readPtr+left])
		if err != nil {
			return
		}
		left -= i
		readPtr += i
	}

	n = 5 + dataLength
	return
}

func parseKeyShare(input []byte) (ret []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.New("malformed key_share")
		}
	}()
	totalLen := int(binary.BigEndian.Uint16(input[0:2]))
	// 2 bytes "client key share length"
	pointer := 2
	for pointer < totalLen {
		if bytes.Equal([]byte{0x00, 0x1d}, input[pointer:pointer+2]) {
			// skip "key exchange length"
			pointer += 2
			length := int(binary.BigEndian.Uint16(input[pointer : pointer+2]))
			pointer += 2
			if length != 32 {
				return nil, fmt.Errorf("key share length should be 32, instead of %v", length)
			}
			return input[pointer : pointer+length], nil
		}
		pointer += 2
		length := int(binary.BigEndian.Uint16(input[pointer : pointer+2]))
		pointer += 2
		_ = input[pointer : pointer+length]
		pointer += length
	}
	return nil, errors.New("x25519 does not exist")
}

func parseRedirAddr(redirAddr string) (string, string, error) {
	var host string
	var port string
	colonSep := strings.Split(redirAddr, ":")
	if len(colonSep) > 1 {
		if len(colonSep) == 2 {
			// domain or ipv4 with port
			host = colonSep[0]
			port = colonSep[1]
		} else {
			if strings.Contains(redirAddr, "[") {
				// ipv6 with port
				port = colonSep[len(colonSep)-1]
				host = strings.TrimSuffix(redirAddr, "]:"+port)
				host = strings.TrimPrefix(host, "[")
			} else {
				// ipv6 without port
				host = redirAddr
			}
		}
	} else {
		// domain or ipv4 without port
		host = redirAddr
	}

	redirHost, err := net.ResolveIPAddr("ip", host)
	if err != nil {
		return "", "", fmt.Errorf("unable to resolve RedirAddr: %v. ", err)
	}
	return redirHost.String(), port, nil
}
