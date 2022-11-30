// obfs4 connection wrappers

package gost

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"

	"github.com/go-log/log"

	pt "git.torproject.org/pluggable-transports/goptlib.git"
	dissector "github.com/go-gost/tls-dissector"
	"gitlab.com/yawning/obfs4.git/transports/base"
	"gitlab.com/yawning/obfs4.git/transports/obfs4"
)

const (
	maxTLSDataLen = 16384
)

type obfsHTTPTransporter struct {
	tcpTransporter
}

// ObfsHTTPTransporter creates a Transporter that is used by HTTP obfuscating tunnel client.
func ObfsHTTPTransporter() Transporter {
	return &obfsHTTPTransporter{}
}

func (tr *obfsHTTPTransporter) Handshake(conn net.Conn, options ...HandshakeOption) (net.Conn, error) {
	opts := &HandshakeOptions{}
	for _, option := range options {
		option(opts)
	}
	return &obfsHTTPConn{Conn: conn, host: opts.Host}, nil
}

type obfsHTTPListener struct {
	net.Listener
}

// ObfsHTTPListener creates a Listener for HTTP obfuscating tunnel server.
func ObfsHTTPListener(addr string) (Listener, error) {
	laddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, err
	}
	ln, err := net.ListenTCP("tcp", laddr)
	if err != nil {
		return nil, err
	}
	return &obfsHTTPListener{Listener: tcpKeepAliveListener{ln}}, nil
}

func (l *obfsHTTPListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	return &obfsHTTPConn{Conn: conn, isServer: true}, nil
}

type obfsHTTPConn struct {
	net.Conn
	host           string
	rbuf           bytes.Buffer
	wbuf           bytes.Buffer
	isServer       bool
	headerDrained  bool
	handshaked     bool
	handshakeMutex sync.Mutex
}

func (c *obfsHTTPConn) Handshake() (err error) {
	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()

	if c.handshaked {
		return nil
	}

	if c.isServer {
		err = c.serverHandshake()
	} else {
		err = c.clientHandshake()
	}
	if err != nil {
		return
	}

	c.handshaked = true
	return nil
}

func (c *obfsHTTPConn) serverHandshake() (err error) {
	br := bufio.NewReader(c.Conn)
	r, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if Debug {
		dump, _ := httputil.DumpRequest(r, false)
		log.Logf("[ohttp] %s -> %s\n%s", c.RemoteAddr(), c.LocalAddr(), string(dump))
	}

	if r.ContentLength > 0 {
		_, err = io.Copy(&c.rbuf, r.Body)
	} else {
		var b []byte
		b, err = br.Peek(br.Buffered())
		if len(b) > 0 {
			_, err = c.rbuf.Write(b)
		}
	}
	if err != nil {
		log.Logf("[ohttp] %s -> %s : %v", c.Conn.RemoteAddr(), c.Conn.LocalAddr(), err)
		return
	}

	b := bytes.Buffer{}

	if r.Method != http.MethodGet || r.Header.Get("Upgrade") != "websocket" {
		b.WriteString("HTTP/1.1 503 Service Unavailable\r\n")
		b.WriteString("Content-Length: 0\r\n")
		b.WriteString("Date: " + time.Now().Format(time.RFC1123) + "\r\n")
		b.WriteString("\r\n")

		if Debug {
			log.Logf("[ohttp] %s <- %s\n%s", c.RemoteAddr(), c.LocalAddr(), b.String())
		}

		b.WriteTo(c.Conn)
		return errors.New("bad request")
	}

	b.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
	b.WriteString("Server: nginx/1.10.0\r\n")
	b.WriteString("Date: " + time.Now().Format(time.RFC1123) + "\r\n")
	b.WriteString("Connection: Upgrade\r\n")
	b.WriteString("Upgrade: websocket\r\n")
	b.WriteString(fmt.Sprintf("Sec-WebSocket-Accept: %s\r\n", computeAcceptKey(r.Header.Get("Sec-WebSocket-Key"))))
	b.WriteString("\r\n")

	if Debug {
		log.Logf("[ohttp] %s <- %s\n%s", c.RemoteAddr(), c.LocalAddr(), b.String())
	}

	if c.rbuf.Len() > 0 {
		c.wbuf = b // cache the response header if there are extra data in the request body.
		return
	}

	_, err = b.WriteTo(c.Conn)
	return
}

func (c *obfsHTTPConn) clientHandshake() (err error) {
	r := &http.Request{
		Method:     http.MethodGet,
		ProtoMajor: 1,
		ProtoMinor: 1,
		URL:        &url.URL{Scheme: "http", Host: c.host},
		Header:     make(http.Header),
	}
	r.Header.Set("User-Agent", DefaultUserAgent)
	r.Header.Set("Connection", "Upgrade")
	r.Header.Set("Upgrade", "websocket")
	key, _ := generateChallengeKey()
	r.Header.Set("Sec-WebSocket-Key", key)

	// cache the request header
	if err = r.Write(&c.wbuf); err != nil {
		return
	}

	if Debug {
		dump, _ := httputil.DumpRequest(r, false)
		log.Logf("[ohttp] %s -> %s\n%s", c.LocalAddr(), c.RemoteAddr(), string(dump))
	}

	return nil
}

func (c *obfsHTTPConn) Read(b []byte) (n int, err error) {
	if err = c.Handshake(); err != nil {
		return
	}

	if !c.isServer {
		if err = c.drainHeader(); err != nil {
			return
		}
	}

	if c.rbuf.Len() > 0 {
		return c.rbuf.Read(b)
	}
	return c.Conn.Read(b)
}

func (c *obfsHTTPConn) drainHeader() (err error) {
	if c.headerDrained {
		return
	}
	c.headerDrained = true

	br := bufio.NewReader(c.Conn)
	// drain and discard the response header
	var line string
	var buf bytes.Buffer
	for {
		line, err = br.ReadString('\n')
		if err != nil {
			return
		}
		buf.WriteString(line)
		if line == "\r\n" {
			break
		}
	}

	if Debug {
		log.Logf("[ohttp] %s <- %s\n%s", c.LocalAddr(), c.RemoteAddr(), buf.String())
	}
	// cache the extra data for next read.
	var b []byte
	b, err = br.Peek(br.Buffered())
	if len(b) > 0 {
		_, err = c.rbuf.Write(b)
	}
	return
}

func (c *obfsHTTPConn) Write(b []byte) (n int, err error) {
	if err = c.Handshake(); err != nil {
		return
	}
	if c.wbuf.Len() > 0 {
		c.wbuf.Write(b) // append the data to the cached header
		_, err = c.wbuf.WriteTo(c.Conn)
		n = len(b) // exclude the header length
		return
	}
	return c.Conn.Write(b)
}

type obfsTLSTransporter struct {
	tcpTransporter
}

// ObfsTLSTransporter creates a Transporter that is used by TLS obfuscating.
func ObfsTLSTransporter() Transporter {
	return &obfsTLSTransporter{}
}

func (tr *obfsTLSTransporter) Handshake(conn net.Conn, options ...HandshakeOption) (net.Conn, error) {
	opts := &HandshakeOptions{}
	for _, option := range options {
		option(opts)
	}
	return ClientObfsTLSConn(conn, opts.Host), nil
}

type obfsTLSListener struct {
	net.Listener
}

// ObfsTLSListener creates a Listener for TLS obfuscating server.
func ObfsTLSListener(addr string) (Listener, error) {
	laddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, err
	}
	ln, err := net.ListenTCP("tcp", laddr)
	if err != nil {
		return nil, err
	}
	return &obfsTLSListener{Listener: tcpKeepAliveListener{ln}}, nil
}

func (l *obfsTLSListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	return ServerObfsTLSConn(conn, ""), nil
}

var (
	cipherSuites = []uint16{
		0xc02c, 0xc030, 0x009f, 0xcca9, 0xcca8, 0xccaa, 0xc02b, 0xc02f,
		0x009e, 0xc024, 0xc028, 0x006b, 0xc023, 0xc027, 0x0067, 0xc00a,
		0xc014, 0x0039, 0xc009, 0xc013, 0x0033, 0x009d, 0x009c, 0x003d,
		0x003c, 0x0035, 0x002f, 0x00ff,
	}

	compressionMethods = []uint8{0x00}

	algorithms = []uint16{
		0x0601, 0x0602, 0x0603, 0x0501, 0x0502, 0x0503, 0x0401, 0x0402,
		0x0403, 0x0301, 0x0302, 0x0303, 0x0201, 0x0202, 0x0203,
	}

	tlsRecordTypes   = []uint8{0x16, 0x14, 0x16, 0x17}
	tlsVersionMinors = []uint8{0x01, 0x03, 0x03, 0x03}

	ErrBadType         = errors.New("bad type")
	ErrBadMajorVersion = errors.New("bad major version")
	ErrBadMinorVersion = errors.New("bad minor version")
	ErrMaxDataLen      = errors.New("bad tls data len")
)

const (
	tlsRecordStateType = iota
	tlsRecordStateVersion0
	tlsRecordStateVersion1
	tlsRecordStateLength0
	tlsRecordStateLength1
	tlsRecordStateData
)

type obfsTLSParser struct {
	step   uint8
	state  uint8
	length uint16
}

type obfsTLSConn struct {
	net.Conn
	rbuf           bytes.Buffer
	wbuf           bytes.Buffer
	host           string
	isServer       bool
	handshaked     chan struct{}
	parser         *obfsTLSParser
	handshakeMutex sync.Mutex
}

func (r *obfsTLSParser) Parse(b []byte) (int, error) {
	i := 0
	last := 0
	length := len(b)

	for i < length {
		ch := b[i]
		switch r.state {
		case tlsRecordStateType:
			if tlsRecordTypes[r.step] != ch {
				return 0, ErrBadType
			}
			r.state = tlsRecordStateVersion0
			i++
		case tlsRecordStateVersion0:
			if ch != 0x03 {
				return 0, ErrBadMajorVersion
			}
			r.state = tlsRecordStateVersion1
			i++
		case tlsRecordStateVersion1:
			if ch != tlsVersionMinors[r.step] {
				return 0, ErrBadMinorVersion
			}
			r.state = tlsRecordStateLength0
			i++
		case tlsRecordStateLength0:
			r.length = uint16(ch) << 8
			r.state = tlsRecordStateLength1
			i++
		case tlsRecordStateLength1:
			r.length |= uint16(ch)
			if r.step == 0 {
				r.length = 91
			} else if r.step == 1 {
				r.length = 1
			} else if r.length > maxTLSDataLen {
				return 0, ErrMaxDataLen
			}
			if r.length > 0 {
				r.state = tlsRecordStateData
			} else {
				r.state = tlsRecordStateType
				r.step++
			}
			i++
		case tlsRecordStateData:
			left := uint16(length - i)
			if left > r.length {
				left = r.length
			}
			if r.step >= 2 {
				skip := i - last
				copy(b[last:], b[i:length])
				length -= int(skip)
				last += int(left)
				i = last
			} else {
				i += int(left)
			}
			r.length -= left
			if r.length == 0 {
				if r.step < 3 {
					r.step++
				}
				r.state = tlsRecordStateType
			}
		}
	}

	if last == 0 {
		return 0, nil
	} else if last < length {
		length -= last
	}

	return length, nil
}

// ClientObfsTLSConn creates a connection for obfs-tls client.
func ClientObfsTLSConn(conn net.Conn, host string) net.Conn {
	return &obfsTLSConn{
		Conn:       conn,
		host:       host,
		handshaked: make(chan struct{}),
		parser:     &obfsTLSParser{},
	}
}

// ServerObfsTLSConn creates a connection for obfs-tls server.
func ServerObfsTLSConn(conn net.Conn, host string) net.Conn {
	return &obfsTLSConn{
		Conn:       conn,
		host:       host,
		isServer:   true,
		handshaked: make(chan struct{}),
	}
}

func (c *obfsTLSConn) Handshaked() bool {
	select {
	case <-c.handshaked:
		return true
	default:
		return false
	}
}

func (c *obfsTLSConn) Handshake(payload []byte) (err error) {
	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()

	if c.Handshaked() {
		return
	}

	if c.isServer {
		err = c.serverHandshake()
	} else {
		err = c.clientHandshake(payload)
	}
	if err != nil {
		return
	}

	close(c.handshaked)
	return nil
}

func (c *obfsTLSConn) clientHandshake(payload []byte) error {
	clientMsg := &dissector.ClientHelloMsg{
		Version:            tls.VersionTLS12,
		SessionID:          make([]byte, 32),
		CipherSuites:       cipherSuites,
		CompressionMethods: compressionMethods,
		Extensions: []dissector.Extension{
			&dissector.SessionTicketExtension{
				Data: payload,
			},
			&dissector.ServerNameExtension{
				Name: c.host,
			},
			&dissector.ECPointFormatsExtension{
				Formats: []uint8{0x01, 0x00, 0x02},
			},
			&dissector.SupportedGroupsExtension{
				Groups: []uint16{0x001d, 0x0017, 0x0019, 0x0018},
			},
			&dissector.SignatureAlgorithmsExtension{
				Algorithms: algorithms,
			},
			&dissector.EncryptThenMacExtension{},
			&dissector.ExtendedMasterSecretExtension{},
		},
	}
	clientMsg.Random.Time = uint32(time.Now().Unix())
	rand.Read(clientMsg.Random.Opaque[:])
	rand.Read(clientMsg.SessionID)
	b, err := clientMsg.Encode()
	if err != nil {
		return err
	}

	record := &dissector.Record{
		Type:    dissector.Handshake,
		Version: tls.VersionTLS10,
		Opaque:  b,
	}
	if _, err := record.WriteTo(c.Conn); err != nil {
		return err
	}
	return err
}

func (c *obfsTLSConn) serverHandshake() error {
	record := &dissector.Record{}
	if _, err := record.ReadFrom(c.Conn); err != nil {
		log.Log(err)
		return err
	}
	if record.Type != dissector.Handshake {
		return dissector.ErrBadType
	}

	clientMsg := &dissector.ClientHelloMsg{}
	if err := clientMsg.Decode(record.Opaque); err != nil {
		log.Log(err)
		return err
	}

	for _, ext := range clientMsg.Extensions {
		if ext.Type() == dissector.ExtSessionTicket {
			b, err := ext.Encode()
			if err != nil {
				log.Log(err)
				return err
			}
			c.rbuf.Write(b)
			break
		}
	}

	serverMsg := &dissector.ServerHelloMsg{
		Version:           tls.VersionTLS12,
		SessionID:         clientMsg.SessionID,
		CipherSuite:       0xcca8,
		CompressionMethod: 0x00,
		Extensions: []dissector.Extension{
			&dissector.RenegotiationInfoExtension{},
			&dissector.ExtendedMasterSecretExtension{},
			&dissector.ECPointFormatsExtension{
				Formats: []uint8{0x00},
			},
		},
	}

	serverMsg.Random.Time = uint32(time.Now().Unix())
	rand.Read(serverMsg.Random.Opaque[:])
	b, err := serverMsg.Encode()
	if err != nil {
		return err
	}

	record = &dissector.Record{
		Type:    dissector.Handshake,
		Version: tls.VersionTLS10,
		Opaque:  b,
	}

	if _, err := record.WriteTo(&c.wbuf); err != nil {
		return err
	}

	record = &dissector.Record{
		Type:    dissector.ChangeCipherSpec,
		Version: tls.VersionTLS12,
		Opaque:  []byte{0x01},
	}
	if _, err := record.WriteTo(&c.wbuf); err != nil {
		return err
	}
	return nil
}

func (c *obfsTLSConn) Read(b []byte) (n int, err error) {
	if c.isServer { // NOTE: only Write performs the handshake operation on client side.
		if err = c.Handshake(nil); err != nil {
			return
		}
	}

	select {
	case <-c.handshaked:
	}

	if c.isServer {
		if c.rbuf.Len() > 0 {
			return c.rbuf.Read(b)
		}
		record := &dissector.Record{}
		if _, err = record.ReadFrom(c.Conn); err != nil {
			return
		}
		n = copy(b, record.Opaque)
		_, err = c.rbuf.Write(record.Opaque[n:])
	} else {
		n, err = c.Conn.Read(b)
		if err != nil {
			return
		}
		if n > 0 {
			n, err = c.parser.Parse(b[:n])
		}
	}
	return
}

func (c *obfsTLSConn) Write(b []byte) (n int, err error) {
	n = len(b)
	if !c.Handshaked() {
		if err = c.Handshake(b); err != nil {
			return
		}
		if !c.isServer { // the data b has been sended during handshake phase.
			return
		}
	}

	for len(b) > 0 {
		data := b
		if len(b) > maxTLSDataLen {
			data = b[:maxTLSDataLen]
			b = b[maxTLSDataLen:]
		} else {
			b = b[:0]
		}
		record := &dissector.Record{
			Type:    dissector.AppData,
			Version: tls.VersionTLS12,
			Opaque:  data,
		}

		if c.wbuf.Len() > 0 {
			record.Type = dissector.Handshake
			record.WriteTo(&c.wbuf)
			_, err = c.wbuf.WriteTo(c.Conn)
			return
		}

		if _, err = record.WriteTo(c.Conn); err != nil {
			return
		}
	}
	return
}

type obfs4Context struct {
	cf    base.ClientFactory
	cargs interface{} // type obfs4ClientArgs
	sf    base.ServerFactory
	sargs *pt.Args
}

var obfs4Map = make(map[string]obfs4Context)

// Obfs4Init initializes the obfs client or server based on isServeNode
func Obfs4Init(node Node, isServeNode bool) error {
	if _, ok := obfs4Map[node.Addr]; ok {
		return fmt.Errorf("obfs4 context already inited")
	}

	t := new(obfs4.Transport)

	stateDir := node.Values.Get("state-dir")
	if stateDir == "" {
		stateDir = "."
	}

	ptArgs := pt.Args(node.Values)

	if !isServeNode {
		cf, err := t.ClientFactory(stateDir)
		if err != nil {
			return err
		}

		cargs, err := cf.ParseArgs(&ptArgs)
		if err != nil {
			return err
		}

		obfs4Map[node.Addr] = obfs4Context{cf: cf, cargs: cargs}
	} else {
		sf, err := t.ServerFactory(stateDir, &ptArgs)
		if err != nil {
			return err
		}

		sargs := sf.Args()

		obfs4Map[node.Addr] = obfs4Context{sf: sf, sargs: sargs}

		log.Log("[obfs4] server inited:", obfs4ServerURL(node))
	}

	return nil
}

func obfs4GetContext(addr string) (obfs4Context, error) {
	ctx, ok := obfs4Map[addr]
	if !ok {
		return obfs4Context{}, fmt.Errorf("obfs4 context not inited")
	}
	return ctx, nil
}

func obfs4ServerURL(node Node) string {
	ctx, err := obfs4GetContext(node.Addr)
	if err != nil {
		return ""
	}

	values := (*url.Values)(ctx.sargs)
	query := values.Encode()
	return fmt.Sprintf(
		"%s+%s://%s/?%s", //obfs4-cert=%s&iat-mode=%s",
		node.Protocol,
		node.Transport,
		node.Addr,
		query,
	)
}

func obfs4ClientConn(addr string, conn net.Conn) (net.Conn, error) {
	ctx, err := obfs4GetContext(addr)
	if err != nil {
		return nil, err
	}

	pseudoDial := func(a, b string) (net.Conn, error) { return conn, nil }
	return ctx.cf.Dial("tcp", "", pseudoDial, ctx.cargs)
}

func obfs4ServerConn(addr string, conn net.Conn) (net.Conn, error) {
	ctx, err := obfs4GetContext(addr)
	if err != nil {
		return nil, err
	}

	return ctx.sf.WrapConn(conn)
}

type obfs4Transporter struct {
	tcpTransporter
}

// Obfs4Transporter creates a Transporter that is used by obfs4 client.
func Obfs4Transporter() Transporter {
	return &obfs4Transporter{}
}

func (tr *obfs4Transporter) Handshake(conn net.Conn, options ...HandshakeOption) (net.Conn, error) {
	opts := &HandshakeOptions{}
	for _, option := range options {
		option(opts)
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = HandshakeTimeout
	}
	conn.SetDeadline(time.Now().Add(timeout))
	defer conn.SetDeadline(time.Time{})

	return obfs4ClientConn(opts.Addr, conn)
}

type obfs4Listener struct {
	addr string
	net.Listener
}

// Obfs4Listener creates a Listener for obfs4 server.
func Obfs4Listener(addr string) (Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	l := &obfs4Listener{
		addr:     addr,
		Listener: tcpKeepAliveListener{ln.(*net.TCPListener)},
	}
	return l, nil
}

// TempError satisfies the net.Error interface and presents itself
// as temporary to make sure that it gets retried by the Accept loop
// in server.go.
type TempError struct {
	error
}

func (e TempError) Timeout() bool   { return false }
func (e TempError) Temporary() bool { return true }

func (l *obfs4Listener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	cc, err := obfs4ServerConn(l.addr, conn)
	if err != nil {
		conn.Close()
		return nil, TempError{err}
	}
	return cc, nil
}
