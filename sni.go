// SNI proxy based on https://github.com/bradfitz/tcpproxy

package gost

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"net"
	"strings"
	"sync"

	dissector "github.com/ginuerzh/tls-dissector"
	"github.com/go-log/log"
)

type sniConnector struct {
	host string
}

// SNIConnector creates a Connector for SNI proxy client.
func SNIConnector(host string) Connector {
	return &sniConnector{host: host}
}

func (c *sniConnector) Connect(conn net.Conn, addr string) (net.Conn, error) {
	return &sniClientConn{addr: addr, host: c.host, Conn: conn}, nil
}

type sniHandler struct {
	options []HandlerOption
}

// SNIHandler creates a server Handler for SNI proxy server.
func SNIHandler(opts ...HandlerOption) Handler {
	h := &sniHandler{
		options: opts,
	}
	return h
}

func (h *sniHandler) Handle(conn net.Conn) {
	br := bufio.NewReader(conn)

	hdr, err := br.Peek(dissector.RecordHeaderLen)
	if err != nil {
		log.Log("[sni]", err)
		conn.Close()
		return
	}
	conn = &bufferdConn{br: br, Conn: conn}

	if hdr[0] != dissector.Handshake {
		// We assume that it is HTTP request
		HTTPHandler(h.options...).Handle(conn)
		return
	}

	defer conn.Close()

	b, host, err := readClientHelloRecord(conn, "", false)
	if err != nil {
		log.Log("[sni]", err)
		return
	}

	options := &HandlerOptions{}
	for _, opt := range h.options {
		opt(options)
	}

	if !Can("tcp", host, options.Whitelist, options.Blacklist) {
		log.Logf("[sni] Unauthorized to tcp connect to %s", host)
		return
	}

	cc, err := options.Chain.Dial(host + ":443")
	if err != nil {
		log.Logf("[sni] %s -> %s : %s", conn.RemoteAddr(), host, err)
		return
	}
	defer cc.Close()

	if _, err := cc.Write(b); err != nil {
		log.Logf("[sni] %s -> %s : %s", conn.RemoteAddr(), host, err)
	}

	log.Logf("[sni] %s <-> %s", cc.LocalAddr(), host)
	transport(conn, cc)
	log.Logf("[sni] %s >-< %s", cc.LocalAddr(), host)
}

// clientHelloServerName returns the SNI server name inside the TLS ClientHello,
// without consuming any bytes from br.
// On any error, the empty string is returned.
func clientHelloServerName(br *bufio.Reader) (isTLS bool, sni string, err error) {
	const recordHeaderLen = 5
	hdr, err := br.Peek(recordHeaderLen)
	if err != nil {
		return
	}
	const recordTypeHandshake = 0x16
	if hdr[0] != recordTypeHandshake {
		return // Not TLS.
	}
	isTLS = true
	recLen := int(hdr[3])<<8 | int(hdr[4]) // ignoring version in hdr[1:3]
	helloBytes, err := br.Peek(recordHeaderLen + recLen)
	if err != nil {
		return
	}
	tls.Server(sniSniffConn{r: bytes.NewReader(helloBytes)}, &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			sni = hello.ServerName
			return nil, nil
		},
	}).Handshake()
	return
}

// sniSniffConn is a net.Conn that reads from r, fails on Writes,
// and crashes otherwise.
type sniSniffConn struct {
	r        io.Reader
	net.Conn // nil; crash on any unexpected use
}

func (c sniSniffConn) Read(p []byte) (int, error) { return c.r.Read(p) }
func (sniSniffConn) Write(p []byte) (int, error)  { return 0, io.EOF }

type sniClientConn struct {
	addr       string
	host       string
	mutex      sync.Mutex
	obfuscated bool
	net.Conn
}

func (c *sniClientConn) Write(p []byte) (int, error) {
	b, err := c.obfuscate(p)
	if err != nil {
		return 0, err
	}
	if _, err = c.Conn.Write(b); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *sniClientConn) obfuscate(p []byte) ([]byte, error) {
	if c.host == "" {
		return p, nil
	}
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.obfuscated {
		return p, nil
	}

	if p[0] == dissector.Handshake {
		b, host, err := readClientHelloRecord(bytes.NewReader(p), c.host, true)
		if err != nil {
			return nil, err
		}
		if Debug {
			log.Logf("[sni] obfuscate: %s -> %s", c.addr, host)
		}
		c.obfuscated = true
		return b, nil
	}

	// TODO: HTTP obfuscate
	c.obfuscated = true
	return p, nil
}

func readClientHelloRecord(r io.Reader, host string, isClient bool) ([]byte, string, error) {
	record, err := dissector.ReadRecord(r)
	if err != nil {
		return nil, "", err
	}
	clientHello := &dissector.ClientHelloHandshake{}
	if err := clientHello.Decode(record.Opaque); err != nil {
		return nil, "", err
	}
	for _, ext := range clientHello.Extensions {
		if ext.Type() == dissector.ExtServerName {
			snExtension := ext.(*dissector.ServerNameExtension)
			serverName := snExtension.Name
			if isClient {
				snExtension.Name = encodeServerName(serverName) + "." + host
			} else {
				if index := strings.IndexByte(serverName, '.'); index > 0 {
					// try to decode the prefix
					if name, err := decodeServerName(serverName[:index]); err == nil {
						snExtension.Name = name
					}
				}
			}
			host = snExtension.Name
			break
		}
	}
	record.Opaque, err = clientHello.Encode()
	if err != nil {
		return nil, "", err
	}

	buf := &bytes.Buffer{}
	if _, err := record.WriteTo(buf); err != nil {
		return nil, "", err
	}

	return buf.Bytes(), host, nil
}

func encodeServerName(name string) string {
	buf := &bytes.Buffer{}
	binary.Write(buf, binary.BigEndian, crc32.ChecksumIEEE([]byte(name)))
	buf.WriteString(base64.StdEncoding.EncodeToString([]byte(name)))
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

func decodeServerName(s string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	if len(b) < 4 {
		return "", errors.New("invalid name")
	}
	v, err := base64.StdEncoding.DecodeString(string(b[4:]))
	if err != nil {
		return "", err
	}
	if crc32.ChecksumIEEE(v) != binary.BigEndian.Uint32(b[:4]) {
		return "", errors.New("invalid name")
	}
	return string(v), nil
}
