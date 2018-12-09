// SNI proxy based on https://github.com/bradfitz/tcpproxy

package gost

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net"
	"net/http"
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

func (c *sniConnector) Connect(conn net.Conn, addr string, options ...ConnectOption) (net.Conn, error) {
	return &sniClientConn{addr: addr, host: c.host, Conn: conn}, nil
}

type sniHandler struct {
	options *HandlerOptions
}

// SNIHandler creates a server Handler for SNI proxy server.
func SNIHandler(opts ...HandlerOption) Handler {
	h := &sniHandler{}
	h.Init(opts...)

	return h
}

func (h *sniHandler) Init(options ...HandlerOption) {
	if h.options == nil {
		h.options = &HandlerOptions{}
	}

	for _, opt := range options {
		opt(h.options)
	}
}

func (h *sniHandler) Handle(conn net.Conn) {
	defer conn.Close()

	br := bufio.NewReader(conn)
	hdr, err := br.Peek(dissector.RecordHeaderLen)
	if err != nil {
		log.Logf("[sni] %s -> %s : %s",
			conn.RemoteAddr(), conn.LocalAddr(), err)
		return
	}
	conn = &bufferdConn{br: br, Conn: conn}

	if hdr[0] != dissector.Handshake {
		// We assume it is an HTTP request
		req, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			log.Logf("[sni] %s -> %s : %s",
				conn.RemoteAddr(), conn.LocalAddr(), err)
			return
		}
		if !req.URL.IsAbs() {
			req.URL.Scheme = "http" // make sure that the URL is absolute
		}
		handler := &httpHandler{options: h.options}
		handler.Init()
		handler.handleRequest(conn, req)
		return
	}

	b, host, err := readClientHelloRecord(conn, "", false)
	if err != nil {
		log.Logf("[sni] %s -> %s : %s",
			conn.RemoteAddr(), conn.LocalAddr(), err)
		return
	}

	_, sport, _ := net.SplitHostPort(h.options.Host)
	if sport == "" {
		sport = "443"
	}
	host = net.JoinHostPort(host, sport)

	log.Logf("[sni] %s -> %s -> %s",
		conn.RemoteAddr(), h.options.Node.String(), host)

	if !Can("tcp", host, h.options.Whitelist, h.options.Blacklist) {
		log.Logf("[sni] %s -> %s : Unauthorized to tcp connect to %s",
			conn.RemoteAddr(), conn.LocalAddr(), host)
		return
	}
	if h.options.Bypass.Contains(host) {
		log.Log("[sni] %s - %s bypass %s",
			conn.RemoteAddr(), conn.LocalAddr(), host)
		return
	}

	retries := 1
	if h.options.Chain != nil && h.options.Chain.Retries > 0 {
		retries = h.options.Chain.Retries
	}
	if h.options.Retries > 0 {
		retries = h.options.Retries
	}

	var cc net.Conn
	var route *Chain
	for i := 0; i < retries; i++ {
		route, err = h.options.Chain.selectRouteFor(host)
		if err != nil {
			log.Logf("[sni] %s -> %s : %s",
				conn.RemoteAddr(), conn.LocalAddr(), err)
			continue
		}

		buf := bytes.Buffer{}
		fmt.Fprintf(&buf, "%s -> %s -> ",
			conn.RemoteAddr(), h.options.Node.String())
		for _, nd := range route.route {
			fmt.Fprintf(&buf, "%d@%s -> ", nd.ID, nd.String())
		}
		fmt.Fprintf(&buf, "%s", host)
		log.Log("[route]", buf.String())

		cc, err = route.Dial(host,
			TimeoutChainOption(h.options.Timeout),
			HostsChainOption(h.options.Hosts),
			ResolverChainOption(h.options.Resolver),
		)
		if err == nil {
			break
		}
		log.Logf("[sni] %s -> %s : %s",
			conn.RemoteAddr(), conn.LocalAddr(), err)
	}

	if err != nil {
		return
	}
	defer cc.Close()

	if _, err := cc.Write(b); err != nil {
		log.Logf("[sni] %s -> %s : %s",
			conn.RemoteAddr(), conn.LocalAddr(), err)
	}

	log.Logf("[sni] %s <-> %s", cc.LocalAddr(), host)
	transport(conn, cc)
	log.Logf("[sni] %s >-< %s", cc.LocalAddr(), host)
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

	buf := &bytes.Buffer{}
	br := bufio.NewReader(bytes.NewReader(p))
	for {
		s, err := br.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				return nil, err
			}
			if s != "" {
				buf.Write([]byte(s))
			}
			break
		}

		// end of HTTP header
		if s == "\r\n" {
			buf.Write([]byte(s))
			// drain the remain bytes.
			io.Copy(buf, br)
			break
		}

		if strings.HasPrefix(s, "Host") {
			s = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(s, "Host:"), "\r\n"))
			host := encodeServerName(s)
			if Debug {
				log.Logf("[sni] obfuscate: %s -> %s", s, c.host)
			}
			buf.WriteString("Host: " + c.host + "\r\n")
			buf.WriteString("Gost-Target: " + host + "\r\n")
			// drain the remain bytes.
			io.Copy(buf, br)
			break
		}
		buf.Write([]byte(s))
	}
	c.obfuscated = true
	return buf.Bytes(), nil
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

	if !isClient {
		var extensions []dissector.Extension

		for _, ext := range clientHello.Extensions {
			if ext.Type() == 0xFFFE {
				if host, err = decodeServerName(string(ext.Bytes()[4:])); err == nil {
					continue
				}
			}
			extensions = append(extensions, ext)
		}
		clientHello.Extensions = extensions
	}

	for _, ext := range clientHello.Extensions {
		if ext.Type() == dissector.ExtServerName {
			snExtension := ext.(*dissector.ServerNameExtension)
			if host == "" {
				host = snExtension.Name
			}
			if isClient {
				clientHello.Extensions = append(clientHello.Extensions,
					dissector.NewExtension(0xFFFE, []byte(encodeServerName(snExtension.Name))))
			}
			if host != "" {
				snExtension.Name = host
			}
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
	buf.WriteString(base64.RawURLEncoding.EncodeToString([]byte(name)))
	return base64.RawURLEncoding.EncodeToString(buf.Bytes())
}

func decodeServerName(s string) (string, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	if len(b) < 4 {
		return "", errors.New("invalid name")
	}
	v, err := base64.RawURLEncoding.DecodeString(string(b[4:]))
	if err != nil {
		return "", err
	}
	if crc32.ChecksumIEEE(v) != binary.BigEndian.Uint32(b[:4]) {
		return "", errors.New("invalid name")
	}
	return string(v), nil
}
