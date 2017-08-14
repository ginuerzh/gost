// SNI proxy based on https://github.com/bradfitz/tcpproxy

package gost

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"net"

	"github.com/go-log/log"
)

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
	isTLS, sni, err := clientHelloServerName(br)
	if err != nil {
		log.Log("[sni]", err)
		return
	}

	conn = &bufferdConn{br: br, Conn: conn}
	// We assume that it is HTTP request
	if !isTLS {
		HTTPHandler(h.options...).Handle(conn)
		return
	}

	defer conn.Close()

	if sni == "" {
		log.Log("[sni] The client does not support SNI")
		return
	}

	options := &HandlerOptions{}
	for _, opt := range h.options {
		opt(options)
	}

	if !Can("tcp", sni, options.Whitelist, options.Blacklist) {
		log.Logf("[sni] Unauthorized to tcp connect to %s", sni)
		return
	}

	cc, err := options.Chain.Dial(sni + ":443")
	if err != nil {
		log.Logf("[sni] %s -> %s : %s", conn.RemoteAddr(), sni, err)
		return
	}
	defer cc.Close()
	log.Logf("[sni] %s <-> %s", cc.LocalAddr(), sni)
	transport(conn, cc)
	log.Logf("[sni] %s >-< %s", cc.LocalAddr(), sni)
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
