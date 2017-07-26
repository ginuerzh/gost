package gost

import (
	"crypto/tls"
	"net"
)

type tlsTransporter struct {
	*tcpTransporter
}

// TLSTransporter creates a Transporter that is used by TLS proxy client.
// It accepts a TLS config for TLS handshake.
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
	return tls.Client(conn, opts.TLSConfig), nil
}

func (tr *tlsTransporter) Multiplex() bool {
	return false
}

type tlsListener struct {
	net.Listener
}

// TLSListener creates a Listener for TLS proxy server.
func TLSListener(addr string, config *tls.Config) (Listener, error) {
	ln, err := tls.Listen("tcp", addr, config)
	if err != nil {
		return nil, err
	}
	return &tlsListener{ln}, nil
}
