package gost

import (
	"crypto/tls"
	"net"
)

type tlsTransporter struct {
	tlsConfig *tls.Config
}

// TLSTransporter creates a Transporter that is used by TLS proxy client.
// It accepts a TLS config for TLS handshake.
func TLSTransporter(cfg *tls.Config) Transporter {
	return &tlsTransporter{tlsConfig: cfg}
}

func (tr *tlsTransporter) Dial(addr string) (net.Conn, error) {
	return net.Dial("tcp", addr)
}

func (tr *tlsTransporter) Handshake(conn net.Conn) (net.Conn, error) {
	return tls.Client(conn, tr.tlsConfig), nil
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
