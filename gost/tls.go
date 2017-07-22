package gost

import (
	"crypto/tls"
	"net"
)

type tlsTransporter struct {
	TLSClientConfig *tls.Config
}

func TLSTransporter(cfg *tls.Config) Transporter {
	return &tlsTransporter{TLSClientConfig: cfg}
}

func (tr *tlsTransporter) Network() string {
	return "tcp"
}

func (tr *tlsTransporter) Handshake(conn net.Conn) (net.Conn, error) {
	return tls.Client(conn, tr.TLSClientConfig), nil
}

type tlsListener struct {
	net.Listener
}

func TLSListener(addr string, config *tls.Config) (Listener, error) {
	ln, err := tls.Listen("tcp", addr, config)
	if err != nil {
		return nil, err
	}
	return &tlsListener{Listener: ln}, nil
}
