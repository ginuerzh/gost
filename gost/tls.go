package gost

import (
	"context"
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

func (tr *tlsTransporter) Handshake(ctx context.Context, conn net.Conn) (net.Conn, error) {
	return tls.Client(conn, tr.TLSClientConfig), nil
}
