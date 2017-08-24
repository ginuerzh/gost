package gost

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"time"
)

type tlsTransporter struct {
	tcpTransporter
}

// TLSTransporter creates a Transporter that is used by TLS proxy client.
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
	return wrapTLSClient(conn, opts.TLSConfig)
}

type tlsListener struct {
	net.Listener
}

// TLSListener creates a Listener for TLS proxy server.
func TLSListener(addr string, config *tls.Config) (Listener, error) {
	if config == nil {
		config = DefaultTLSConfig
	}
	ln, err := tls.Listen("tcp", addr, config)
	if err != nil {
		return nil, err
	}
	return &tlsListener{ln}, nil
}

// Wrap a net.Conn into a client tls connection, performing any
// additional verification as needed.
//
// As of go 1.3, crypto/tls only supports either doing no certificate
// verification, or doing full verification including of the peer's
// DNS name. For consul, we want to validate that the certificate is
// signed by a known CA, but because consul doesn't use DNS names for
// node names, we don't verify the certificate DNS names. Since go 1.3
// no longer supports this mode of operation, we have to do it
// manually.
//
// This code is taken from consul:
// https://github.com/hashicorp/consul/blob/master/tlsutil/config.go
func wrapTLSClient(conn net.Conn, tlsConfig *tls.Config) (net.Conn, error) {
	var err error
	var tlsConn *tls.Conn

	tlsConn = tls.Client(conn, tlsConfig)

	// If crypto/tls is doing verification, there's no need to do our own.
	if tlsConfig.InsecureSkipVerify == false {
		return tlsConn, nil
	}

	// Similarly if we use host's CA, we can do full handshake
	if tlsConfig.RootCAs == nil {
		return tlsConn, nil
	}

	// Otherwise perform handshake, but don't verify the domain
	//
	// The following is lightly-modified from the doFullHandshake
	// method in https://golang.org/src/crypto/tls/handshake_client.go
	if err = tlsConn.Handshake(); err != nil {
		tlsConn.Close()
		return nil, err
	}

	opts := x509.VerifyOptions{
		Roots:         tlsConfig.RootCAs,
		CurrentTime:   time.Now(),
		DNSName:       "",
		Intermediates: x509.NewCertPool(),
	}

	certs := tlsConn.ConnectionState().PeerCertificates
	for i, cert := range certs {
		if i == 0 {
			continue
		}
		opts.Intermediates.AddCert(cert)
	}

	_, err = certs[0].Verify(opts)
	if err != nil {
		tlsConn.Close()
		return nil, err
	}

	return tlsConn, err
}
