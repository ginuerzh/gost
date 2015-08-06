package main

import (
	"crypto/tls"
	"github.com/ginuerzh/gosocks5"
	"net"
)

type TlsServer struct {
	Addr              string
	CertFile, KeyFile string
}

func (s *TlsServer) ListenAndServe() error {
	return s.listenAndServeTLS()
}

func (s *TlsServer) listenAndServeTLS() error {
	var cert tls.Certificate
	var err error

	if len(s.CertFile) == 0 || len(s.KeyFile) == 0 {
		cert, err = tls.X509KeyPair([]byte(rawCert), []byte(rawKey))
	} else {
		cert, err = tls.LoadX509KeyPair(s.CertFile, s.KeyFile)
	}
	if err != nil {
		return err
	}

	config := &tls.Config{Certificates: []tls.Certificate{cert}}
	l, err := tls.Listen("tcp", s.Addr, config)
	if err != nil {
		return err
	}
	defer l.Close()

	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}

		go func(c net.Conn) {
			c = gosocks5.ServerConn(c, serverConfig)
			serveSocks5(c)
		}(conn)
	}

	return nil
}
