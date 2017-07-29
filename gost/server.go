package gost

import (
	"io"
	"net"
	"time"

	"github.com/go-log/log"
)

// Server is a proxy server.
type Server struct {
}

// Serve serves as a proxy server.
func (s *Server) Serve(l net.Listener, h Handler) error {
	defer l.Close()

	if l == nil {
		ln, err := TCPListener(":8080")
		if err != nil {
			return err
		}
		l = ln
	}
	if h == nil {
		h = HTTPHandler()
	}

	var tempDelay time.Duration
	for {
		conn, e := l.Accept()
		if e != nil {
			if ne, ok := e.(net.Error); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if max := 1 * time.Second; tempDelay > max {
					tempDelay = max
				}
				log.Logf("server: Accept error: %v; retrying in %v", e, tempDelay)
				time.Sleep(tempDelay)
				continue
			}
			return e
		}
		tempDelay = 0
		go h.Handle(conn)
	}

}

// Listener is a proxy server listener, just like a net.Listener.
type Listener interface {
	net.Listener
}

type tcpListener struct {
	net.Listener
}

// TCPListener creates a Listener for TCP proxy server.
func TCPListener(addr string) (Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	return &tcpListener{Listener: &tcpKeepAliveListener{ln.(*net.TCPListener)}}, nil
}

type tcpKeepAliveListener struct {
	*net.TCPListener
}

func (ln tcpKeepAliveListener) Accept() (c net.Conn, err error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return
	}
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(KeepAliveTime)
	return tc, nil
}

func transport(rw1, rw2 io.ReadWriter) error {
	errc := make(chan error, 1)
	go func() {
		_, err := io.Copy(rw1, rw2)
		errc <- err
	}()

	go func() {
		_, err := io.Copy(rw2, rw1)
		errc <- err
	}()

	err := <-errc
	if err != nil && err == io.EOF {
		err = nil
	}
	return err
}
