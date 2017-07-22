package gost

import (
	"crypto/tls"
	"io"
	"net"
	"time"

	"net/url"

	"github.com/go-log/log"
)

type Server struct {
	l       net.Listener
	handler Handler
}

func (s *Server) Handle(h Handler) {
	s.handler = h
}

func (s *Server) Serve(l net.Listener) error {
	defer l.Close()

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
		go s.handler.Handle(conn)
	}

}

type Listener interface {
	net.Listener
}

type tcpListener struct {
	net.Listener
}

func TCPListener(addr string) (Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	return &tcpListener{Listener: &tcpKeepAliveListener{ln.(*net.TCPListener)}}, nil
}

type Handler interface {
	Handle(net.Conn)
}

type HandlerOptions struct {
	Chain     *Chain
	Users     []*url.Userinfo
	TLSConfig *tls.Config
}

type HandlerOption func(opts *HandlerOptions)

func ChainHandlerOption(chain *Chain) HandlerOption {
	return func(opts *HandlerOptions) {
		opts.Chain = chain
	}
}

func UsersHandlerOption(users ...*url.Userinfo) HandlerOption {
	return func(opts *HandlerOptions) {
		opts.Users = users
	}
}

func TLSConfigHandlerOption(config *tls.Config) HandlerOption {
	return func(opts *HandlerOptions) {
		opts.TLSConfig = config
	}
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

	return <-errc
}

// tcpKeepAliveListener sets TCP keep-alive timeouts on accepted
// connections. It's used by ListenAndServe and ListenAndServeTLS so
// dead TCP connections (e.g. closing laptop mid-download) eventually
// go away.
type tcpKeepAliveListener struct {
	*net.TCPListener
}

func (ln tcpKeepAliveListener) Accept() (c net.Conn, err error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return
	}
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(3 * time.Minute)
	return tc, nil
}
