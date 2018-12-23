package gost

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

func init() {
	// SetLogger(&LogLogger{})
	// Debug = true
	DialTimeout = 1000 * time.Millisecond
	HandshakeTimeout = 1000 * time.Millisecond
	ConnectTimeout = 1000 * time.Millisecond

	cert, err := GenCertificate()
	if err != nil {
		panic(err)
	}
	DefaultTLSConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
}

var (
	httpTestHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(w, r.Body)
	})

	udpTestHandler = udpHandlerFunc(func(w io.Writer, r *udpRequest) {
		io.Copy(w, r.Body)
	})
)

type udpRequest struct {
	Body       io.Reader
	RemoteAddr string
}

type udpResponseWriter struct {
	conn net.PacketConn
	addr net.Addr
}

func (w *udpResponseWriter) Write(p []byte) (int, error) {
	return w.conn.WriteTo(p, w.addr)
}

type udpHandlerFunc func(w io.Writer, r *udpRequest)

// udpTestServer is a UDP server for test.
type udpTestServer struct {
	ln      net.PacketConn
	handler udpHandlerFunc
	wg      sync.WaitGroup
	mu      sync.Mutex // guards closed and conns
	closed  bool
}

func newUDPTestServer(handler udpHandlerFunc) *udpTestServer {
	laddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	ln, err := net.ListenUDP("udp", laddr)
	if err != nil {
		panic(fmt.Sprintf("udptest: failed to listen on a port: %v", err))
	}
	return &udpTestServer{
		ln:      ln,
		handler: handler,
	}
}

func (s *udpTestServer) Start() {
	go s.serve()
}

func (s *udpTestServer) serve() {
	for {
		data := make([]byte, 1024)
		n, raddr, err := s.ln.ReadFrom(data)
		if err != nil {
			return
		}
		if s.handler != nil {
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				w := &udpResponseWriter{
					conn: s.ln,
					addr: raddr,
				}
				r := &udpRequest{
					Body:       bytes.NewReader(data[:n]),
					RemoteAddr: raddr.String(),
				}
				s.handler(w, r)
			}()
		}
	}
}

func (s *udpTestServer) Addr() string {
	return s.ln.LocalAddr().String()
}

func (s *udpTestServer) Close() error {
	s.mu.Lock()

	if s.closed {
		s.mu.Unlock()
		return nil
	}

	err := s.ln.Close()
	s.closed = true
	s.mu.Unlock()

	s.wg.Wait()

	return err
}
