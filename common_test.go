package gost

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/go-log/log"
)

func init() {
	SetLogger(&NopLogger{})
	// SetLogger(&LogLogger{})
	Debug = true
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
		data, _ := io.ReadAll(r.Body)
		if len(data) == 0 {
			data = []byte("Hello World!")
		}
		io.Copy(w, bytes.NewReader(data))
	})

	udpTestHandler = udpHandlerFunc(func(w io.Writer, r *udpRequest) {
		io.Copy(w, r.Body)
	})
)

// proxyConn obtains a connection to the proxy server.
func proxyConn(client *Client, server *Server) (net.Conn, error) {
	conn, err := client.Dial(server.Addr().String())
	if err != nil {
		return nil, err
	}

	cc, err := client.Handshake(conn, AddrHandshakeOption(server.Addr().String()))
	if err != nil {
		conn.Close()
		return nil, err
	}

	return cc, nil
}

// httpRoundtrip does a HTTP request-response roundtrip, and checks the data received.
func httpRoundtrip(conn net.Conn, targetURL string, data []byte) (err error) {
	req, err := http.NewRequest(
		http.MethodGet,
		targetURL,
		bytes.NewReader(data),
	)
	if err != nil {
		return
	}
	if err = req.Write(conn); err != nil {
		return
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return errors.New(resp.Status)
	}

	recv, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	if !bytes.Equal(data, recv) {
		return fmt.Errorf("data not equal")
	}
	return
}

func udpRoundtrip(logger log.Logger, client *Client, server *Server, host string, data []byte) (err error) {
	conn, err := proxyConn(client, server)
	if err != nil {
		return
	}
	defer conn.Close()

	conn, err = client.Connect(conn, host)
	if err != nil {
		return
	}

	conn.SetDeadline(time.Now().Add(1 * time.Second))
	defer conn.SetDeadline(time.Time{})

	if _, err = conn.Write(data); err != nil {
		logger.Logf("write to %s via %s: %s", host, server.Addr(), err)
		return
	}

	recv := make([]byte, len(data))
	if _, err = conn.Read(recv); err != nil {
		logger.Logf("read from %s via %s: %s", host, server.Addr(), err)
		return
	}

	if !bytes.Equal(data, recv) {
		return fmt.Errorf("data not equal")
	}

	return
}

func proxyRoundtrip(client *Client, server *Server, targetURL string, data []byte) (err error) {
	conn, err := proxyConn(client, server)
	if err != nil {
		return err
	}
	defer conn.Close()

	u, err := url.Parse(targetURL)
	if err != nil {
		return
	}

	conn, err = client.Connect(conn, u.Host)
	if err != nil {
		return
	}

	conn.SetDeadline(time.Now().Add(1000 * time.Millisecond))
	defer conn.SetDeadline(time.Time{})

	return httpRoundtrip(conn, targetURL, data)
}

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
	ln        net.PacketConn
	handler   udpHandlerFunc
	wg        sync.WaitGroup
	mu        sync.Mutex // guards closed and conns
	closed    bool
	startChan chan struct{}
	exitChan  chan struct{}
}

func newUDPTestServer(handler udpHandlerFunc) *udpTestServer {
	laddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	ln, err := net.ListenUDP("udp", laddr)
	if err != nil {
		panic(fmt.Sprintf("udptest: failed to listen on a port: %v", err))
	}

	return &udpTestServer{
		ln:        ln,
		handler:   handler,
		startChan: make(chan struct{}),
		exitChan:  make(chan struct{}),
	}
}

func (s *udpTestServer) Start() {
	go s.serve()
	<-s.startChan
}

func (s *udpTestServer) serve() {
	select {
	case <-s.startChan:
		return
	default:
		close(s.startChan)
	}

	for {
		data := make([]byte, 32*1024)
		n, raddr, err := s.ln.ReadFrom(data)
		if err != nil {
			break
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

	// signal the listener has been exited.
	close(s.exitChan)
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

	<-s.exitChan

	s.wg.Wait()

	return err
}
