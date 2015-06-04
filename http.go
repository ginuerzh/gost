package main

import (
	"bufio"
	"bytes"
	"code.google.com/p/go-uuid/uuid"
	"github.com/ginuerzh/gosocks5"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"time"
)

const (
	s2cUri = "/s2c"
	c2sUri = "/c2s"
)

type HttpClientConn struct {
	c   net.Conn
	url *url.URL
	r   io.ReadCloser
}

func NewHttpClientConn(conn net.Conn) *HttpClientConn {
	return &HttpClientConn{
		c: conn,
	}
}

func (conn *HttpClientConn) Handshake() error {
	log.Println("remote", conn.c.RemoteAddr().String())
	req := &http.Request{
		Method: "Get",
		Host:   conn.c.RemoteAddr().String(),
		URL: &url.URL{
			Host:   "ignored",
			Scheme: "http",
			Path:   s2cUri,
		},
	}
	if err := req.Write(conn.c); err != nil {
		return err
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn.c), req)
	if err != nil {
		return err
	}

	b := make([]byte, 36)
	if _, err = io.ReadFull(resp.Body, b); err != nil {
		return err
	}
	log.Println("token", string(b))
	q := url.Values{}
	q.Set("token", string(b))
	conn.url = &url.URL{
		Scheme:   "http",
		Host:     conn.c.RemoteAddr().String(),
		Path:     c2sUri,
		RawQuery: q.Encode(),
	}
	conn.r = resp.Body

	return nil
}

func (conn *HttpClientConn) Read(b []byte) (n int, err error) {
	return conn.r.Read(b)
}

func (conn *HttpClientConn) Write(b []byte) (n int, err error) {
	c, err := Connect(Saddr, Proxy)
	if err != nil {
		log.Println(err)
		return
	}

	request, err := http.NewRequest("POST", conn.url.String(), bytes.NewReader(b))
	if err != nil {
		log.Println(err)
		return
	}

	err = request.Write(c)
	if err != nil {
		log.Println(err)
		return
	}

	return len(b), nil
}

func (conn *HttpClientConn) Close() error {
	return conn.r.Close()
}

func (conn *HttpClientConn) LocalAddr() net.Addr {
	return conn.c.LocalAddr()
}

func (conn *HttpClientConn) RemoteAddr() net.Addr {
	return conn.c.RemoteAddr()
}

func (conn *HttpClientConn) SetDeadline(t time.Time) error {
	return conn.c.SetDeadline(t)
}

func (conn *HttpClientConn) SetReadDeadline(t time.Time) error {
	return conn.c.SetReadDeadline(t)
}

func (conn *HttpClientConn) SetWriteDeadline(t time.Time) error {
	return conn.c.SetWriteDeadline(t)
}

type HttpServerConn struct {
	w  http.ResponseWriter
	c  chan []byte
	rb []byte
}

func NewHttpServerConn(w http.ResponseWriter, c chan []byte) *HttpServerConn {
	return &HttpServerConn{
		w: w,
		c: c,
	}
}

func (conn *HttpServerConn) Read(b []byte) (n int, err error) {
	if len(conn.rb) == 0 {
		var ok bool
		if conn.rb, ok = <-conn.c; !ok {
			return 0, io.EOF
		}
	}
	n = copy(b, conn.rb)
	conn.rb = conn.rb[n:]

	//log.Println("ws r:", n)

	return
}

func (conn *HttpServerConn) Write(b []byte) (n int, err error) {
	n, err = conn.w.Write(b)
	if f, ok := conn.w.(http.Flusher); ok {
		f.Flush()
	}
	return
}

func (conn *HttpServerConn) Close() error {
	return nil
}

func (conn *HttpServerConn) LocalAddr() net.Addr {
	return nil
}

func (conn *HttpServerConn) RemoteAddr() net.Addr {
	return nil
}

func (conn *HttpServerConn) SetDeadline(t time.Time) error {
	return nil
}

func (conn *HttpServerConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (conn *HttpServerConn) SetWriteDeadline(t time.Time) error {
	return nil
}

type HttpServer struct {
	Addr  string
	chans map[string]chan []byte
}

func (s *HttpServer) s2c(w http.ResponseWriter, r *http.Request) {
	token := uuid.New()
	ch := make(chan []byte, 1)

	conn := NewHttpServerConn(w, ch)
	if _, err := conn.Write([]byte(token)); err != nil {
		return
	}

	s.chans[token] = ch
	defer delete(s.chans, token)

	c := gosocks5.ServerConn(conn, serverConfig)
	socks5Handle(c)
}

func (s *HttpServer) c2s(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	token := r.FormValue("token")
	ch := s.chans[token]
	if ch == nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	b, err := ioutil.ReadAll(r.Body)
	if err != nil || len(b) == 0 {
		close(ch)
		delete(s.chans, token)
		return
	}
	ch <- b
}

func (s *HttpServer) ListenAndServe() error {
	s.chans = make(map[string]chan []byte)
	http.HandleFunc(s2cUri, s.s2c)
	http.HandleFunc(c2sUri, s.c2s)
	return http.ListenAndServe(s.Addr, nil)
}
