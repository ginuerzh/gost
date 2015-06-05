package main

import (
	"bufio"
	"bytes"
	"code.google.com/p/go-uuid/uuid"
	"errors"
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
	c     net.Conn
	token string
	r     io.ReadCloser
}

func NewHttpClientConn(conn net.Conn) *HttpClientConn {
	return &HttpClientConn{
		c: conn,
	}
}

func (conn *HttpClientConn) Handshake() (err error) {
	//log.Println("remote", conn.c.RemoteAddr().String())
	req := &http.Request{
		Method: "GET",
		URL: &url.URL{
			Host:   Saddr,
			Scheme: "http",
			Path:   s2cUri,
		},
	}
	if len(Proxy) == 0 {
		err = req.Write(conn.c)
	} else {
		err = req.WriteProxy(conn.c)
	}
	if err != nil {
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
	if uuid.Parse(string(b)) == nil {
		return errors.New("wrong token")
	}
	conn.token = string(b)
	conn.r = resp.Body
	//log.Println(conn.token, "connected")

	return nil
}

func (conn *HttpClientConn) Read(b []byte) (n int, err error) {
	n, err = conn.r.Read(b)
	//log.Println("http r:", n)
	return
}

func (conn *HttpClientConn) Write(b []byte) (n int, err error) {
	q := url.Values{}
	q.Set("token", conn.token)
	req := &http.Request{
		Method:        "POST",
		Body:          ioutil.NopCloser(bytes.NewReader(b)),
		ContentLength: int64(len(b)),
		URL: &url.URL{
			Host:     Saddr,
			Scheme:   "http",
			Path:     c2sUri,
			RawQuery: q.Encode(),
		},
	}
	resp, err := doRequest(req, Proxy)
	if err != nil {
		log.Println(err)
		return
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, errors.New(resp.Status)
	}
	//log.Println("http w:", len(b))
	return len(b), nil
}

func (conn *HttpClientConn) Close() error {
	conn.Write(nil)
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
	w      http.ResponseWriter
	c      chan []byte
	closed bool
	rb     []byte
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

	//log.Println("http r:", n)

	return
}

func (conn *HttpServerConn) Write(b []byte) (n int, err error) {
	n, err = conn.w.Write(b)
	if f, ok := conn.w.(http.Flusher); ok {
		f.Flush()
	}
	//log.Println("http w:", n)
	return
}

func (conn *HttpServerConn) Close() error {
	if !conn.closed {
		close(conn.c)
		conn.closed = true
	}
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
	conns map[string]*HttpServerConn
}

func (s *HttpServer) s2c(w http.ResponseWriter, r *http.Request) {
	token := uuid.New()
	ch := make(chan []byte, 1)

	conn := NewHttpServerConn(w, ch)
	if _, err := conn.Write([]byte(token)); err != nil {
		return
	}

	s.conns[token] = conn
	defer delete(s.conns, token)

	socks5Handle(gosocks5.ServerConn(conn, serverConfig))
}

func (s *HttpServer) c2s(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	token := r.FormValue("token")
	conn := s.conns[token]
	if conn == nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	b, err := ioutil.ReadAll(r.Body)
	if err != nil || len(b) == 0 {
		conn.Close()
		delete(s.conns, token)
		//log.Println(token, "disconnected")
		return
	}
	conn.c <- b
}

func (s *HttpServer) ListenAndServe() error {
	s.conns = make(map[string]*HttpServerConn)
	http.HandleFunc(s2cUri, s.s2c)
	http.HandleFunc(c2sUri, s.c2s)
	return http.ListenAndServe(s.Addr, nil)
}

func doRequest(req *http.Request, proxy string) (*http.Response, error) {
	if len(proxy) > 0 {
		c, err := Connect(proxy)
		if err != nil {
			log.Println(err)
			return nil, err
		}
		defer c.Close()

		if err := req.WriteProxy(c); err != nil {
			log.Println(err)
			return nil, err
		}
		/*
			b, err := ioutil.ReadAll(c)
			if err != nil {
				log.Println(err)
				return nil, err
			}
		*/
		return http.ReadResponse(bufio.NewReader(c), req)
	}

	return http.DefaultClient.Do(req)
}
