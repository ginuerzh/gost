package main

import (
	//"github.com/ginuerzh/gosocks5"
	"crypto/tls"
	"github.com/golang/glog"
	"github.com/gorilla/websocket"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
)

type wsConn struct {
	conn *websocket.Conn
	rb   []byte
}

func wsClient(scheme string, conn net.Conn, host string) (*wsConn, error) {
	dialer := websocket.Dialer{
		ReadBufferSize:   4096,
		WriteBufferSize:  4096,
		TLSClientConfig:  &tls.Config{InsecureSkipVerify: true},
		HandshakeTimeout: time.Second * 90,
		NetDial: func(net, addr string) (net.Conn, error) {
			return conn, nil
		},
	}
	u := url.URL{Scheme: scheme, Host: host, Path: "/ws"}
	c, resp, err := dialer.Dial(u.String(), nil)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()

	return &wsConn{conn: c}, nil
}

func wsServer(conn *websocket.Conn) *wsConn {
	return &wsConn{
		conn: conn,
	}
}

func (c *wsConn) Read(b []byte) (n int, err error) {
	if len(c.rb) == 0 {
		_, c.rb, err = c.conn.ReadMessage()
	}
	n = copy(b, c.rb)
	c.rb = c.rb[n:]

	//log.Println("ws r:", n)

	return
}

func (c *wsConn) Write(b []byte) (n int, err error) {
	err = c.conn.WriteMessage(websocket.BinaryMessage, b)
	n = len(b)
	//log.Println("ws w:", n)

	return
}

func (c *wsConn) Close() error {
	return c.conn.Close()
}

func (c *wsConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *wsConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (conn *wsConn) SetDeadline(t time.Time) error {
	if err := conn.SetReadDeadline(t); err != nil {
		return err
	}
	return conn.SetWriteDeadline(t)
}
func (c *wsConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *wsConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

type ws struct {
	upgrader websocket.Upgrader
	arg      Args
}

func NewWs(arg Args) *ws {
	return &ws{
		arg: arg,
		upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin:     func(r *http.Request) bool { return true },
		},
	}
}

func (s *ws) handle(w http.ResponseWriter, r *http.Request) {
	glog.V(LINFO).Infof("[ws] %s - %s", r.RemoteAddr, s.arg.Addr)
	if glog.V(LDEBUG) {
		dump, err := httputil.DumpRequest(r, false)
		if err != nil {
			glog.V(LWARNING).Infof("[ws] %s - %s : %s", r.RemoteAddr, s.arg.Addr, err)
		} else {
			glog.V(LDEBUG).Infof("[ws] %s - %s\n%s", r.RemoteAddr, s.arg.Addr, string(dump))
		}
	}
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		glog.V(LERROR).Infoln(err)
		return
	}
	handleConn(wsServer(conn), s.arg)
}

func (s *ws) ListenAndServe() error {
	sm := http.NewServeMux()
	sm.HandleFunc("/ws", s.handle)
	return http.ListenAndServe(s.arg.Addr, sm)
}

func (s *ws) listenAndServeTLS() error {
	sm := http.NewServeMux()
	sm.HandleFunc("/ws", s.handle)
	server := &http.Server{
		Addr:      s.arg.Addr,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{s.arg.Cert}},
		Handler:   sm,
	}
	return server.ListenAndServeTLS("", "")
}
