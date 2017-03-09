package gost

import (
	"crypto/tls"
	"github.com/golang/glog"
	"gopkg.in/gorilla/websocket.v1"
	"net"
	"net/http"
	"net/http/httputil"
	"time"
)

type WebsocketServer struct {
	Addr     string
	Base     *ProxyServer
	Handler  http.Handler
	upgrader websocket.Upgrader
}

func NewWebsocketServer(base *ProxyServer) *WebsocketServer {
	return &WebsocketServer{
		Addr: base.Node.Addr,
		Base: base,
		upgrader: websocket.Upgrader{
			ReadBufferSize:    1024,
			WriteBufferSize:   1024,
			CheckOrigin:       func(r *http.Request) bool { return true },
			EnableCompression: true,
		},
	}
}

// Default websocket server handler
func (s *WebsocketServer) HandleRequest(w http.ResponseWriter, r *http.Request) {
	glog.V(LINFO).Infof("[ws] %s - %s", r.RemoteAddr, s.Addr)
	if glog.V(LDEBUG) {
		dump, _ := httputil.DumpRequest(r, false)
		glog.V(LDEBUG).Infof("[ws] %s - %s\n%s", r.RemoteAddr, s.Addr, string(dump))
	}
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		glog.V(LERROR).Infof("[ws] %s - %s : %s", r.RemoteAddr, s.Addr, err)
		return
	}
	s.Base.handleConn(WebsocketServerConn(conn))
}

func (s *WebsocketServer) ListenAndServe() error {
	mux := http.NewServeMux()
	if s.Handler == nil {
		s.Handler = http.HandlerFunc(s.HandleRequest)
	}
	mux.Handle("/ws", s.Handler)
	return http.ListenAndServe(s.Addr, mux)
}

func (s *WebsocketServer) ListenAndServeTLS(config *tls.Config) error {
	mux := http.NewServeMux()
	if s.Handler == nil {
		s.Handler = http.HandlerFunc(s.HandleRequest)
	}
	mux.Handle("/ws", s.Handler)
	server := &http.Server{
		Addr:      s.Addr,
		Handler:   mux,
		TLSConfig: config,
	}
	return server.ListenAndServeTLS("", "")
}

type WebsocketConn struct {
	conn *websocket.Conn
	rb   []byte
}

func WebsocketClientConn(url string, conn net.Conn, config *tls.Config) (*WebsocketConn, error) {
	dialer := websocket.Dialer{
		ReadBufferSize:    1024,
		WriteBufferSize:   1024,
		TLSClientConfig:   config,
		HandshakeTimeout:  DialTimeout,
		EnableCompression: true,
		NetDial: func(net, addr string) (net.Conn, error) {
			return conn, nil
		},
	}

	c, resp, err := dialer.Dial(url, nil)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()
	return &WebsocketConn{conn: c}, nil
}

func WebsocketServerConn(conn *websocket.Conn) *WebsocketConn {
	conn.EnableWriteCompression(true)
	return &WebsocketConn{
		conn: conn,
	}
}

func (c *WebsocketConn) Read(b []byte) (n int, err error) {
	if len(c.rb) == 0 {
		_, c.rb, err = c.conn.ReadMessage()
	}
	n = copy(b, c.rb)
	c.rb = c.rb[n:]
	return
}

func (c *WebsocketConn) Write(b []byte) (n int, err error) {
	err = c.conn.WriteMessage(websocket.BinaryMessage, b)
	n = len(b)
	return
}

func (c *WebsocketConn) Close() error {
	return c.conn.Close()
}

func (c *WebsocketConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *WebsocketConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (conn *WebsocketConn) SetDeadline(t time.Time) error {
	if err := conn.SetReadDeadline(t); err != nil {
		return err
	}
	return conn.SetWriteDeadline(t)
}
func (c *WebsocketConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *WebsocketConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}
