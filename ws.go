package main

import (
    "github.com/gorilla/websocket"
    "net/http"
    "log"
    "time"
    "github.com/ginuerzh/gosocks5"
)

type WSConn struct {
    *websocket.Conn
}

func NewWSConn(conn *websocket.Conn) *WSConn {
    c := &WSConn{}
    c.Conn = conn
    
    return c
}

func (conn *WSConn) Read(b []byte) (n int, err error) {
    _, b, err = conn.ReadMessage()
    n = len(b)
    
    return
}

func (conn *WSConn) Write(b []byte) (n int, err error) {
    n = len(b)
    err = conn.WriteMessage(websocket.BinaryMessage, b)
    return
}

func (conn *WSConn) SetDeadline(t time.Time) error {
    if err := conn.SetReadDeadline(t); err != nil {
        return err
    }
    return conn.SetWriteDeadline(t)
}

type WSServer struct {
    Addr string
}

var upgrader = websocket.Upgrader{
    ReadBufferSize:  8192,
    WriteBufferSize: 8192,
    CheckOrigin: func(r *http.Request) bool{ return true;},
}


func (s *WSServer) handle(w http.ResponseWriter, r *http.Request) {
    conn, err := upgrader.Upgrade(w, r, nil)
    if err != nil {
        log.Println(err)
        return
    }
    defer conn.Close()
    
    c := NewWSConn(conn)
    
    socks5Handle(gosocks5.ServerConn(c, serverConfig))
}

func (s *WSServer) ListenAndServe() error {
    http.HandleFunc("/", s.handle)
    return http.ListenAndServe(s.Addr, nil)
}