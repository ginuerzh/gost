package main

import (
	"github.com/ginuerzh/gosocks5"
	"github.com/gorilla/websocket"
	"log"
	"net/http"
	"time"
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
	_, p, err := conn.ReadMessage()
	copy(b, p)
	n = len(p)
	log.Println("ws r:", n)
	return
}

func (conn *WSConn) Write(b []byte) (n int, err error) {
	err = conn.WriteMessage(websocket.BinaryMessage, b)
	n = len(b)
	log.Println("ws w:", n)
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
	CheckOrigin:     func(r *http.Request) bool { return true },
}

func (s *WSServer) handle(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println(err)
		return
	}
	defer conn.Close()

	c := gosocks5.ServerConn(NewWSConn(conn), serverConfig)
	/*
		if err := c.Handleshake(); err != nil {
			log.Println(err)
			return
		}
	*/
	socks5Handle(c)
}

func (s *WSServer) ListenAndServe() error {
	http.HandleFunc("/", s.handle)
	return http.ListenAndServe(s.Addr, nil)
}
