package main

import (
	"github.com/ginuerzh/gosocks5"
	"github.com/golang/glog"
	"net"
)

type UDPConn struct {
	isClient bool
	udpConn  *net.UDPConn
	udpAddr  *net.UDPAddr
	tcpConn  net.Conn
}

func Client(conn net.Conn, addr net.Addr) *UDPConn {
	client := &UDPConn{isClient: true}

	switch conn := conn.(type) {
	case net.UDPConn:
		client.udpConn = conn
		client.udpAddr = addr
	default:
		client.tcpConn = conn
	}

	return client
}

func Server(conn net.Conn) *UDPConn {
	server := &UDPConn{}
	switch conn := conn.(type) {
	case net.UDPConn:
		server.udpConn = conn
	default:
		server.tcpConn = conn
	}
	return server
}
