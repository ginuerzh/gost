package main

import (
	"github.com/golang/glog"
	"net"
)

func handleTcpForward(conn net.Conn, arg Args) {
	glog.V(LINFO).Infoln("[tcp-forward] CONNECT", arg.Forward)
	c, err := Connect(arg.Forward)
	if err != nil {
		glog.V(LWARNING).Infoln("[tcp-forward] CONNECT", arg.Forward, err)
		return
	}
	defer c.Close()

	glog.V(LINFO).Infoln("[tcp-forward] CONNECT", arg.Forward, "OK")
	Transport(conn, c)
}

func handleUdpForward(conn *net.UDPConn, arg Args) {

}
