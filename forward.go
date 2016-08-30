package main

import (
	"github.com/ginuerzh/gosocks5"
	"github.com/golang/glog"
	"net"
	"strings"
)

func handleTcpForward(conn net.Conn, arg Args) {
	defer conn.Close()
	glog.V(LINFO).Infof("[tcp-forward] %s -> %s", conn.RemoteAddr(), arg.Forward)
	c, err := Connect(arg.Forward)
	if err != nil {
		glog.V(LWARNING).Infof("[tcp-forward] %s -> %s : %s", conn.RemoteAddr(), arg.Forward, err)
		return
	}
	defer c.Close()

	glog.V(LINFO).Infof("[tcp-forward] %s <-> %s OK", conn.RemoteAddr(), arg.Forward)
	Transport(conn, c)
	glog.V(LINFO).Infof("[tcp-forward] %s >-< %s DISCONNECTED", conn.RemoteAddr(), arg.Forward)
}

func handleUdpForward(conn *net.UDPConn, raddr *net.UDPAddr, data []byte, arg Args) {
	if !strings.Contains(arg.Forward, ":") {
		arg.Forward += ":53"
	}
	glog.V(LINFO).Infof("[udp-forward] %s -> %s", raddr, arg.Forward)
	fconn, _, err := forwardChain(forwardArgs...)
	if err != nil {
		glog.V(LWARNING).Infof("[udp-forward] %s -> %s : %s", raddr, arg.Forward, err)
		if fconn != nil {
			fconn.Close()
		}
		return
	}
	defer fconn.Close()

	glog.V(LINFO).Infof("[udp-forward] %s -> %s ASSOCIATE", raddr, arg.Forward)

	req := gosocks5.NewRequest(CmdUdpTun, nil)
	if err = req.Write(fconn); err != nil {
		glog.V(LWARNING).Infof("[udp-forward] %s -> %s ASSOCIATE : %s", raddr, arg.Forward, err)
		return
	}
	glog.V(LDEBUG).Infof("[udp-forward] %s -> %s\n%s", raddr, arg.Forward, req)

	rep, err := gosocks5.ReadReply(fconn)
	if err != nil {
		glog.V(LWARNING).Infof("[udp-forward] %s <- %s ASSOCIATE : %s", raddr, arg.Forward, err)
		return
	}
	glog.V(LDEBUG).Infof("[udp-forward] %s <- %s\n%s", raddr, arg.Forward, rep)
	if rep.Rep != gosocks5.Succeeded {
		glog.V(LWARNING).Infof("[udp-forward] %s <- %s ASSOCIATE failured", raddr, arg.Forward)
		return
	}
	glog.V(LINFO).Infof("[udp-forward] %s <-> %s ASSOCIATE ON %s OK", raddr, arg.Forward, rep.Addr)

	addr, err := net.ResolveUDPAddr("udp", arg.Forward)
	if err != nil {
		glog.V(LWARNING).Infof("[udp-forward] %s -> %s : %s", raddr, arg.Forward, err)
		return
	}
	dgram := gosocks5.NewUDPDatagram(
		gosocks5.NewUDPHeader(uint16(len(data)), 0, ToSocksAddr(addr)), data)
	if err = dgram.Write(fconn); err != nil {
		glog.V(LWARNING).Infof("[udp-forward] %s -> %s : %s", raddr, arg.Forward, err)
		return
	}
	glog.V(LINFO).Infof("[udp-forward] %s >>> %s length %d", raddr, arg.Forward, len(data))

	dgram, err = gosocks5.ReadUDPDatagram(fconn)
	if err != nil {
		glog.V(LWARNING).Infof("[udp-forward] %s <- %s : %s", raddr, arg.Forward, err)
		return
	}
	glog.V(LINFO).Infof("[udp-forward] %s <<< %s length %d", raddr, arg.Forward, len(dgram.Data))

	if _, err = conn.WriteToUDP(dgram.Data, raddr); err != nil {
		glog.V(LWARNING).Infof("[udp-forward] %s <- %s : %s", raddr, arg.Forward, err)
	}
}
