// +build !windows

package gost

import (
	"errors"
	"fmt"
	"github.com/golang/glog"
	"net"
	"syscall"
)

const (
	SO_ORIGINAL_DST = 80
)

type RedsocksTCPServer struct {
	Base *ProxyServer
}

func NewRedsocksTCPServer(base *ProxyServer) *RedsocksTCPServer {
	return &RedsocksTCPServer{
		Base: base,
	}
}

func (s *RedsocksTCPServer) ListenAndServe() error {
	laddr, err := net.ResolveTCPAddr("tcp", s.Base.Node.Addr)
	if err != nil {
		return err
	}
	ln, err := net.ListenTCP("tcp", laddr)
	if err != nil {
		return err
	}

	defer ln.Close()
	for {
		conn, err := ln.AcceptTCP()
		if err != nil {
			glog.V(LWARNING).Infoln(err)
			continue
		}
		go s.handleRedirectTCP(conn)
	}
}

func (s *RedsocksTCPServer) handleRedirectTCP(conn *net.TCPConn) {
	srcAddr := conn.RemoteAddr()
	dstAddr, conn, err := getOriginalDstAddr(conn)
	if err != nil {
		glog.V(LWARNING).Infof("[red-tcp] %s -> %s : %s", srcAddr, dstAddr, err)
		return
	}
	defer conn.Close()

	glog.V(LINFO).Infof("[red-tcp] %s -> %s", srcAddr, dstAddr)

	cc, err := s.Base.Chain.Dial(dstAddr.String())
	if err != nil {
		glog.V(LWARNING).Infof("[red-tcp] %s -> %s : %s", srcAddr, dstAddr, err)
		return
	}
	defer cc.Close()

	glog.V(LINFO).Infof("[red-tcp] %s <-> %s", srcAddr, dstAddr)
	s.Base.transport(conn, cc)
	glog.V(LINFO).Infof("[red-tcp] %s >-< %s", srcAddr, dstAddr)
}

func getOriginalDstAddr(conn *net.TCPConn) (addr net.Addr, c *net.TCPConn, err error) {
	defer conn.Close()

	fc, err := conn.File()
	if err != nil {
		return
	}
	defer fc.Close()

	mreq, err := syscall.GetsockoptIPv6Mreq(int(fc.Fd()), syscall.IPPROTO_IP, SO_ORIGINAL_DST)
	if err != nil {
		return
	}

	// only ipv4 support
	ip := net.IPv4(mreq.Multiaddr[4], mreq.Multiaddr[5], mreq.Multiaddr[6], mreq.Multiaddr[7])
	port := uint16(mreq.Multiaddr[2])<<8 + uint16(mreq.Multiaddr[3])
	addr, err = net.ResolveTCPAddr("tcp4", fmt.Sprintf("%s:%d", ip.String(), port))
	if err != nil {
		return
	}

	cc, err := net.FileConn(fc)
	if err != nil {
		return
	}

	c, ok := cc.(*net.TCPConn)
	if !ok {
		err = errors.New("not a TCP connection")
	}
	return
}
