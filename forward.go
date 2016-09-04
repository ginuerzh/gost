package main

import (
	"errors"
	"github.com/ginuerzh/gosocks5"
	"github.com/golang/glog"
	"net"
	"strings"
	"time"
)

func handleTcpForward(conn net.Conn, arg Args) {
	defer conn.Close()

	if !strings.Contains(arg.Remote, ":") {
		arg.Remote += ":22" // default is ssh service
	}
	glog.V(LINFO).Infof("[tcp-forward] %s - %s", conn.RemoteAddr(), arg.Remote)
	c, err := Connect(arg.Remote)
	if err != nil {
		glog.V(LWARNING).Infof("[tcp-forward] %s -> %s : %s", conn.RemoteAddr(), arg.Remote, err)
		return
	}
	defer c.Close()

	glog.V(LINFO).Infof("[tcp-forward] %s <-> %s", conn.RemoteAddr(), arg.Remote)
	Transport(conn, c)
	glog.V(LINFO).Infof("[tcp-forward] %s >-< %s", conn.RemoteAddr(), arg.Remote)
}

func handleUdpForward(conn *net.UDPConn, raddr *net.UDPAddr, data []byte, arg Args) {
	if !strings.Contains(arg.Remote, ":") {
		arg.Remote += ":53" // default is dns service
	}

	faddr, err := net.ResolveUDPAddr("udp", arg.Remote)
	if err != nil {
		glog.V(LWARNING).Infof("[udp-forward] %s -> %s : %s", raddr, arg.Remote, err)
		return
	}

	glog.V(LINFO).Infof("[udp-forward] %s - %s", raddr, faddr)

	if len(forwardArgs) == 0 {
		lconn, err := net.ListenUDP("udp", nil)
		if err != nil {
			glog.V(LWARNING).Infof("[udp-forward] %s -> %s : %s", raddr, arg.Remote, err)
			return
		}
		defer lconn.Close()

		if _, err := lconn.WriteToUDP(data, faddr); err != nil {
			glog.V(LWARNING).Infof("[udp-forward] %s -> %s : %s", raddr, arg.Remote, err)
			return
		}
		glog.V(LDEBUG).Infof("[udp-forward] %s >>> %s length %d", raddr, arg.Remote, len(data))

		b := udpPool.Get().([]byte)
		defer udpPool.Put(b)
		lconn.SetReadDeadline(time.Now().Add(time.Second * 60))
		n, addr, err := lconn.ReadFromUDP(b)
		if err != nil {
			glog.V(LWARNING).Infof("[udp-forward] %s <- %s : %s", raddr, arg.Remote, err)
			return
		}
		glog.V(LDEBUG).Infof("[udp-forward] %s <<< %s length %d", raddr, addr, n)

		if _, err := conn.WriteToUDP(b[:n], raddr); err != nil {
			glog.V(LWARNING).Infof("[udp-forward] %s <- %s : %s", raddr, arg.Remote, err)
		}
		glog.V(LINFO).Infof("[udp-forward] %s >-< %s", raddr, arg.Remote)
		return
	}

	fconn, _, err := forwardChain(forwardArgs...)
	if err != nil {
		glog.V(LWARNING).Infof("[udp-forward] %s -> %s : %s", raddr, arg.Remote, err)
		return
	}
	defer fconn.Close()

	glog.V(LINFO).Infof("[udp-forward] %s -> %s ASSOCIATE", raddr, arg.Remote)

	req := gosocks5.NewRequest(CmdUdpTun, nil)
	if err = req.Write(fconn); err != nil {
		glog.V(LWARNING).Infof("[udp-forward] %s -> %s ASSOCIATE : %s", raddr, arg.Remote, err)
		return
	}
	glog.V(LDEBUG).Infof("[udp-forward] %s -> %s\n%s", raddr, arg.Remote, req)

	rep, err := gosocks5.ReadReply(fconn)
	if err != nil {
		glog.V(LWARNING).Infof("[udp-forward] %s <- %s ASSOCIATE : %s", raddr, arg.Remote, err)
		return
	}
	glog.V(LDEBUG).Infof("[udp-forward] %s <- %s\n%s", raddr, arg.Remote, rep)
	if rep.Rep != gosocks5.Succeeded {
		glog.V(LWARNING).Infof("[udp-forward] %s <- %s ASSOCIATE failured", raddr, arg.Remote)
		return
	}
	glog.V(LINFO).Infof("[udp-forward] %s <-> %s ASSOCIATE ON %s", raddr, arg.Remote, rep.Addr)

	dgram := gosocks5.NewUDPDatagram(
		gosocks5.NewUDPHeader(uint16(len(data)), 0, ToSocksAddr(faddr)), data)

	fconn.SetWriteDeadline(time.Now().Add(time.Second * 90))
	if err = dgram.Write(fconn); err != nil {
		glog.V(LWARNING).Infof("[udp-forward] %s -> %s : %s", raddr, arg.Remote, err)
		return
	}
	glog.V(LDEBUG).Infof("[udp-forward] %s >>> %s length %d", raddr, arg.Remote, len(data))

	fconn.SetReadDeadline(time.Now().Add(time.Second * 90))
	dgram, err = gosocks5.ReadUDPDatagram(fconn)
	if err != nil {
		glog.V(LWARNING).Infof("[udp-forward] %s <- %s : %s", raddr, arg.Remote, err)
		return
	}
	glog.V(LDEBUG).Infof("[udp-forward] %s <<< %s length %d", raddr, dgram.Header.Addr, len(dgram.Data))

	if _, err = conn.WriteToUDP(dgram.Data, raddr); err != nil {
		glog.V(LWARNING).Infof("[udp-forward] %s <- %s : %s", raddr, arg.Remote, err)
	}

	glog.V(LINFO).Infof("[udp-forward] %s >-< %s", raddr, arg.Remote)
}

func connectRTcpForward(conn net.Conn, arg Args) error {
	glog.V(LINFO).Infof("[rtcp] %s - %s", arg.Addr, arg.Remote)

	addr, _ := net.ResolveTCPAddr("tcp", arg.Addr)
	req := gosocks5.NewRequest(gosocks5.CmdBind, ToSocksAddr(addr))
	bindAddr := req.Addr
	if err := req.Write(conn); err != nil {
		glog.V(LWARNING).Infof("[rtcp] %s <- %s : %s", bindAddr, arg.Remote, err)
		return err
	}

	// first reply, bind status
	rep, err := gosocks5.ReadReply(conn)
	if err != nil {
		glog.V(LWARNING).Infof("[rtcp] %s -> %s : %s", bindAddr, arg.Remote, err)
		return err
	}
	if rep.Rep != gosocks5.Succeeded {
		glog.V(LWARNING).Infof("[rtcp] %s -> %s : bind on %s failure", bindAddr, arg.Remote, arg.Addr)
		return errors.New("Bind on " + arg.Addr + " failure")
	}
	glog.V(LINFO).Infof("[rtcp] %s - %s BIND ON %s OK", bindAddr, arg.Remote, rep.Addr)

	// second reply, peer connection
	rep, err = gosocks5.ReadReply(conn)
	if err != nil {
		glog.V(LWARNING).Infof("[rtcp] %s -> %s : %s", bindAddr, arg.Remote, err)
		return err
	}
	if rep.Rep != gosocks5.Succeeded {
		glog.V(LWARNING).Infof("[rtcp] %s -> %s : peer connect failure", bindAddr, arg.Remote)
		return errors.New("peer connect failure")
	}

	glog.V(LINFO).Infof("[rtcp] %s -> %s PEER %s CONNECTED", bindAddr, arg.Remote, rep.Addr)

	go func() {
		defer conn.Close()

		lconn, err := net.Dial("tcp", arg.Remote)
		if err != nil {
			glog.V(LWARNING).Infof("[rtcp] %s -> %s : %s", rep.Addr, lconn.RemoteAddr(), err)
			return
		}
		defer lconn.Close()

		glog.V(LINFO).Infof("[rtcp] %s <-> %s", rep.Addr, lconn.RemoteAddr())
		Transport(lconn, conn)
		glog.V(LINFO).Infof("[rtcp] %s >-< %s", rep.Addr, lconn.RemoteAddr())
	}()

	return nil
}
