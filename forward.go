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

	if !strings.Contains(arg.Forward, ":") {
		arg.Forward += ":22" // default is ssh service
	}
	glog.V(LINFO).Infof("[tcp-forward] %s - %s", conn.RemoteAddr(), arg.Forward)
	c, err := Connect(arg.Forward)
	if err != nil {
		glog.V(LWARNING).Infof("[tcp-forward] %s -> %s : %s", conn.RemoteAddr(), arg.Forward, err)
		return
	}
	defer c.Close()

	glog.V(LINFO).Infof("[tcp-forward] %s <-> %s", conn.RemoteAddr(), arg.Forward)
	Transport(conn, c)
	glog.V(LINFO).Infof("[tcp-forward] %s >-< %s", conn.RemoteAddr(), arg.Forward)
}

func handleUdpForward(conn *net.UDPConn, raddr *net.UDPAddr, data []byte, arg Args) {
	if !strings.Contains(arg.Forward, ":") {
		arg.Forward += ":53" // default is dns service
	}

	faddr, err := net.ResolveUDPAddr("udp", arg.Forward)
	if err != nil {
		glog.V(LWARNING).Infof("[udp-forward] %s -> %s : %s", raddr, arg.Forward, err)
		return
	}

	glog.V(LINFO).Infof("[udp-forward] %s - %s", raddr, faddr)

	if len(forwardArgs) == 0 {
		lconn, err := net.ListenUDP("udp", nil)
		if err != nil {
			glog.V(LWARNING).Infof("[udp-forward] %s -> %s : %s", raddr, arg.Forward, err)
			return
		}
		defer lconn.Close()

		if _, err := lconn.WriteToUDP(data, faddr); err != nil {
			glog.V(LWARNING).Infof("[udp-forward] %s -> %s : %s", raddr, arg.Forward, err)
			return
		}
		glog.V(LDEBUG).Infof("[udp-forward] %s >>> %s length %d", raddr, arg.Forward, len(data))

		b := udpPool.Get().([]byte)
		defer udpPool.Put(b)
		lconn.SetReadDeadline(time.Now().Add(time.Second * 60))
		n, addr, err := lconn.ReadFromUDP(b)
		if err != nil {
			glog.V(LWARNING).Infof("[udp-forward] %s <- %s : %s", raddr, arg.Forward, err)
			return
		}
		glog.V(LDEBUG).Infof("[udp-forward] %s <<< %s length %d", raddr, addr, n)

		if _, err := conn.WriteToUDP(b[:n], raddr); err != nil {
			glog.V(LWARNING).Infof("[udp-forward] %s <- %s : %s", raddr, arg.Forward, err)
		}
		glog.V(LINFO).Infof("[udp-forward] %s >-< %s", raddr, arg.Forward)
		return
	}

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
	glog.V(LINFO).Infof("[udp-forward] %s <-> %s ASSOCIATE ON %s", raddr, arg.Forward, rep.Addr)

	dgram := gosocks5.NewUDPDatagram(
		gosocks5.NewUDPHeader(uint16(len(data)), 0, ToSocksAddr(faddr)), data)

	fconn.SetWriteDeadline(time.Now().Add(time.Second * 90))
	if err = dgram.Write(fconn); err != nil {
		glog.V(LWARNING).Infof("[udp-forward] %s -> %s : %s", raddr, arg.Forward, err)
		return
	}
	glog.V(LDEBUG).Infof("[udp-forward] %s >>> %s length %d", raddr, arg.Forward, len(data))

	fconn.SetReadDeadline(time.Now().Add(time.Second * 90))
	dgram, err = gosocks5.ReadUDPDatagram(fconn)
	if err != nil {
		glog.V(LWARNING).Infof("[udp-forward] %s <- %s : %s", raddr, arg.Forward, err)
		return
	}
	glog.V(LDEBUG).Infof("[udp-forward] %s <<< %s length %d", raddr, dgram.Header.Addr, len(dgram.Data))

	if _, err = conn.WriteToUDP(dgram.Data, raddr); err != nil {
		glog.V(LWARNING).Infof("[udp-forward] %s <- %s : %s", raddr, arg.Forward, err)
	}

	glog.V(LINFO).Infof("[udp-forward] %s >-< %s", raddr, arg.Forward)
}

func handleRTcpForwardConn(conn net.Conn, arg Args) {
	defer conn.Close()

	req, err := gosocks5.ReadRequest(conn)
	if err != nil {
		glog.V(LWARNING).Infof("[rtcp] %s -> %s : %s", conn.RemoteAddr(), arg.Addr, err)
		return
	}
	bindAddr, _ := net.ResolveTCPAddr("tcp", req.Addr.String())
	ln, err := net.ListenTCP("tcp", bindAddr)
	if err != nil {
		glog.V(LWARNING).Infof("[rtcp] %s -> %s : %s", conn.RemoteAddr(), req.Addr, err)
		rep := gosocks5.NewReply(gosocks5.Failure, nil)
		if err := rep.Write(conn); err != nil {
			glog.V(LWARNING).Infof("[rtcp] %s <- %s : %s", conn.RemoteAddr(), req.Addr, err)
		}
		return
	}

	addr := ToSocksAddr(ln.Addr())
	addr.Host, _, _ = net.SplitHostPort(conn.LocalAddr().String())

	rep := gosocks5.NewReply(gosocks5.Succeeded, addr)
	if err := rep.Write(conn); err != nil {
		glog.V(LWARNING).Infof("[rtcp] %s <- %s : %s", conn.RemoteAddr(), req.Addr, err)
		ln.Close()
		return
	}
	glog.V(LINFO).Infof("[rtcp] %s - %s BIND ON %s OK", conn.RemoteAddr(), req.Addr, addr)

	lnChan := make(chan net.Conn, 1)
	go func() {
		defer close(lnChan)
		c, err := ln.AcceptTCP()
		if err != nil {
			// glog.V(LWARNING).Infof("[rtcp] %s <- %s ACCEPT : %s", conn.RemoteAddr(), addr, err)
			return
		}
		lnChan <- c
	}()

	peerChan := make(chan *gosocks5.Reply, 1)
	go func() {
		defer close(peerChan)
		reply, err := gosocks5.ReadReply(conn)
		if err != nil {
			return
		}
		peerChan <- reply
	}()

	var pconn net.Conn

	for {
		select {
		case c := <-lnChan:
			ln.Close() // only accept one peer
			if c == nil {
				if err := gosocks5.NewReply(gosocks5.Failure, nil).Write(conn); err != nil {
					glog.V(LWARNING).Infoln("[rtcp] %s <- %s : %s", conn.RemoteAddr(), addr, err)
				}
				glog.V(LWARNING).Infof("[rtcp] %s >-< %s : %s", conn.RemoteAddr(), addr)
				return
			}
			glog.V(LINFO).Infof("[rtcp] %s <- %s PEER %s ACCEPTED", conn.RemoteAddr(), addr, c.RemoteAddr())
			gosocks5.NewReply(gosocks5.Succeeded, ToSocksAddr(c.RemoteAddr())).Write(conn)
			pconn = c
			lnChan = nil
			ln = nil
		case reply := <-peerChan:
			if reply == nil {
				if ln != nil {
					ln.Close()
				}
				if pconn != nil {
					pconn.Close()
				}
				glog.V(LWARNING).Infof("[rtcp] %s >-< %s", conn.RemoteAddr(), addr)
				return
			}
			goto out
		}
	}

out:
	defer pconn.Close()

	glog.V(LINFO).Infof("[rtcp] %s <-> %s", conn.RemoteAddr(), pconn.RemoteAddr())
	Transport(conn, pconn)
	glog.V(LINFO).Infof("[rtcp] %s >-< %s", conn.RemoteAddr(), pconn.RemoteAddr())
}

func connectRTcpForward(conn net.Conn, arg Args) error {
	glog.V(LINFO).Infof("[rtcp] %s - %s", arg.Addr, arg.Forward)

	addr, _ := net.ResolveTCPAddr("tcp", arg.Bind)
	req := gosocks5.NewRequest(gosocks5.CmdBind, ToSocksAddr(addr))
	if err := req.Write(conn); err != nil {
		glog.V(LWARNING).Infof("[rtcp] %s -> %s : %s", arg.Addr, arg.Forward, err)
		return err
	}

	// first reply, bind status
	rep, err := gosocks5.ReadReply(conn)
	if err != nil {
		glog.V(LWARNING).Infof("[rtcp] %s <- %s : %s", arg.Addr, arg.Forward, err)
		return err
	}
	if rep.Rep != gosocks5.Succeeded {
		glog.V(LWARNING).Infof("[rtcp] %s <- %s : bind on %s failure", arg.Addr, arg.Forward, arg.Bind)
		return errors.New("Bind on " + arg.Bind + " failure")
	}
	glog.V(LINFO).Infof("[rtcp] %s - %s BIND ON %s OK", arg.Addr, arg.Forward, arg.Bind)

	// second reply, peer connection
	rep, err = gosocks5.ReadReply(conn)
	if err != nil {
		glog.V(LWARNING).Infof("[rtcp] %s <- %s : %s", arg.Addr, arg.Forward, err)
		return err
	}
	if rep.Rep != gosocks5.Succeeded {
		glog.V(LWARNING).Infof("[rtcp] %s <- %s : peer connect failure", arg.Addr, arg.Forward)
		return errors.New("peer connect failure")
	}

	glog.V(LINFO).Infof("[rtcp] %s <- %s PEER %s CONNECTED", conn.RemoteAddr(), req.Addr, rep.Addr)

	go func() {
		defer conn.Close()

		lconn, err := net.Dial("tcp", arg.Addr)
		if err != nil {
			glog.V(LWARNING).Infof("[rtcp] %s <- %s : %s", arg.Addr, arg.Forward, err)
			return
		}
		defer lconn.Close()

		if err := gosocks5.NewReply(gosocks5.Succeeded, nil).Write(conn); err != nil {
			glog.V(LWARNING).Infof("[rtcp] %s -> %s : %s", arg.Addr, arg.Forward, err)
			return
		}

		glog.V(LINFO).Infof("[rtcp] %s <-> %s", arg.Addr, arg.Forward)
		Transport(lconn, conn)
		glog.V(LINFO).Infof("[rtcp] %s >-< %s", arg.Addr, arg.Forward)
	}()

	return nil
}
