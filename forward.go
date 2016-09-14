package main

import (
	"errors"
	"fmt"
	"github.com/ginuerzh/gosocks5"
	"github.com/golang/glog"
	"net"
	"time"
)

func handleTcpForward(conn net.Conn, raddr net.Addr) {
	defer conn.Close()

	glog.V(LINFO).Infof("[tcp-forward] %s - %s", conn.RemoteAddr(), raddr)
	c, err := Connect(raddr.String())
	if err != nil {
		glog.V(LWARNING).Infof("[tcp-forward] %s -> %s : %s", conn.RemoteAddr(), raddr, err)
		return
	}
	defer c.Close()

	glog.V(LINFO).Infof("[tcp-forward] %s <-> %s", conn.RemoteAddr(), raddr)
	Transport(conn, c)
	glog.V(LINFO).Infof("[tcp-forward] %s >-< %s", conn.RemoteAddr(), raddr)
}

func handleUdpForwardLocal(conn *net.UDPConn, laddr, raddr *net.UDPAddr, data []byte) {
	lconn, err := net.ListenUDP("udp", nil)
	if err != nil {
		glog.V(LWARNING).Infof("[udp-forward] %s -> %s : %s", laddr, raddr, err)
		return
	}
	defer lconn.Close()

	if _, err := lconn.WriteToUDP(data, raddr); err != nil {
		glog.V(LWARNING).Infof("[udp-forward] %s -> %s : %s", laddr, raddr, err)
		return
	}
	glog.V(LDEBUG).Infof("[udp-forward] %s >>> %s length %d", laddr, raddr, len(data))

	b := udpPool.Get().([]byte)
	defer udpPool.Put(b)
	lconn.SetReadDeadline(time.Now().Add(time.Second * 60))
	n, addr, err := lconn.ReadFromUDP(b)
	if err != nil {
		glog.V(LWARNING).Infof("[udp-forward] %s <- %s : %s", laddr, raddr, err)
		return
	}
	glog.V(LDEBUG).Infof("[udp-forward] %s <<< %s length %d", laddr, addr, n)

	if _, err := conn.WriteToUDP(b[:n], laddr); err != nil {
		glog.V(LWARNING).Infof("[udp-forward] %s <- %s : %s", laddr, raddr, err)
	}
	return
}

func prepareUdpConnectTunnel(addr net.Addr) (net.Conn, error) {
	conn, _, err := forwardChain(forwardArgs...)
	if err != nil {
		return nil, err
	}

	conn.SetWriteDeadline(time.Now().Add(time.Second * 90))
	if err = gosocks5.NewRequest(CmdUdpConnect, ToSocksAddr(addr)).Write(conn); err != nil {
		conn.Close()
		return nil, err
	}
	conn.SetWriteDeadline(time.Time{})

	conn.SetReadDeadline(time.Now().Add(90 * time.Second))
	reply, err := gosocks5.ReadReply(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	conn.SetReadDeadline(time.Time{})

	if reply.Rep != gosocks5.Succeeded {
		conn.Close()
		return nil, errors.New("failure")
	}

	return conn, nil
}

func handleUdpForwardTunnel(laddr, raddr *net.UDPAddr, rChan, wChan chan *gosocks5.UDPDatagram) {
	var tun net.Conn
	var err error
	retry := 0
	for {
		tun, err = prepareUdpConnectTunnel(raddr)
		if err != nil {
			glog.V(LWARNING).Infof("[udp-connect] %s -> %s : %s", laddr, raddr, err)
			time.Sleep((1 << uint(retry)) * time.Second)
			if retry < 5 {
				retry++
			}
			continue
		}
		break
	}

	glog.V(LINFO).Infof("[udp-connect] %s <-> %s", laddr, raddr)

	rExit := make(chan interface{})
	rErr, wErr := make(chan error, 1), make(chan error, 1)

	go func() {
		for {
			select {
			case dgram := <-rChan:
				if err := dgram.Write(tun); err != nil {
					glog.V(LWARNING).Infof("[udp-connect] %s -> %s : %s", laddr, raddr, err)
					rErr <- err
					return
				}
				glog.V(LDEBUG).Infof("[udp-tun] %s >>> %s length: %d", laddr, raddr, len(dgram.Data))
			case <-rExit:
				// glog.V(LDEBUG).Infof("[udp-connect] %s -> %s : exited", laddr, raddr)
				return
			}
		}
	}()
	go func() {
		for {
			dgram, err := gosocks5.ReadUDPDatagram(tun)
			if err != nil {
				glog.V(LWARNING).Infof("[udp-connect] %s <- %s : %s", laddr, raddr, err)
				close(rExit)
				wErr <- err
				return
			}

			select {
			case wChan <- dgram:
				glog.V(LDEBUG).Infof("[udp-tun] %s <<< %s length: %d", laddr, raddr, len(dgram.Data))
			default:
			}
		}
	}()

	select {
	case <-rErr:
		//log.Println("w exit", err)
	case <-wErr:
		//log.Println("r exit", err)
	}
	glog.V(LINFO).Infof("[udp-connect] %s >-< %s", laddr, raddr)
}

func connectRTcpForward(conn net.Conn, arg Args) error {
	glog.V(LINFO).Infof("[rtcp] %s - %s", arg.Addr, arg.Remote)

	addr, _ := net.ResolveTCPAddr("tcp", arg.Addr)
	req := gosocks5.NewRequest(gosocks5.CmdBind, ToSocksAddr(addr))
	bindAddr := req.Addr
	if err := req.Write(conn); err != nil {
		glog.V(LWARNING).Infof("[rtcp] %s -> %s : %s", bindAddr, arg.Remote, err)
		return err
	}

	// first reply, bind status
	conn.SetReadDeadline(time.Now().Add(90 * time.Second))
	rep, err := gosocks5.ReadReply(conn)
	if err != nil {
		glog.V(LWARNING).Infof("[rtcp] %s -> %s : %s", bindAddr, arg.Remote, err)
		return err
	}
	conn.SetReadDeadline(time.Time{})
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

func connectRUdpForward(conn net.Conn, arg Args) error {
	glog.V(LINFO).Infof("[rudp] %s - %s", arg.Addr, arg.Remote)

	addr, _ := net.ResolveUDPAddr("udp", arg.Addr)
	req := gosocks5.NewRequest(CmdUdpTun, ToSocksAddr(addr))
	bindAddr := req.Addr
	conn.SetWriteDeadline(time.Now().Add(time.Second * 90))
	if err := req.Write(conn); err != nil {
		glog.V(LWARNING).Infof("[rudp] %s -> %s : %s", bindAddr, arg.Remote, err)
		return err
	}
	conn.SetWriteDeadline(time.Time{})

	conn.SetReadDeadline(time.Now().Add(90 * time.Second))
	rep, err := gosocks5.ReadReply(conn)
	if err != nil {
		glog.V(LWARNING).Infof("[rudp] %s <- %s : %s", bindAddr, arg.Remote, err)
		return err
	}
	conn.SetReadDeadline(time.Time{})

	if rep.Rep != gosocks5.Succeeded {
		glog.V(LWARNING).Infof("[rudp] %s <- %s : bind on %s failure", bindAddr, arg.Remote, arg.Addr)
		return errors.New(fmt.Sprintf("Bind on %s failure", bindAddr))
	}

	glog.V(LINFO).Infof("[rudp] %s - %s BIND ON %s OK", bindAddr, arg.Remote, rep.Addr)

	raddr, err := net.ResolveUDPAddr("udp", arg.Remote)
	if err != nil {
		glog.V(LWARNING).Infof("[rudp] %s <- %s : %s", bindAddr, arg.Remote, err)
		return err
	}

	for {
		dgram, err := gosocks5.ReadUDPDatagram(conn)
		if err != nil {
			glog.V(LWARNING).Infof("[rudp] %s <- %s : %s", bindAddr, arg.Remote, err)
			return err
		}

		go func() {
			b := udpPool.Get().([]byte)
			defer udpPool.Put(b)

			relay, err := net.DialUDP("udp", nil, raddr)
			if err != nil {
				glog.V(LWARNING).Infof("[rudp] %s -> %s : %s", bindAddr, arg.Remote, err)
				return
			}
			defer relay.Close()

			if _, err := relay.Write(dgram.Data); err != nil {
				glog.V(LWARNING).Infof("[rudp] %s -> %s : %s", bindAddr, arg.Remote, err)
				return
			}
			glog.V(LDEBUG).Infof("[rudp] %s <<< %s length: %d", arg.Remote, bindAddr, len(dgram.Data))

			relay.SetReadDeadline(time.Now().Add(time.Second * 60))
			n, err := relay.Read(b)
			if err != nil {
				glog.V(LWARNING).Infof("[rudp] %s <- %s : %s", bindAddr, arg.Remote, err)
				return
			}
			relay.SetReadDeadline(time.Time{})

			glog.V(LDEBUG).Infof("[rudp] %s >>> %s length: %d", arg.Remote, bindAddr, n)

			conn.SetWriteDeadline(time.Now().Add(time.Second * 90))
			if err := gosocks5.NewUDPDatagram(gosocks5.NewUDPHeader(uint16(n), 0, dgram.Header.Addr), b[:n]).Write(conn); err != nil {
				glog.V(LWARNING).Infof("[rudp] %s <- %s : %s", bindAddr, arg.Remote, err)
				return
			}
			conn.SetWriteDeadline(time.Time{})
		}()
	}

}
