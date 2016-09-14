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

	glog.V(LINFO).Infof("[tcp] %s - %s", conn.RemoteAddr(), raddr)
	c, err := Connect(raddr.String())
	if err != nil {
		glog.V(LWARNING).Infof("[tcp] %s -> %s : %s", conn.RemoteAddr(), raddr, err)
		return
	}
	defer c.Close()

	glog.V(LINFO).Infof("[tcp] %s <-> %s", conn.RemoteAddr(), raddr)
	Transport(conn, c)
	glog.V(LINFO).Infof("[tcp] %s >-< %s", conn.RemoteAddr(), raddr)
}

func handleUdpForwardLocal(conn *net.UDPConn, laddr, raddr *net.UDPAddr, data []byte) {
	lconn, err := net.ListenUDP("udp", nil)
	if err != nil {
		glog.V(LWARNING).Infof("[udp] %s -> %s : %s", laddr, raddr, err)
		return
	}
	defer lconn.Close()

	if _, err := lconn.WriteToUDP(data, raddr); err != nil {
		glog.V(LWARNING).Infof("[udp] %s -> %s : %s", laddr, raddr, err)
		return
	}
	glog.V(LDEBUG).Infof("[udp] %s >>> %s length %d", laddr, raddr, len(data))

	b := udpPool.Get().([]byte)
	defer udpPool.Put(b)
	lconn.SetReadDeadline(time.Now().Add(time.Second * 60))
	n, addr, err := lconn.ReadFromUDP(b)
	if err != nil {
		glog.V(LWARNING).Infof("[udp] %s <- %s : %s", laddr, raddr, err)
		return
	}
	glog.V(LDEBUG).Infof("[udp] %s <<< %s length %d", laddr, addr, n)

	if _, err := conn.WriteToUDP(b[:n], laddr); err != nil {
		glog.V(LWARNING).Infof("[udp] %s <- %s : %s", laddr, raddr, err)
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
			glog.V(LWARNING).Infof("[udp] %s -> %s : %s", laddr, raddr, err)
			time.Sleep((1 << uint(retry)) * time.Second)
			if retry < 5 {
				retry++
			}
			continue
		}
		break
	}

	glog.V(LINFO).Infof("[udp] %s <-> %s", laddr, raddr)

	rExit := make(chan interface{})
	rErr, wErr := make(chan error, 1), make(chan error, 1)

	go func() {
		for {
			select {
			case dgram := <-rChan:
				if err := dgram.Write(tun); err != nil {
					glog.V(LWARNING).Infof("[udp] %s -> %s : %s", laddr, raddr, err)
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
				glog.V(LWARNING).Infof("[udp] %s <- %s : %s", laddr, raddr, err)
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
	glog.V(LINFO).Infof("[udp] %s >-< %s", laddr, raddr)
}

func connectRTcpForward(conn net.Conn, laddr, raddr net.Addr) error {
	glog.V(LINFO).Infof("[rtcp] %s - %s", laddr, raddr)

	req := gosocks5.NewRequest(gosocks5.CmdBind, ToSocksAddr(laddr))
	if err := req.Write(conn); err != nil {
		glog.V(LWARNING).Infof("[rtcp] %s -> %s : %s", laddr, raddr, err)
		return err
	}

	// first reply, bind status
	conn.SetReadDeadline(time.Now().Add(90 * time.Second))
	rep, err := gosocks5.ReadReply(conn)
	if err != nil {
		glog.V(LWARNING).Infof("[rtcp] %s -> %s : %s", laddr, raddr, err)
		return err
	}
	conn.SetReadDeadline(time.Time{})
	if rep.Rep != gosocks5.Succeeded {
		glog.V(LWARNING).Infof("[rtcp] %s -> %s : bind on %s failure", laddr, raddr, laddr)
		return errors.New("Bind on " + laddr.String() + " failure")
	}
	glog.V(LINFO).Infof("[rtcp] %s - %s BIND ON %s OK", laddr, raddr, rep.Addr)

	// second reply, peer connection
	rep, err = gosocks5.ReadReply(conn)
	if err != nil {
		glog.V(LWARNING).Infof("[rtcp] %s -> %s : %s", laddr, raddr, err)
		return err
	}
	if rep.Rep != gosocks5.Succeeded {
		glog.V(LWARNING).Infof("[rtcp] %s -> %s : peer connect failure", laddr, raddr)
		return errors.New("peer connect failure")
	}

	glog.V(LINFO).Infof("[rtcp] %s -> %s PEER %s CONNECTED", laddr, raddr, rep.Addr)

	go func() {
		defer conn.Close()

		lconn, err := net.DialTimeout("tcp", raddr.String(), time.Second*180)
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

func connectRUdpForward(conn net.Conn, laddr, raddr *net.UDPAddr) error {
	glog.V(LINFO).Infof("[rudp] %s - %s", laddr, raddr)

	req := gosocks5.NewRequest(CmdUdpTun, ToSocksAddr(laddr))
	conn.SetWriteDeadline(time.Now().Add(time.Second * 90))
	if err := req.Write(conn); err != nil {
		glog.V(LWARNING).Infof("[rudp] %s -> %s : %s", laddr, raddr, err)
		return err
	}
	conn.SetWriteDeadline(time.Time{})

	conn.SetReadDeadline(time.Now().Add(90 * time.Second))
	rep, err := gosocks5.ReadReply(conn)
	if err != nil {
		glog.V(LWARNING).Infof("[rudp] %s <- %s : %s", laddr, raddr, err)
		return err
	}
	conn.SetReadDeadline(time.Time{})

	if rep.Rep != gosocks5.Succeeded {
		glog.V(LWARNING).Infof("[rudp] %s <- %s : bind on %s failure", laddr, raddr, laddr)
		return errors.New(fmt.Sprintf("Bind on %s failure", laddr))
	}

	glog.V(LINFO).Infof("[rudp] %s - %s BIND ON %s OK", laddr, raddr, rep.Addr)

	for {
		dgram, err := gosocks5.ReadUDPDatagram(conn)
		if err != nil {
			glog.V(LWARNING).Infof("[rudp] %s <- %s : %s", laddr, raddr, err)
			return err
		}

		go func() {
			b := udpPool.Get().([]byte)
			defer udpPool.Put(b)

			relay, err := net.DialUDP("udp", nil, raddr)
			if err != nil {
				glog.V(LWARNING).Infof("[rudp] %s -> %s : %s", laddr, raddr, err)
				return
			}
			defer relay.Close()

			if _, err := relay.Write(dgram.Data); err != nil {
				glog.V(LWARNING).Infof("[rudp] %s -> %s : %s", laddr, raddr, err)
				return
			}
			glog.V(LDEBUG).Infof("[rudp] %s >>> %s length: %d", laddr, raddr, len(dgram.Data))

			relay.SetReadDeadline(time.Now().Add(time.Second * 60))
			n, err := relay.Read(b)
			if err != nil {
				glog.V(LWARNING).Infof("[rudp] %s <- %s : %s", laddr, raddr, err)
				return
			}
			relay.SetReadDeadline(time.Time{})

			glog.V(LDEBUG).Infof("[rudp] %s <<< %s length: %d", laddr, raddr, n)

			conn.SetWriteDeadline(time.Now().Add(time.Second * 90))
			if err := gosocks5.NewUDPDatagram(gosocks5.NewUDPHeader(uint16(n), 0, dgram.Header.Addr), b[:n]).Write(conn); err != nil {
				glog.V(LWARNING).Infof("[rudp] %s <- %s : %s", laddr, raddr, err)
				return
			}
			conn.SetWriteDeadline(time.Time{})
		}()
	}

}
