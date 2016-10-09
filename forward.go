package gost

import (
	"errors"
	"fmt"
	"github.com/ginuerzh/gosocks5"
	"github.com/golang/glog"
	"net"
	"time"
)

type TcpForwardServer struct {
	Base    *ProxyServer
	Handler func(conn net.Conn, raddr net.Addr)
}

func NewTcpForwardServer(base *ProxyServer) *TcpForwardServer {
	return &TcpForwardServer{Base: base}
}

func (s *TcpForwardServer) ListenAndServe() error {
	raddr, err := net.ResolveTCPAddr("tcp", s.Base.Node.Remote)
	if err != nil {
		return err
	}

	ln, err := net.Listen("tcp", s.Base.Node.Addr)
	if err != nil {
		return err
	}
	defer ln.Close()

	if s.Handler == nil {
		s.Handler = s.handleTcpForward
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			glog.V(LWARNING).Infoln(err)
			continue
		}
		setKeepAlive(conn, KeepAliveTime)

		go s.Handler(conn, raddr)
	}
}

func (s *TcpForwardServer) handleTcpForward(conn net.Conn, raddr net.Addr) {
	defer conn.Close()

	glog.V(LINFO).Infof("[tcp] %s - %s", conn.RemoteAddr(), raddr)
	cc, err := s.Base.Chain.Dial(raddr.String())
	if err != nil {
		glog.V(LWARNING).Infof("[tcp] %s -> %s : %s", conn.RemoteAddr(), raddr, err)
		return
	}
	defer cc.Close()

	glog.V(LINFO).Infof("[tcp] %s <-> %s", conn.RemoteAddr(), raddr)
	s.Base.transport(conn, cc)
	glog.V(LINFO).Infof("[tcp] %s >-< %s", conn.RemoteAddr(), raddr)
}

type UdpForwardServer struct {
	Base *ProxyServer
}

func NewUdpForwardServer(base *ProxyServer) *UdpForwardServer {
	return &UdpForwardServer{Base: base}
}

func (s *UdpForwardServer) ListenAndServe() error {
	laddr, err := net.ResolveUDPAddr("udp", s.Base.Node.Addr)
	if err != nil {
		return err
	}

	raddr, err := net.ResolveUDPAddr("udp", s.Base.Node.Remote)
	if err != nil {
		return err
	}

	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		glog.V(LWARNING).Infof("[udp] %s -> %s : %s", laddr, raddr, err)
		return err
	}
	defer conn.Close()

	if len(s.Base.Chain.nodes) == 0 {
		for {
			b := make([]byte, MediumBufferSize)
			n, addr, err := conn.ReadFromUDP(b)
			if err != nil {
				glog.V(LWARNING).Infof("[udp] %s -> %s : %s", laddr, raddr, err)
				continue
			}
			go func() {
				s.handleUdpForwardLocal(conn, addr, raddr, b[:n])
			}()
		}
	}

	rChan, wChan := make(chan *gosocks5.UDPDatagram, 32), make(chan *gosocks5.UDPDatagram, 32)

	go func() {
		for {
			b := make([]byte, MediumBufferSize)
			n, addr, err := conn.ReadFromUDP(b)
			if err != nil {
				glog.V(LWARNING).Infof("[udp] %s -> %s : %s", laddr, raddr, err)
				return
			}

			select {
			case rChan <- gosocks5.NewUDPDatagram(gosocks5.NewUDPHeader(uint16(n), 0, ToSocksAddr(addr)), b[:n]):
			default:
				// glog.V(LWARNING).Infof("[udp-connect] %s -> %s : rbuf is full", laddr, raddr)
			}
		}
	}()

	go func() {
		for {
			dgram := <-wChan
			addr, err := net.ResolveUDPAddr("udp", dgram.Header.Addr.String())
			if err != nil {
				glog.V(LWARNING).Infof("[udp] %s <- %s : %s", laddr, raddr, err)
				continue // drop silently
			}
			if _, err = conn.WriteToUDP(dgram.Data, addr); err != nil {
				glog.V(LWARNING).Infof("[udp] %s <- %s : %s", laddr, raddr, err)
				return
			}
		}
	}()

	for {
		s.handleUdpForwardTunnel(laddr, raddr, rChan, wChan)
	}
}

func (s *UdpForwardServer) handleUdpForwardLocal(conn *net.UDPConn, laddr, raddr *net.UDPAddr, data []byte) {
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

	b := make([]byte, MediumBufferSize)
	lconn.SetReadDeadline(time.Now().Add(ReadTimeout))
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

func (s *UdpForwardServer) handleUdpForwardTunnel(laddr, raddr *net.UDPAddr, rChan, wChan chan *gosocks5.UDPDatagram) {
	var cc net.Conn
	var err error
	retry := 0

	for {
		cc, err = s.prepareUdpConnectTunnel(raddr)
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
	defer cc.Close()

	glog.V(LINFO).Infof("[udp] %s <-> %s", laddr, raddr)

	rExit := make(chan interface{})
	errc := make(chan error, 2)

	go func() {
		for {
			select {
			case dgram := <-rChan:
				if err := dgram.Write(cc); err != nil {
					glog.V(LWARNING).Infof("[udp] %s -> %s : %s", laddr, raddr, err)
					errc <- err
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
			dgram, err := gosocks5.ReadUDPDatagram(cc)
			if err != nil {
				glog.V(LWARNING).Infof("[udp] %s <- %s : %s", laddr, raddr, err)
				close(rExit)
				errc <- err
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
	case <-errc:
		//log.Println("w exit", err)
	}
	glog.V(LINFO).Infof("[udp] %s >-< %s", laddr, raddr)
}

func (s *UdpForwardServer) prepareUdpConnectTunnel(addr net.Addr) (net.Conn, error) {
	conn, err := s.Base.Chain.GetConn()
	if err != nil {
		return nil, err
	}

	conn.SetWriteDeadline(time.Now().Add(WriteTimeout))
	if err = gosocks5.NewRequest(CmdUdpConnect, ToSocksAddr(addr)).Write(conn); err != nil {
		conn.Close()
		return nil, err
	}
	conn.SetWriteDeadline(time.Time{})

	conn.SetReadDeadline(time.Now().Add(ReadTimeout))
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

type RTcpForwardServer struct {
	Base *ProxyServer
}

func NewRTcpForwardServer(base *ProxyServer) *RTcpForwardServer {
	return &RTcpForwardServer{Base: base}
}

func (s *RTcpForwardServer) Serve() error {
	if len(s.Base.Chain.nodes) == 0 {
		return errors.New("rtcp: at least one -F must be assigned")
	}

	laddr, err := net.ResolveTCPAddr("tcp", s.Base.Node.Addr)
	if err != nil {
		return err
	}
	raddr, err := net.ResolveTCPAddr("tcp", s.Base.Node.Remote)
	if err != nil {
		return err
	}

	retry := 0
	for {
		conn, err := s.Base.Chain.GetConn()
		if err != nil {
			glog.V(LWARNING).Infof("[rtcp] %s - %s : %s", laddr, raddr, err)
			time.Sleep((1 << uint(retry)) * time.Second)
			if retry < 5 {
				retry++
			}
			continue
		}
		retry = 0

		if err := s.connectRTcpForward(conn, laddr, raddr); err != nil {
			conn.Close()
			time.Sleep(6 * time.Second)
		}
	}
}

func (s *RTcpForwardServer) connectRTcpForward(conn net.Conn, laddr, raddr net.Addr) error {
	glog.V(LINFO).Infof("[rtcp] %s - %s", laddr, raddr)

	req := gosocks5.NewRequest(gosocks5.CmdBind, ToSocksAddr(laddr))
	if err := req.Write(conn); err != nil {
		glog.V(LWARNING).Infof("[rtcp] %s -> %s : %s", laddr, raddr, err)
		return err
	}

	// first reply, bind status
	conn.SetReadDeadline(time.Now().Add(ReadTimeout))
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
			glog.V(LWARNING).Infof("[rtcp] %s -> %s : %s", rep.Addr, raddr, err)
			return
		}
		defer lconn.Close()

		glog.V(LINFO).Infof("[rtcp] %s <-> %s", rep.Addr, lconn.RemoteAddr())
		s.Base.transport(lconn, conn)
		glog.V(LINFO).Infof("[rtcp] %s >-< %s", rep.Addr, lconn.RemoteAddr())
	}()

	return nil
}

type RUdpForwardServer struct {
	Base *ProxyServer
}

func NewRUdpForwardServer(base *ProxyServer) *RUdpForwardServer {
	return &RUdpForwardServer{Base: base}
}

func (s *RUdpForwardServer) Serve() error {
	if len(s.Base.Chain.nodes) == 0 {
		return errors.New("rudp: at least one -F must be assigned")
	}

	laddr, err := net.ResolveUDPAddr("udp", s.Base.Node.Addr)
	if err != nil {
		return err
	}
	raddr, err := net.ResolveUDPAddr("udp", s.Base.Node.Remote)
	if err != nil {
		return err
	}

	retry := 0
	for {
		conn, err := s.Base.Chain.GetConn()
		if err != nil {
			glog.V(LWARNING).Infof("[rudp] %s - %s : %s", laddr, raddr, err)
			time.Sleep((1 << uint(retry)) * time.Second)
			if retry < 5 {
				retry++
			}
			continue
		}
		retry = 0

		if err := s.connectRUdpForward(conn, laddr, raddr); err != nil {
			conn.Close()
			time.Sleep(6 * time.Second)
		}
	}
}

func (s *RUdpForwardServer) connectRUdpForward(conn net.Conn, laddr, raddr *net.UDPAddr) error {
	glog.V(LINFO).Infof("[rudp] %s - %s", laddr, raddr)

	req := gosocks5.NewRequest(CmdUdpTun, ToSocksAddr(laddr))
	conn.SetWriteDeadline(time.Now().Add(WriteTimeout))
	if err := req.Write(conn); err != nil {
		glog.V(LWARNING).Infof("[rudp] %s -> %s : %s", laddr, raddr, err)
		return err
	}
	conn.SetWriteDeadline(time.Time{})

	conn.SetReadDeadline(time.Now().Add(ReadTimeout))
	rep, err := gosocks5.ReadReply(conn)
	if err != nil {
		glog.V(LWARNING).Infof("[rudp] %s <- %s : %s", laddr, raddr, err)
		return err
	}
	conn.SetReadDeadline(time.Time{})

	if rep.Rep != gosocks5.Succeeded {
		glog.V(LWARNING).Infof("[rudp] %s <- %s : bind on %s failure", laddr, raddr, laddr)
		return errors.New(fmt.Sprintf("bind on %s failure", laddr))
	}

	glog.V(LINFO).Infof("[rudp] %s - %s BIND ON %s OK", laddr, raddr, rep.Addr)

	for {
		dgram, err := gosocks5.ReadUDPDatagram(conn)
		if err != nil {
			glog.V(LWARNING).Infof("[rudp] %s <- %s : %s", laddr, raddr, err)
			return err
		}

		go func() {
			b := make([]byte, MediumBufferSize)

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

			relay.SetReadDeadline(time.Now().Add(ReadTimeout))
			n, err := relay.Read(b)
			if err != nil {
				glog.V(LWARNING).Infof("[rudp] %s <- %s : %s", laddr, raddr, err)
				return
			}
			relay.SetReadDeadline(time.Time{})

			glog.V(LDEBUG).Infof("[rudp] %s <<< %s length: %d", laddr, raddr, n)

			conn.SetWriteDeadline(time.Now().Add(WriteTimeout))
			if err := gosocks5.NewUDPDatagram(gosocks5.NewUDPHeader(uint16(n), 0, dgram.Header.Addr), b[:n]).Write(conn); err != nil {
				glog.V(LWARNING).Infof("[rudp] %s <- %s : %s", laddr, raddr, err)
				return
			}
			conn.SetWriteDeadline(time.Time{})
		}()
	}
}
