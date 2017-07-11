package gost

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/ginuerzh/gosocks5"
	"github.com/golang/glog"
	"golang.org/x/crypto/ssh"
)

type TcpForwardServer struct {
	Base      *ProxyServer
	sshClient *ssh.Client
	Handler   func(conn net.Conn, raddr *net.TCPAddr)
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

	quit := make(chan interface{})
	close(quit) // first init ssh client

	for {
	start:
		conn, err := ln.Accept()
		if err != nil {
			glog.V(LWARNING).Infoln("[ssh]", err)
			continue
		}
		setKeepAlive(conn, KeepAliveTime)

		select {
		case <-quit:
			if s.Base.Chain.lastNode == nil || s.Base.Chain.lastNode.Transport != "ssh" {
				break
			}
			if err := s.initSSHClient(); err != nil {
				glog.V(LWARNING).Infoln("[ssh]", err)
				conn.Close()
				goto start
			}
			quit = make(chan interface{})
			exit := make(chan error, 1)
			go func() {
				exit <- s.sshClient.Wait()
			}()

			go func() {
				var c <-chan time.Time
				ping, _ := strconv.Atoi(s.Base.Chain.lastNode.Get("ping"))
				if ping > 0 {
					d := time.Second * time.Duration(ping)
					glog.V(LINFO).Infoln("[tcp-ssh] ping is enabled:", d)
					t := time.NewTicker(d)
					defer t.Stop()
					c = t.C
				}

				for {
					select {
					case <-c:
						_, _, err := s.sshClient.SendRequest("ping", true, nil)
						if err != nil {
							glog.V(LWARNING).Infoln("[tcp-ssh] ping", err)
							close(quit)
							return
						}
						glog.V(LDEBUG).Infoln("[tcp-ssh] heartbeat OK")

					case er := <-exit:
						if er != nil {
							glog.V(LWARNING).Infoln("[tcp-ssh] ssh connection closed:", er)
						}
						close(quit)
						return
					}
				}
			}()

		default:
		}

		go s.Handler(conn, raddr)
	}
}

func (s *TcpForwardServer) initSSHClient() error {
	if s.sshClient != nil {
		s.sshClient.Close()
		s.sshClient = nil
	}

	sshNode := s.Base.Chain.lastNode
	c, err := s.Base.Chain.GetConn()
	if err != nil {
		return err
	}
	var user, password string
	if len(sshNode.Users) > 0 {
		user = sshNode.Users[0].Username()
		password, _ = sshNode.Users[0].Password()
	}
	config := ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(c, sshNode.Addr, &config)
	if err != nil {
		return err
	}
	s.sshClient = ssh.NewClient(sshConn, chans, reqs)
	s.Handler = s.handleTcpForwardSSH

	return nil
}

func (s *TcpForwardServer) handleTcpForward(conn net.Conn, raddr *net.TCPAddr) {
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

func (s *TcpForwardServer) handleTcpForwardSSH(conn net.Conn, raddr *net.TCPAddr) {
	defer conn.Close()

	if s.sshClient == nil {
		return
	}

	rc, err := s.sshClient.DialTCP("tcp", nil, raddr)
	if err != nil {
		glog.V(LWARNING).Infof("[tcp] %s -> %s : %s", conn.RemoteAddr(), raddr, err)
		return
	}
	defer rc.Close()

	glog.V(LINFO).Infof("[tcp] %s <-> %s", conn.RemoteAddr(), raddr)
	Transport(conn, rc)
	glog.V(LINFO).Infof("[tcp] %s >-< %s", conn.RemoteAddr(), raddr)
}

type packet struct {
	srcAddr string // src address
	dstAddr string // dest address
	data    []byte
}

type cnode struct {
	chain            *ProxyChain
	conn             net.Conn
	srcAddr, dstAddr string
	rChan, wChan     chan *packet
	err              error
	ttl              time.Duration
}

func (node *cnode) getUDPTunnel() (net.Conn, error) {
	conn, err := node.chain.GetConn()
	if err != nil {
		return nil, err
	}

	conn.SetWriteDeadline(time.Now().Add(WriteTimeout))
	if err = gosocks5.NewRequest(CmdUdpTun, nil).Write(conn); err != nil {
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
		return nil, errors.New("UDP tunnel failure")
	}

	return conn, nil
}

func (node *cnode) run() {
	if len(node.chain.Nodes()) == 0 {
		lconn, err := net.ListenUDP("udp", nil)
		if err != nil {
			glog.V(LWARNING).Infof("[udp] %s -> %s : %s", node.srcAddr, node.dstAddr, err)
			node.err = err
			return
		}
		node.conn = lconn
	} else {
		tc, err := node.getUDPTunnel()
		if err != nil {
			glog.V(LWARNING).Infof("[udp-tun] %s -> %s : %s", node.srcAddr, node.dstAddr, err)
			node.err = err
			return
		}
		node.conn = tc
	}

	defer node.conn.Close()

	timer := time.NewTimer(node.ttl)
	errChan := make(chan error, 2)

	go func() {
		for {
			switch c := node.conn.(type) {
			case *net.UDPConn:
				b := make([]byte, MediumBufferSize)
				n, addr, err := c.ReadFromUDP(b)
				if err != nil {
					glog.V(LWARNING).Infof("[udp] %s <- %s : %s", node.srcAddr, node.dstAddr, err)
					node.err = err
					errChan <- err
					return
				}

				timer.Reset(node.ttl)
				glog.V(LDEBUG).Infof("[udp] %s <<< %s : length %d", node.srcAddr, addr, n)

				select {
				// swap srcAddr with dstAddr
				case node.rChan <- &packet{srcAddr: addr.String(), dstAddr: node.srcAddr, data: b[:n]}:
				case <-time.After(time.Second * 3):
					glog.V(LWARNING).Infof("[udp] %s <- %s : %s", node.srcAddr, node.dstAddr, "recv queue is full, discard")
				}

			default:
				dgram, err := gosocks5.ReadUDPDatagram(c)
				if err != nil {
					glog.V(LWARNING).Infof("[udp-tun] %s <- %s : %s", node.srcAddr, node.dstAddr, err)
					node.err = err
					errChan <- err
					return
				}

				timer.Reset(node.ttl)
				glog.V(LDEBUG).Infof("[udp-tun] %s <<< %s : length %d", node.srcAddr, dgram.Header.Addr.String(), len(dgram.Data))

				select {
				// swap srcAddr with dstAddr
				case node.rChan <- &packet{srcAddr: dgram.Header.Addr.String(), dstAddr: node.srcAddr, data: dgram.Data}:
				case <-time.After(time.Second * 3):
					glog.V(LWARNING).Infof("[udp-tun] %s <- %s : %s", node.srcAddr, node.dstAddr, "recv queue is full, discard")
				}
			}
		}
	}()

	go func() {
		for pkt := range node.wChan {
			timer.Reset(node.ttl)

			dstAddr, err := net.ResolveUDPAddr("udp", pkt.dstAddr)
			if err != nil {
				glog.V(LWARNING).Infof("[udp] %s -> %s : %s", pkt.srcAddr, pkt.dstAddr, err)
				continue
			}

			switch c := node.conn.(type) {
			case *net.UDPConn:
				if _, err := c.WriteToUDP(pkt.data, dstAddr); err != nil {
					glog.V(LWARNING).Infof("[udp] %s -> %s : %s", pkt.srcAddr, pkt.dstAddr, err)
					node.err = err
					errChan <- err
					return
				}
				glog.V(LDEBUG).Infof("[udp] %s >>> %s : length %d", pkt.srcAddr, pkt.dstAddr, len(pkt.data))

			default:
				dgram := gosocks5.NewUDPDatagram(gosocks5.NewUDPHeader(uint16(len(pkt.data)), 0, ToSocksAddr(dstAddr)), pkt.data)
				if err := dgram.Write(c); err != nil {
					glog.V(LWARNING).Infof("[udp-tun] %s -> %s : %s", pkt.srcAddr, pkt.dstAddr, err)
					node.err = err
					errChan <- err
					return
				}
				glog.V(LDEBUG).Infof("[udp-tun] %s >>> %s : length %d", pkt.srcAddr, pkt.dstAddr, len(pkt.data))
			}
		}
	}()

	select {
	case <-errChan:
	case <-timer.C:
	}
}

type UdpForwardServer struct {
	Base *ProxyServer
	TTL  int
}

func NewUdpForwardServer(base *ProxyServer, ttl int) *UdpForwardServer {
	return &UdpForwardServer{Base: base, TTL: ttl}
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

	rChan, wChan := make(chan *packet, 128), make(chan *packet, 128)
	// start send queue
	go func(ch chan<- *packet) {
		for {
			b := make([]byte, MediumBufferSize)
			n, addr, err := conn.ReadFromUDP(b)
			if err != nil {
				glog.V(LWARNING).Infof("[udp] %s -> %s : %s", laddr, raddr, err)
				continue
			}

			select {
			case ch <- &packet{srcAddr: addr.String(), dstAddr: raddr.String(), data: b[:n]}:
			case <-time.After(time.Second * 3):
				glog.V(LWARNING).Infof("[udp] %s -> %s : %s", addr, raddr, "send queue is full, discard")
			}
		}
	}(wChan)
	// start recv queue
	go func(ch <-chan *packet) {
		for pkt := range ch {
			dstAddr, err := net.ResolveUDPAddr("udp", pkt.dstAddr)
			if err != nil {
				glog.V(LWARNING).Infof("[udp] %s <- %s : %s", pkt.dstAddr, pkt.srcAddr, err)
				continue
			}
			if _, err := conn.WriteToUDP(pkt.data, dstAddr); err != nil {
				glog.V(LWARNING).Infof("[udp] %s <- %s : %s", pkt.dstAddr, pkt.srcAddr, err)
				return
			}
		}
	}(rChan)

	// mapping client to node
	m := make(map[string]*cnode)

	// start dispatcher
	for pkt := range wChan {
		// clear obsolete nodes
		for k, node := range m {
			if node != nil && node.err != nil {
				close(node.wChan)
				delete(m, k)
				glog.V(LINFO).Infof("[udp] clear node %s", k)
			}
		}

		node, ok := m[pkt.srcAddr]
		if !ok {
			node = &cnode{
				chain:   s.Base.Chain,
				srcAddr: pkt.srcAddr,
				dstAddr: pkt.dstAddr,
				rChan:   rChan,
				wChan:   make(chan *packet, 32),
				ttl:     time.Duration(s.TTL) * time.Second,
			}
			m[pkt.srcAddr] = node
			go node.run()
			glog.V(LINFO).Infof("[udp] %s -> %s : new client (%d)", pkt.srcAddr, pkt.dstAddr, len(m))
		}

		select {
		case node.wChan <- pkt:
		case <-time.After(time.Second * 3):
			glog.V(LWARNING).Infof("[udp] %s -> %s : %s", pkt.srcAddr, pkt.dstAddr, "node send queue is full, discard")
		}
	}

	return nil
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

		glog.V(LINFO).Infof("[rtcp] %s - %s", laddr, raddr)

		lastNode := s.Base.Chain.lastNode
		if lastNode != nil && lastNode.Transport == "ssh" {
			s.connectRTcpForwardSSH(conn, lastNode, laddr, raddr)
		} else {
			if err := s.connectRTcpForward(conn, laddr, raddr); err != nil {
				conn.Close()
			}
		}
		time.Sleep(3 * time.Second)
	}
}

func (s *RTcpForwardServer) connectRTcpForwardSSH(conn net.Conn, sshNode *ProxyNode, laddr, raddr net.Addr) error {
	defer conn.Close()

	var user, password string
	if len(sshNode.Users) > 0 {
		user = sshNode.Users[0].Username()
		password, _ = sshNode.Users[0].Password()
	}
	config := ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, sshNode.Addr, &config)
	if err != nil {
		glog.V(LWARNING).Infof("[rtcp] %s -> %s : %s", laddr, raddr, err)
		return err
	}
	client := ssh.NewClient(c, chans, reqs)

	quit := make(chan interface{})
	defer close(quit)

	go func() {
		defer client.Close()

		var c <-chan time.Time

		ping, _ := strconv.Atoi(sshNode.Get("ping"))
		if ping > 0 {
			d := time.Second * time.Duration(ping)
			glog.V(LINFO).Infoln("[rtcp] ping is enabled:", d)
			t := time.NewTicker(d)
			defer t.Stop()
			c = t.C
		}

		for {
			select {
			case <-c:
				_, _, err := client.SendRequest("ping", true, nil)
				if err != nil {
					glog.V(LWARNING).Infoln("[rtcp] ping", err)
					return
				}
				glog.V(LDEBUG).Infoln("[rtcp] heartbeat OK")

			case <-quit:
				glog.V(LWARNING).Infoln("[rtcp] ssh connection closed")
				return
			}
		}
	}()

	addr := laddr.String()
	if strings.HasPrefix(addr, ":") {
		addr = "0.0.0.0" + addr
	}
	ln, err := client.Listen("tcp", addr)
	if err != nil {
		glog.V(LWARNING).Infof("[rtcp] %s -> %s : %s", laddr, raddr, err)
		return err
	}
	defer ln.Close()

	for {
		rc, err := ln.Accept()
		if err != nil {
			return err
		}

		go func(c net.Conn) {
			defer c.Close()

			tc, err := net.DialTimeout("tcp", raddr.String(), time.Second*30)
			if err != nil {
				glog.V(LWARNING).Infof("[rtcp] %s -> %s : %s", laddr, raddr, err)
				return
			}
			defer tc.Close()

			glog.V(LINFO).Infof("[rtcp] %s <-> %s", c.RemoteAddr(), c.LocalAddr())
			Transport(c, tc)
			glog.V(LINFO).Infof("[rtcp] %s >-< %s", c.RemoteAddr(), c.LocalAddr())
		}(rc)
	}
}

func (s *RTcpForwardServer) connectRTcpForward(conn net.Conn, laddr, raddr net.Addr) error {
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

		lconn, err := net.DialTimeout("tcp", raddr.String(), time.Second*30)
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
