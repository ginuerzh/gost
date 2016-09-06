package main

import (
	"bytes"
	"github.com/ginuerzh/gosocks5"
	"github.com/golang/glog"
	"net"
	//"time"
)

func transportUDP(relay, peer *net.UDPConn) (err error) {
	rChan := make(chan error, 1)
	wChan := make(chan error, 1)

	var clientAddr *net.UDPAddr

	go func() {
		b := udpPool.Get().([]byte)
		defer udpPool.Put(b)

		for {
			n, laddr, err := relay.ReadFromUDP(b)
			if err != nil {
				rChan <- err
				return
			}
			if clientAddr == nil {
				clientAddr = laddr
			}
			dgram, err := gosocks5.ReadUDPDatagram(bytes.NewReader(b[:n]))
			if err != nil {
				rChan <- err
				return
			}

			raddr, err := net.ResolveUDPAddr("udp", dgram.Header.Addr.String())
			if err != nil {
				continue // drop silently
			}
			if _, err := peer.WriteToUDP(dgram.Data, raddr); err != nil {
				rChan <- err
				return
			}
			glog.V(LDEBUG).Infof("[socks5-udp] %s >>> %s length: %d", relay.LocalAddr(), raddr, len(dgram.Data))
		}
	}()

	go func() {
		b := udpPool.Get().([]byte)
		defer udpPool.Put(b)

		for {
			n, raddr, err := peer.ReadFrom(b)
			if err != nil {
				wChan <- err
				return
			}
			if clientAddr == nil {
				continue
			}
			buf := bytes.Buffer{}
			dgram := gosocks5.NewUDPDatagram(gosocks5.NewUDPHeader(0, 0, ToSocksAddr(raddr)), b[:n])
			dgram.Write(&buf)
			if _, err := relay.WriteToUDP(buf.Bytes(), clientAddr); err != nil {
				wChan <- err
				return
			}
			glog.V(LDEBUG).Infof("[socks5-udp] %s <<< %s length: %d", relay.LocalAddr(), raddr, len(dgram.Data))
		}
	}()

	select {
	case err = <-wChan:
		//log.Println("w exit", err)
	case err = <-rChan:
		//log.Println("r exit", err)
	}

	return
}

func tunnelUDP(conn *net.UDPConn, tun net.Conn, client bool) (err error) {
	rChan := make(chan error, 1)
	wChan := make(chan error, 1)

	var clientAddr *net.UDPAddr

	go func() {
		b := udpPool.Get().([]byte)
		defer udpPool.Put(b)

		for {
			n, addr, err := conn.ReadFromUDP(b)
			if err != nil {
				rChan <- err
				return
			}

			var dgram *gosocks5.UDPDatagram
			if client { // pipe from relay to tunnel
				dgram, err = gosocks5.ReadUDPDatagram(bytes.NewReader(b[:n]))
				if err != nil {
					rChan <- err
					return
				}
				if clientAddr == nil {
					clientAddr = addr
				}
				dgram.Header.Rsv = uint16(len(dgram.Data))
				if err := dgram.Write(tun); err != nil {
					rChan <- err
					return
				}
				glog.V(LDEBUG).Infof("[socks5-udp] %s >>> %s length: %d", conn.LocalAddr(), dgram.Header.Addr, len(dgram.Data))
			} else { // pipe from peer to tunnel
				dgram = gosocks5.NewUDPDatagram(
					gosocks5.NewUDPHeader(uint16(n), 0, ToSocksAddr(addr)), b[:n])
				if err := dgram.Write(tun); err != nil {
					rChan <- err
					return
				}
				glog.V(LDEBUG).Infof("[socks5-udp] %s <<< %s length: %d", tun.RemoteAddr(), dgram.Header.Addr, len(dgram.Data))
			}
		}
	}()

	go func() {
		for {
			dgram, err := gosocks5.ReadUDPDatagram(tun)
			if err != nil {
				wChan <- err
				return
			}

			if client { // pipe from tunnel to relay
				if clientAddr == nil {
					continue
				}
				dgram.Header.Rsv = 0

				buf := bytes.Buffer{}
				dgram.Write(&buf)
				if _, err := conn.WriteToUDP(buf.Bytes(), clientAddr); err != nil {
					wChan <- err
					return
				}
				glog.V(LDEBUG).Infof("[socks5-udp] %s <<< %s length: %d", conn.LocalAddr(), dgram.Header.Addr, len(dgram.Data))
			} else { // pipe from tunnel to peer
				addr, err := net.ResolveUDPAddr("udp", dgram.Header.Addr.String())
				if err != nil {
					continue // drop silently
				}
				if _, err := conn.WriteToUDP(dgram.Data, addr); err != nil {
					wChan <- err
					return
				}
				glog.V(LDEBUG).Infof("[socks5-udp] %s >>> %s length: %d", tun.RemoteAddr(), addr, len(dgram.Data))
			}
		}
	}()

	select {
	case err = <-wChan:
		//log.Println("w exit", err)
	case err = <-rChan:
		//log.Println("r exit", err)
	}

	return
}
