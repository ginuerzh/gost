package main

import (
	"bytes"
	"log"
	"net"
	"strconv"

	"github.com/ginuerzh/gosocks5"
	ss "github.com/shadowsocks/shadowsocks-go/shadowsocks"
)

func main() {
	ssuClient()
}

func ssuClient() {
	addr, err := net.ResolveUDPAddr("udp", ":18338")
	if err != nil {
		log.Fatal(err)
	}
	laddr, _ := net.ResolveUDPAddr("udp", ":10800")
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		log.Fatal(err)
	}
	cp, err := ss.NewCipher("chacha20", "123456")
	if err != nil {
		log.Fatal(err)
	}
	cc := ss.NewSecurePacketConn(conn, cp, false)

	raddr, _ := net.ResolveUDPAddr("udp", ":8080")
	msg := []byte(`abcdefghijklmnopqrstuvwxyz`)
	dgram := gosocks5.NewUDPDatagram(gosocks5.NewUDPHeader(0, 0, toSocksAddr(raddr)), msg)
	buf := bytes.Buffer{}
	dgram.Write(&buf)
	for {
		log.Printf("%# x", buf.Bytes()[3:])
		if _, err := cc.WriteTo(buf.Bytes()[3:], addr); err != nil {
			log.Fatal(err)
		}
		b := make([]byte, 1024)
		n, adr, err := cc.ReadFrom(b)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("%s: %# x", adr, b[:n])
	}
}

func toSocksAddr(addr net.Addr) *gosocks5.Addr {
	host := "0.0.0.0"
	port := 0
	if addr != nil {
		h, p, _ := net.SplitHostPort(addr.String())
		host = h
		port, _ = strconv.Atoi(p)
	}
	return &gosocks5.Addr{
		Type: gosocks5.AddrIPv4,
		Host: host,
		Port: uint16(port),
	}
}
