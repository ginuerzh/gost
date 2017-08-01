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
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		log.Fatal(err)
	}
	cp, err := ss.NewCipher("chacha20", "123456")
	if err != nil {
		log.Fatal(err)
	}
	cc := ss.NewSecurePacketConn(conn, cp, false)

	raddr, _ := net.ResolveTCPAddr("udp", ":8080")
	msg := []byte(`abcdefghijklmnopqrstuvwxyz`)
	dgram := gosocks5.NewUDPDatagram(gosocks5.NewUDPHeader(0, 0, toSocksAddr(raddr)), msg)
	buf := bytes.Buffer{}
	dgram.Write(&buf)
	if _, err := cc.WriteTo(buf.Bytes()[3:], addr); err != nil {
		log.Fatal(err)
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
