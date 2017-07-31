package main

import (
	"flag"
	"log"
	"net"
)

var (
	laddr string
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	flag.StringVar(&laddr, "L", ":8080", "listen address")
	flag.Parse()
}
func main() {
	udpEchoServer()
}

func udpEchoServer() {
	addr, err := net.ResolveUDPAddr("udp", laddr)
	if err != nil {
		log.Fatal(err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatal(err)
	}

	for {
		b := make([]byte, 1024)
		n, raddr, err := conn.ReadFromUDP(b)
		if err != nil {
			log.Fatal(err)
		}
		if _, err = conn.WriteToUDP(b[:n], raddr); err != nil {
			log.Fatal(err)
		}

	}
}
