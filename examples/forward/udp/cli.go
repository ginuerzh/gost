package main

import (
	"flag"
	"log"
	"net"
	"time"
)

var (
	concurrency int
	saddr       string
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	flag.StringVar(&saddr, "S", ":18080", "server address")
	flag.IntVar(&concurrency, "c", 1, "Number of multiple echo to make at a time")
	flag.Parse()
}

func main() {
	for i := 0; i < concurrency; i++ {
		go udpEchoLoop()
	}
	select{}
}

func udpEchoLoop() {
	addr, err := net.ResolveUDPAddr("udp", saddr)
	if err != nil {
		log.Fatal(err)
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		log.Fatal(err)
	}

	msg := []byte(`abcdefghijklmnopqrstuvwxyz`)
	for {
		if _, err := conn.Write(msg); err != nil {
			log.Fatal(err)
		}
		b := make([]byte, 1024)
		_, err := conn.Read(b)
		if err != nil {
			log.Fatal(err)
		}
		// log.Println(string(b[:n]))
		time.Sleep(100 * time.Millisecond)
	}
}
