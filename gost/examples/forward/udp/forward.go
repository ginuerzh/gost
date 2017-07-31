package main

import (
	"flag"
	"log"
	"net/url"
	"time"

	"github.com/ginuerzh/gost/gost"
)

var (
	laddr, faddr string
	quiet        bool
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	flag.StringVar(&laddr, "L", ":18080", "listen address")
	flag.StringVar(&faddr, "F", ":8080", "forward address")
	flag.BoolVar(&quiet, "q", false, "quiet mode")
	flag.BoolVar(&gost.Debug, "d", false, "debug mode")
	flag.Parse()

	if quiet {
		gost.SetLogger(&gost.NopLogger{})
	}
}
func main() {
	udpForwardServer()
}

func udpForwardServer() {
	s := &gost.Server{}
	ln, err := gost.UDPForwardListener(laddr, time.Second*3)
	if err != nil {
		log.Fatal(err)
	}
	h := gost.UDPForwardHandler(
		faddr,
		gost.ChainHandlerOption(gost.NewChain(gost.Node{
			Protocol:  "socks5",
			Transport: "tcp",
			Addr:      ":11080",
			User:      url.UserPassword("admin", "123456"),
			Client: &gost.Client{
				Connector: gost.SOCKS5Connector(
					url.UserPassword("admin", "123456"),
				),
				Transporter: gost.TCPTransporter(),
			},
		})),
	)
	log.Fatal(s.Serve(ln, h))
}
