package main

import (
	"log"

	"github.com/ginuerzh/gost/gost"
)

func main() {
	tcpForward()
}

func tcpForward() {
	chain := gost.NewChain(
		gost.Node{
			Addr: "localhost:11222",
			Client: &gost.Client{
				Connector:   gost.SSHDirectForwardConnector(),
				Transporter: gost.SSHForwardTransporter(),
			},
		},
	)

	s := &gost.Server{}
	ln, err := gost.TCPListener(":11800")
	if err != nil {
		log.Fatal(err)
	}
	h := gost.TCPForwardHandler(
		"localhost:22",
		gost.ChainHandlerOption(chain),
	)
	log.Fatal(s.Serve(ln, h))
}
