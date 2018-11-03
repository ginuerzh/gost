package main

import (
	"log"

	"github.com/ginuerzh/gost"
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

	ln, err := gost.TCPListener(":11800")
	if err != nil {
		log.Fatal(err)
	}
	h := gost.TCPDirectForwardHandler(
		"localhost:22",
		gost.ChainHandlerOption(chain),
	)
	s := &gost.Server{ln}
	log.Fatal(s.Serve(h))
}
