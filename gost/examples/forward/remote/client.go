package main

import (
	"log"

	"github.com/ginuerzh/gost/gost"
)

func main() {
	sshRemoteForward()
}

func sshRemoteForward() {
	chain := gost.NewChain(
		gost.Node{
			Protocol:  "forward",
			Transport: "ssh",
			Addr:      "localhost:11222",
			Client: &gost.Client{
				Connector:   gost.SSHRemoteForwardConnector(),
				Transporter: gost.SSHForwardTransporter(),
			},
		},
	)

	s := &gost.Server{}
	ln, err := gost.TCPRemoteForwardListener(":11800", chain)
	if err != nil {
		log.Fatal(err)
	}
	h := gost.TCPRemoteForwardHandler(
		"localhost:10000",
	)
	log.Fatal(s.Serve(ln, h))
}
