package main

import (
	"flag"
	"log"

	"github.com/ginuerzh/gost/gost"
)

var (
	laddr, faddr string
	quiet        bool
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	flag.StringVar(&laddr, "L", ":18080", "listen address")
	flag.StringVar(&faddr, "F", ":12222", "forward address")
	flag.BoolVar(&quiet, "q", false, "quiet mode")
	flag.BoolVar(&gost.Debug, "d", false, "debug mode")
	flag.Parse()

	if quiet {
		gost.SetLogger(&gost.NopLogger{})
	}
}

func main() {
	chain := gost.NewChain(
		gost.Node{
			Addr: faddr,
			Client: gost.NewClient(
				gost.HTTPConnector(nil),
				gost.SSHTunnelTransporter(),
			),
		},
	)

	s := &gost.Server{}
	s.Handle(gost.SOCKS5Handler(gost.ChainHandlerOption(chain)))
	ln, err := gost.TCPListener(laddr)
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(s.Serve(ln))
}
