// main
package main

import (
	"flag"
	"log"
)

var gost Gost

func init() {
	flag.StringVar(&gost.Proxy, "P", "", "proxy for forward")
	flag.StringVar(&gost.Saddr, "S", "", "the server that connecting to")
	flag.StringVar(&gost.Laddr, "L", ":8080", "listen address")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

func main() {
	log.Fatal(gost.Run())
}
