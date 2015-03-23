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
	flag.BoolVar(&gost.Cipher, "cipher", true, "cipher transfer data")
	flag.BoolVar(&gost.Shadows, "ss", false, "shadowsocks compatible")
	flag.BoolVar(&Debug, "d", false, "debug option")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

func main() {
	log.Fatal(gost.Run())
}
