// main
package main

import (
	"flag"
	"github.com/ginuerzh/gosocks5"
	"log"
)

var (
	Laddr, Saddr, Proxy string
	Shadows             bool
	Cipher, Password    string
)

func init() {
	flag.StringVar(&Proxy, "P", "", "proxy for forward")
	flag.StringVar(&Saddr, "S", "", "the server that connecting to")
	flag.StringVar(&Laddr, "L", ":8080", "listen address")
	flag.StringVar(&Cipher, "cipher", "rc4-md5", "cipher method")
	flag.StringVar(&Password, "password", "ginuerzh@gmail.com", "cipher password")
	flag.BoolVar(&Shadows, "ss", false, "shadowsocks compatible")
	flag.BoolVar(&Debug, "d", false, "debug option")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

func main() {
	//log.Fatal(gost.Run())
	if len(Saddr) == 0 {
		srv := &gosocks5.Server{
			Addr:         Laddr,
			SelectMethod: selectMethod,
			Handle:       srvHandle,
		}
		log.Fatal(srv.ListenAndServe())
		return
	}

	log.Fatal(listenAndServe(Laddr, cliHandle))
}
