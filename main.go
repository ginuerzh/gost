// main
package main

import (
	"flag"
	"github.com/ginuerzh/gosocks5"
	"log"
	"time"
)

var (
	Laddr, Saddr, Proxy string
	Shadows             bool
	SMethod, SPassword  string
	Method, Password    string
	CertFile, KeyFile   string
)

func init() {
	flag.StringVar(&Proxy, "P", "", "proxy for forward")
	flag.StringVar(&Saddr, "S", "", "the server that connecting to")
	flag.StringVar(&Laddr, "L", ":8080", "listen address")
	flag.StringVar(&Method, "m", "tls", "tunnel cipher method")
	flag.StringVar(&Password, "p", "ginuerzh@gmail.com", "tunnel cipher password")
	flag.StringVar(&CertFile, "cert", "cert.pem", "cert.pem file for tls")
	flag.StringVar(&KeyFile, "key", "key.pem", "key.pem file for tls")
	flag.BoolVar(&Shadows, "ss", false, "run as shadowsocks server")
	flag.StringVar(&SMethod, "sm", "rc4-md5", "shadowsocks cipher method")
	flag.StringVar(&SPassword, "sp", "ginuerzh@gmail.com", "shadowsocks cipher password")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

var (
	spool = NewMemPool(1024, 120*time.Minute, 1024)  // 1k size buffer pool
	mpool = NewMemPool(16*1024, 60*time.Minute, 512) // 16k size buffer pool
	lpool = NewMemPool(32*1024, 30*time.Minute, 256) // 32k size buffer pool
)

func main() {
	//log.Fatal(gost.Run())
	if len(Saddr) == 0 {
		srv := &gosocks5.Server{
			Addr:           Laddr,
			SelectMethod:   selectMethod,
			MethodSelected: methodSelected,
			Handle:         srvHandle,
		}
		log.Fatal(srv.ListenAndServe())
		return
	}

	log.Fatal(listenAndServe(Laddr, cliHandle))
}
