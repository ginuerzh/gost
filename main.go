// main
package main

import (
	"flag"
	//"github.com/ginuerzh/gosocks5"
	"log"
	"time"
)

var (
	Laddr, Saddr, Proxy string
	Websocket           bool
	Shadows             bool
	SMethod, SPassword  string
	Method, Password    string
	CertFile, KeyFile   string
	PrintVersion        bool
)

func init() {
	flag.StringVar(&Proxy, "P", "", "proxy for forward")
	flag.StringVar(&Saddr, "S", "", "the server that connect to")
	flag.StringVar(&Laddr, "L", ":8080", "listen address")
	flag.StringVar(&Method, "m", "", "tunnel cipher method")
	flag.StringVar(&Password, "p", "", "tunnel cipher password")
	flag.StringVar(&CertFile, "cert", "", "cert file for tls")
	flag.StringVar(&KeyFile, "key", "", "key file for tls")
	flag.BoolVar(&Shadows, "ss", false, "run as shadowsocks server")
	flag.BoolVar(&Websocket, "ws", false, "use websocket for tunnel")
	flag.StringVar(&SMethod, "sm", "rc4-md5", "shadowsocks cipher method")
	flag.StringVar(&SPassword, "sp", "ginuerzh@gmail.com", "shadowsocks cipher password")
	flag.BoolVar(&PrintVersion, "v", false, "print version")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

var (
	spool = NewMemPool(1024, 120*time.Minute, 1024)  // 1k size buffer pool
	mpool = NewMemPool(16*1024, 60*time.Minute, 512) // 16k size buffer pool
	lpool = NewMemPool(32*1024, 30*time.Minute, 256) // 32k size buffer pool
)

func main() {
	if PrintVersion {
		printVersion()
		return
	}

	if len(Saddr) == 0 {
		var server Server
		if Websocket {
			server = &WSServer{Addr: Laddr}
		} else {
			server = &Socks5Server{Addr: Laddr}
		}
		log.Fatal(server.ListenAndServe())
		return
	}

	log.Fatal(listenAndServe(Laddr, cliHandle))
}
