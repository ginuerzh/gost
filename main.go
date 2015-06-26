// main
package main

import (
	"flag"
	"log"
	"net/url"
	"time"
)

var (
	Laddr, Saddr, Proxy   string
	UseWebsocket, UseHttp bool
	Shadows               bool
	SMethod, SPassword    string
	Method, Password      string
	CertFile, KeyFile     string
	PrintVersion          bool

	proxyURL  *url.URL
	listenUrl *url.URL
)

func init() {
	flag.StringVar(&Proxy, "P", "", "proxy for forward")
	flag.StringVar(&Saddr, "S", "", "the server that connect to")
	flag.StringVar(&Laddr, "L", ":8080", "listen address")
	flag.StringVar(&Method, "m", "", "tunnel cipher method")
	flag.StringVar(&Password, "p", "", "tunnel cipher password")
	flag.StringVar(&CertFile, "cert", "", "tls cert file")
	flag.StringVar(&KeyFile, "key", "", "tls key file")
	flag.BoolVar(&Shadows, "ss", false, "run as shadowsocks server")
	flag.BoolVar(&UseWebsocket, "ws", false, "use websocket tunnel")
	flag.BoolVar(&UseHttp, "http", false, "use http tunnel")
	flag.StringVar(&SMethod, "sm", "rc4-md5", "shadowsocks cipher method")
	flag.StringVar(&SPassword, "sp", "ginuerzh@gmail.com", "shadowsocks cipher password")
	flag.BoolVar(&PrintVersion, "v", false, "print version")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lshortfile)

	proxyURL, _ = parseURL(Proxy)
	listenUrl, _ = parseURL(Laddr)
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

	laddr := listenUrl.Host

	if len(Saddr) == 0 {
		var server Server
		if UseWebsocket {
			server = &WSServer{Addr: laddr}
		} else if UseHttp {
			server = &HttpServer{Addr: laddr}
		} else {
			server = &Socks5Server{Addr: laddr}
		}
		log.Fatal(server.ListenAndServe())
		return
	}

	log.Fatal(listenAndServe(laddr, cliHandle))
}
