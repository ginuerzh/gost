// main
package main

import (
	"flag"
	//"github.com/ginuerzh/gosocks5"
	"log"
	"net/url"
	"strings"
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
	Filter                string

	proxyURL *url.URL
	filters  []string
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
	flag.StringVar(&Filter, "f", "", "comma separated host/url wildcard not go through tunnel")
	flag.BoolVar(&PrintVersion, "v", false, "print version")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lshortfile)

	proxyURL, _ = parseURL(Proxy)
	filters = parseFilter(Filter)
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
		if UseWebsocket {
			server = &WSServer{Addr: Laddr}
		} else if UseHttp {
			server = &HttpServer{Addr: Laddr}
		} else {
			server = &Socks5Server{Addr: Laddr}
		}
		log.Fatal(server.ListenAndServe())
		return
	}

	log.Fatal(listenAndServe(Laddr, cliHandle))
}

func parseURL(rawurl string) (*url.URL, error) {
	if len(rawurl) == 0 {
		return nil, nil
	}
	if !strings.HasPrefix(rawurl, "http://") &&
		!strings.HasPrefix(rawurl, "socks://") {
		rawurl = "http://" + rawurl
	}
	return url.Parse(rawurl)
}

func parseFilter(rawfilter string) (filters []string) {
	for _, s := range strings.Split(rawfilter, ",") {
		s = strings.TrimSpace(s)
		if len(s) > 0 {
			filters = append(filters)
		}
	}
	return
}
