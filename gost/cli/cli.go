package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/ginuerzh/gost/gost"
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	gost.Debug = true
}

func main() {
	chain := gost.NewChain(
		gost.Node{
			Addr: "127.0.0.1:1080",
			Client: gost.NewClient(
				gost.HTTPConnector(url.UserPassword("admin", "123456")),
				gost.TCPTransporter(),
			),
		},
		gost.Node{
			Addr: "172.24.222.54:8338",
			Client: gost.NewClient(
				gost.ShadowConnector(url.UserPassword("chacha20", "123456")),
				gost.TCPTransporter(),
			),
		},
		gost.Node{
			Addr: "172.24.222.54:8080",
			Client: gost.NewClient(
				gost.SOCKS5Connector(url.UserPassword("cmdsh", "cmdsh123456")),
				gost.TCPTransporter(),
			),
		},
	)
	conn, err := chain.Dial(context.Background(), "baidu.com:443")
	if err != nil {
		log.Fatal(err)
	}
	conn = tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	req, err := http.NewRequest(http.MethodGet, "https://www.baidu.com", nil)
	if err != nil {
		log.Fatal(err)
	}
	if err := req.Write(conn); err != nil {
		log.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	rb, _ := httputil.DumpRequest(req, true)
	log.Println(string(rb))
	rb, _ = httputil.DumpResponse(resp, true)
	log.Println(string(rb))
}
