package main

import (
	"bufio"
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
		/*
			// http+ws
			gost.Node{
				Addr: "127.0.0.1:8000",
				Client: gost.NewClient(
					gost.HTTPConnector(url.UserPassword("admin", "123456")),
					gost.WSTransporter("127.0.0.1:8000", nil),
				),
			},
		*/

		// http+wss
		gost.Node{
			Addr: "127.0.0.1:8443",
			Client: gost.NewClient(
				gost.HTTPConnector(url.UserPassword("admin", "123456")),
				gost.WSSTransporter(
					"127.0.0.1:8443",
					&gost.WSOptions{TLSConfig: &tls.Config{InsecureSkipVerify: true}},
				),
			),
		},
	/*
		// http+tcp
		gost.Node{
			Addr: "127.0.0.1:1080",
			Client: gost.NewClient(
				gost.HTTPConnector(url.UserPassword("admin", "123456")),
				gost.TCPTransporter(),
			),
		},
	*/

	/*
		// http+tls
		gost.Node{
			Addr: "127.0.0.1:1443",
			Client: gost.NewClient(
				gost.HTTPConnector(url.UserPassword("admin", "123456")),
				gost.TLSTransporter(&tls.Config{InsecureSkipVerify: true}),
			),
		},
	*/

	/*
		// ss+tcp
		gost.Node{
			Addr: "127.0.0.1:8338",
			Client: gost.NewClient(
				gost.ShadowConnector(url.UserPassword("chacha20", "123456")),
				gost.TCPTransporter(),
			),
		},
	*/
	)
	conn, err := chain.Dial("localhost:10000")
	if err != nil {
		log.Fatal(err)
	}
	//conn = tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	req, err := http.NewRequest(http.MethodGet, "http://localhost:10000/pkg", nil)
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
