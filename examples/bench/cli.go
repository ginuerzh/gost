package main

import (
	"bufio"
	"flag"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"

	"github.com/tongsq/gost"
	"golang.org/x/net/http2"
)

var (
	requests, concurrency int
	quiet                 bool
	swg, ewg              sync.WaitGroup
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	flag.IntVar(&requests, "n", 1, "Number of requests to perform")
	flag.IntVar(&concurrency, "c", 1, "Number of multiple requests to make at a time")
	flag.BoolVar(&quiet, "q", false, "quiet mode")
	flag.BoolVar(&http2.VerboseLogs, "v", false, "HTTP2 verbose logs")
	flag.BoolVar(&gost.Debug, "d", false, "debug mode")
	flag.Parse()

	if quiet {
		gost.SetLogger(&gost.NopLogger{})
	}
}

func main() {
	chain := gost.NewChain(

		/*
			// http+tcp
			gost.Node{
				Addr: "127.0.0.1:18080",
				Client: gost.NewClient(
					gost.HTTPConnector(url.UserPassword("admin", "123456")),
					gost.TCPTransporter(),
				),
			},
		*/

		/*
			// socks5+tcp
			gost.Node{
				Addr: "127.0.0.1:11080",
				Client: gost.NewClient(
					gost.SOCKS5Connector(url.UserPassword("admin", "123456")),
					gost.TCPTransporter(),
				),
			},
		*/

		/*
			// ss+tcp
			gost.Node{
				Addr: "127.0.0.1:18338",
				Client: gost.NewClient(
					gost.ShadowConnector(url.UserPassword("chacha20", "123456")),
					gost.TCPTransporter(),
				),
			},
		*/

		/*
			// http+ws
			gost.Node{
				Addr: "127.0.0.1:18000",
				Client: gost.NewClient(
					gost.HTTPConnector(url.UserPassword("admin", "123456")),
					gost.WSTransporter(nil),
				),
			},
		*/

		/*
			// http+wss
			gost.Node{
				Addr: "127.0.0.1:18443",
				Client: gost.NewClient(
					gost.HTTPConnector(url.UserPassword("admin", "123456")),
					gost.WSSTransporter(nil),
				),
			},
		*/

		/*
			// http+tls
			gost.Node{
				Addr: "127.0.0.1:11443",
				Client: gost.NewClient(
					gost.HTTPConnector(url.UserPassword("admin", "123456")),
					gost.TLSTransporter(),
				),
			},
		*/

		/*
			// http2
			gost.Node{
				Addr: "127.0.0.1:1443",
				Client: &gost.Client{
					Connector:   gost.HTTP2Connector(url.UserPassword("admin", "123456")),
					Transporter: gost.HTTP2Transporter(nil),
				},
			},
		*/

		/*
			// http+kcp
			gost.Node{
				Addr: "127.0.0.1:18388",
				Client: gost.NewClient(
					gost.HTTPConnector(nil),
					gost.KCPTransporter(nil),
				),
			},
		*/

		/*
			// http+ssh
			gost.Node{
				Addr: "127.0.0.1:12222",
				Client: gost.NewClient(
					gost.HTTPConnector(url.UserPassword("admin", "123456")),
					gost.SSHTunnelTransporter(),
				),
			},
		*/

		/*
			// http+quic
			gost.Node{
				Addr: "localhost:6121",
				Client: &gost.Client{
					Connector:   gost.HTTPConnector(url.UserPassword("admin", "123456")),
					Transporter: gost.QUICTransporter(nil),
				},
			},
		*/
		// socks5+h2
		gost.Node{
			Addr: "localhost:8443",
			Client: &gost.Client{
				// Connector: gost.HTTPConnector(url.UserPassword("admin", "123456")),
				Connector: gost.SOCKS5Connector(url.UserPassword("admin", "123456")),
				// Transporter: gost.H2CTransporter(), // HTTP2 h2c mode
				Transporter: gost.H2Transporter(nil), // HTTP2 h2
			},
		},
	)

	total := 0
	for total < requests {
		if total+concurrency > requests {
			concurrency = requests - total
		}
		startChan := make(chan struct{})
		for i := 0; i < concurrency; i++ {
			swg.Add(1)
			ewg.Add(1)
			go request(chain, startChan)
		}

		start := time.Now()
		swg.Wait()       // wait for workers ready
		close(startChan) // start signal
		ewg.Wait()       // wait for workers done

		duration := time.Since(start)
		total += concurrency
		log.Printf("%d/%d/%d requests done (%v/%v)", total, requests, concurrency, duration, duration/time.Duration(concurrency))
	}
}

func request(chain *gost.Chain, start <-chan struct{}) {
	defer ewg.Done()

	swg.Done()
	<-start

	conn, err := chain.Dial("localhost:18888")
	if err != nil {
		log.Println(err)
		return
	}
	defer conn.Close()
	//conn = tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	req, err := http.NewRequest(http.MethodGet, "http://localhost:18888", nil)
	if err != nil {
		log.Println(err)
		return
	}
	if err := req.Write(conn); err != nil {
		log.Println(err)
		return
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		log.Println(err)
		return
	}
	defer resp.Body.Close()

	if gost.Debug {
		rb, _ := httputil.DumpRequest(req, true)
		log.Println(string(rb))
		rb, _ = httputil.DumpResponse(resp, true)
		log.Println(string(rb))
	}
}
