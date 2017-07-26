package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net/url"

	"github.com/ginuerzh/gost/gost"
)

var (
	quiet bool
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	flag.BoolVar(&quiet, "q", false, "quiet mode")
	flag.BoolVar(&gost.Debug, "d", false, "debug mode")
	flag.Parse()

	if quiet {
		gost.SetLogger(&gost.NopLogger{})
	}
}

func main() {
	go httpServer()
	go socks5Server()
	go tlsServer()
	go shadowServer()
	go wsServer()
	go wssServer()
	go kcpServer()
	// go tcpForwardServer()
	// go rtcpForwardServer()
	// go rudpForwardServer()
	// go tcpRedirectServer()
	// go http2Server()

	select {}
}

func httpServer() {
	s := &gost.Server{}
	s.Handle(gost.HTTPHandler(
		gost.UsersHandlerOption(url.UserPassword("admin", "123456")),
	))
	ln, err := gost.TCPListener(":18080")
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(s.Serve(ln))
}

func socks5Server() {
	s := &gost.Server{}
	s.Handle(gost.SOCKS5Handler(
		gost.UsersHandlerOption(url.UserPassword("admin", "123456")),
		gost.TLSConfigHandlerOption(tlsConfig()),
	))
	ln, err := gost.TCPListener(":11080")
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(s.Serve(ln))
}

func shadowServer() {
	s := &gost.Server{}
	s.Handle(gost.ShadowHandler(
		gost.UsersHandlerOption(url.UserPassword("chacha20", "123456")),
	))
	ln, err := gost.TCPListener(":18338")
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(s.Serve(ln))
}

func tlsServer() {
	s := &gost.Server{}
	s.Handle(gost.HTTPHandler(
		gost.UsersHandlerOption(url.UserPassword("admin", "123456")),
	))
	ln, err := gost.TLSListener(":11443", tlsConfig())
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(s.Serve(ln))
}

func wsServer() {
	s := &gost.Server{}
	s.Handle(gost.HTTPHandler(
		gost.UsersHandlerOption(url.UserPassword("admin", "123456")),
	))
	ln, err := gost.WSListener(":18000", nil)
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(s.Serve(ln))
}

func wssServer() {
	s := &gost.Server{}
	s.Handle(gost.HTTPHandler(
		gost.UsersHandlerOption(url.UserPassword("admin", "123456")),
	))
	ln, err := gost.WSSListener(":18443", &gost.WSOptions{TLSConfig: tlsConfig()})
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(s.Serve(ln))
}

func kcpServer() {
	s := &gost.Server{}
	s.Handle(gost.HTTPHandler())
	ln, err := gost.KCPListener(":18388", nil)
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(s.Serve(ln))
}

func tcpForwardServer() {
	s := &gost.Server{}
	s.Handle(gost.TCPForwardHandler("ginuerzh.xyz:22"))
	ln, err := gost.TCPListener(":2222")
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(s.Serve(ln))
}

func rtcpForwardServer() {
	s := &gost.Server{}
	s.Handle(gost.RTCPForwardHandler(":1222", "ginuerzh.xyz:22"))
	ln, err := gost.RTCPForwardListener(
		":1222",
		gost.NewChain(
			gost.Node{
				Protocol:  "socks5",
				Transport: "tcp",
				Addr:      "localhost:12345",
				User:      url.UserPassword("admin", "123456"),
				Client: gost.NewClient(
					gost.SOCKS5Connector(url.UserPassword("admin", "123456")),
					gost.TCPTransporter(),
				),
			},
		),
	)
	if err != nil {
		log.Fatal()
	}
	log.Fatal(s.Serve(ln))
}

func rudpForwardServer() {
	s := &gost.Server{}
	s.Handle(gost.RUDPForwardHandler(":10053", "localhost:53"))
	ln, err := gost.RUDPForwardListener(
		":10053",
		gost.NewChain(
			gost.Node{
				Protocol:  "socks5",
				Transport: "tcp",
				Addr:      "localhost:12345",
				User:      url.UserPassword("admin", "123456"),
				Client: gost.NewClient(
					gost.SOCKS5Connector(url.UserPassword("admin", "123456")),
					gost.TCPTransporter(),
				),
			},
		),
	)
	if err != nil {
		log.Fatal()
	}
	log.Fatal(s.Serve(ln))
}

func tcpRedirectServer() {
	s := &gost.Server{}
	s.Handle(gost.TCPRedirectHandler())
	ln, err := gost.TCPListener(":8008")
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(s.Serve(ln))
}

func http2Server() {
	// http2.VerboseLogs = true

	s := &gost.Server{}
	s.Handle(gost.HTTP2Handler(
		gost.UsersHandlerOption(url.UserPassword("admin", "123456")),
	))
	ln, err := gost.TLSListener(":1443", tlsConfig()) // HTTP2 h2 mode
	// ln, err := gost.TCPListener(":1443") // HTTP2 h2c mode
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(s.Serve(ln))
}

func tlsConfig() *tls.Config {
	cert, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
	if err != nil {
		panic(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}}
}
