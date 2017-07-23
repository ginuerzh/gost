package main

import (
	"crypto/tls"
	"log"

	"net/url"

	"github.com/ginuerzh/gost/gost"
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	gost.Debug = true
}

func main() {
	go httpServer()
	go socks5Server()
	go tlsServer()
	go shadowServer()
	go wsServer()
	go wssServer()
	go kcpServer()
	go tcpForwardServer()
	go rtcpForwardServer()
	// go rudpForwardServer()
	go tcpRedirectServer()

	select {}
}

func httpServer() {
	s := &gost.Server{}
	s.Handle(gost.HTTPHandler(
		gost.UsersHandlerOption(url.UserPassword("admin", "123456")),
	))
	ln, err := gost.TCPListener(":8080")
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(s.Serve(ln))
}

func socks5Server() {
	cert, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
	if err != nil {
		log.Fatal(err)
	}

	s := &gost.Server{}
	s.Handle(gost.SOCKS5Handler(
		gost.UsersHandlerOption(url.UserPassword("admin", "123456")),
		gost.TLSConfigHandlerOption(&tls.Config{Certificates: []tls.Certificate{cert}}),
	))
	ln, err := gost.TCPListener(":1080")
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
	ln, err := gost.TCPListener(":8338")
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
	cert, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
	if err != nil {
		log.Fatal(err)
	}
	ln, err := gost.TLSListener(":1443", &tls.Config{Certificates: []tls.Certificate{cert}})
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
	ln, err := gost.WSListener(":8000", nil)
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

	cert, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
	if err != nil {
		log.Fatal(err)
	}
	ln, err := gost.WSSListener(":8443", &gost.WSOptions{TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}}})
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(s.Serve(ln))
}

func kcpServer() {
	s := &gost.Server{}
	s.Handle(gost.HTTPHandler())
	ln, err := gost.KCPListener(":8388", nil)
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
