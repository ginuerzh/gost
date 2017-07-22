package main

import (
	"crypto/tls"
	"log"

	"net/url"

	"sync"

	"github.com/ginuerzh/gost/gost"
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	gost.Debug = true
}

func main() {
	wg := sync.WaitGroup{}
	wg.Add(1)
	go httpServer(&wg)
	wg.Add(1)
	go tlsServer(&wg)
	wg.Add(1)
	go shadowServer(&wg)
	wg.Add(1)
	go wsServer(&wg)
	wg.Add(1)
	go wssServer(&wg)
	wg.Wait()
}

func httpServer(wg *sync.WaitGroup) {
	defer wg.Done()

	s := &gost.Server{}
	s.Handle(gost.HTTPHandler(
		gost.UsersHandlerOption(url.UserPassword("admin", "123456")),
	))
	ln, err := gost.TCPListener(":1080")
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(s.Serve(ln))
}

func tlsServer(wg *sync.WaitGroup) {
	defer wg.Done()

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

func wsServer(wg *sync.WaitGroup) {
	defer wg.Done()

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

func wssServer(wg *sync.WaitGroup) {
	defer wg.Done()

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

func shadowServer(wg *sync.WaitGroup) {
	defer wg.Done()

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
