package gost

import (
	"crypto/rand"
	"net/http/httptest"
	"net/url"
	"testing"
)

func tcpDirectForwardRoundtrip(targetURL string, data []byte) error {
	ln, err := TCPListener("")
	if err != nil {
		return err
	}

	u, err := url.Parse(targetURL)
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   ForwardConnector(),
		Transporter: TCPTransporter(),
	}

	server := &Server{
		Listener: ln,
		Handler:  TCPDirectForwardHandler(u.Host),
	}

	go server.Run()
	defer server.Close()

	return proxyRoundtrip(client, server, targetURL, data)
}

func TestTCPDirectForward(t *testing.T) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	err := tcpDirectForwardRoundtrip(httpSrv.URL, sendData)
	if err != nil {
		t.Error(err)
	}
}

func BenchmarkTCPDirectForward(b *testing.B) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	ln, err := TCPListener("")
	if err != nil {
		b.Error(err)
	}

	client := &Client{
		Connector:   ForwardConnector(),
		Transporter: TCPTransporter(),
	}

	u, err := url.Parse(httpSrv.URL)
	if err != nil {
		b.Error(err)
	}
	server := &Server{
		Listener: ln,
		Handler:  TCPDirectForwardHandler(u.Host),
	}
	go server.Run()
	defer server.Close()

	for i := 0; i < b.N; i++ {
		if err := proxyRoundtrip(client, server, httpSrv.URL, sendData); err != nil {
			b.Error(err)
		}
	}
}

func BenchmarkTCPDirectForwardParallel(b *testing.B) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	ln, err := TCPListener("")
	if err != nil {
		b.Error(err)
	}

	client := &Client{
		Connector:   ForwardConnector(),
		Transporter: TCPTransporter(),
	}

	u, err := url.Parse(httpSrv.URL)
	if err != nil {
		b.Error(err)
	}
	server := &Server{
		Listener: ln,
		Handler:  TCPDirectForwardHandler(u.Host),
	}
	go server.Run()
	defer server.Close()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if err := proxyRoundtrip(client, server, httpSrv.URL, sendData); err != nil {
				b.Error(err)
			}
		}
	})
}

func udpDirectForwardRoundtrip(host string, data []byte) error {
	ln, err := UDPDirectForwardListener("localhost:0", 0)
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   ForwardConnector(),
		Transporter: UDPTransporter(),
	}

	server := &Server{
		Listener: ln,
		Handler:  UDPDirectForwardHandler(host),
	}

	go server.Run()
	defer server.Close()

	return udpRoundtrip(client, server, host, data)
}

func TestUDPDirectForward(t *testing.T) {
	udpSrv := newUDPTestServer(udpTestHandler)
	udpSrv.Start()
	defer udpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)
	err := udpDirectForwardRoundtrip(udpSrv.Addr(), sendData)
	if err != nil {
		t.Error(err)
	}
}

func BenchmarkUDPDirectForward(b *testing.B) {
	udpSrv := newUDPTestServer(udpTestHandler)
	udpSrv.Start()
	defer udpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	ln, err := UDPDirectForwardListener("localhost:0", 0)
	if err != nil {
		b.Error(err)
	}

	client := &Client{
		Connector:   ForwardConnector(),
		Transporter: UDPTransporter(),
	}

	server := &Server{
		Listener: ln,
		Handler:  UDPDirectForwardHandler(udpSrv.Addr()),
	}

	go server.Run()
	defer server.Close()

	for i := 0; i < b.N; i++ {
		if err := udpRoundtrip(client, server, udpSrv.Addr(), sendData); err != nil {
			b.Error(err)
		}
	}
}

func BenchmarkUDPDirectForwardParallel(b *testing.B) {
	udpSrv := newUDPTestServer(udpTestHandler)
	udpSrv.Start()
	defer udpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	ln, err := UDPDirectForwardListener("localhost:0", 0)
	if err != nil {
		b.Error(err)
	}

	client := &Client{
		Connector:   ForwardConnector(),
		Transporter: UDPTransporter(),
	}

	server := &Server{
		Listener: ln,
		Handler:  UDPDirectForwardHandler(udpSrv.Addr()),
	}

	go server.Run()
	defer server.Close()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if err := udpRoundtrip(client, server, udpSrv.Addr(), sendData); err != nil {
				b.Error(err)
			}
		}
	})
}

func tcpRemoteForwardRoundtrip(t *testing.T, targetURL string, data []byte) error {
	ln, err := TCPRemoteForwardListener("localhost:0", nil) // listening on localhost
	if err != nil {
		return err
	}

	u, err := url.Parse(targetURL)
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   ForwardConnector(),
		Transporter: TCPTransporter(),
	}

	server := &Server{
		Listener: ln,
		Handler:  TCPRemoteForwardHandler(u.Host), // forward to u.Host
	}

	go server.Run()
	defer server.Close()

	return proxyRoundtrip(client, server, targetURL, data)
}

func TestTCPRemoteForward(t *testing.T) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	err := tcpRemoteForwardRoundtrip(t, httpSrv.URL, sendData)
	if err != nil {
		t.Error(err)
	}
}

func udpRemoteForwardRoundtrip(t *testing.T, host string, data []byte) error {
	ln, err := UDPRemoteForwardListener("localhost:0", nil, 0)
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   ForwardConnector(),
		Transporter: UDPTransporter(),
	}

	server := &Server{
		Listener: ln,
		Handler:  UDPRemoteForwardHandler(host),
	}

	go server.Run()
	defer server.Close()

	return udpRoundtrip(client, server, host, data)
}

func TestUDPRemoteForward(t *testing.T) {
	udpSrv := newUDPTestServer(udpTestHandler)
	udpSrv.Start()
	defer udpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	err := udpRemoteForwardRoundtrip(t, udpSrv.Addr(), sendData)
	if err != nil {
		t.Error(err)
	}
}
