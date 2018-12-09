package gost

import (
	"crypto/rand"
	"net/http/httptest"
	"net/url"
	"testing"
)

func httpOverKCPRoundtrip(targetURL string, data []byte,
	clientInfo *url.Userinfo, serverInfo []*url.Userinfo) error {

	ln, err := KCPListener("localhost:0", nil)
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   HTTPConnector(clientInfo),
		Transporter: KCPTransporter(nil),
	}

	server := &Server{
		Listener: ln,
		Handler: HTTPHandler(
			UsersHandlerOption(serverInfo...),
		),
	}

	go server.Run()
	defer server.Close()

	return proxyRoundtrip(client, server, targetURL, data)
}

func TestHTTPOverKCP(t *testing.T) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	for i, tc := range httpProxyTests {
		err := httpOverKCPRoundtrip(httpSrv.URL, sendData, tc.cliUser, tc.srvUsers)
		if err == nil {
			if tc.errStr != "" {
				t.Errorf("#%d should failed with error %s", i, tc.errStr)
			}
		} else {
			if tc.errStr == "" {
				t.Errorf("#%d got error %v", i, err)
			}
			if err.Error() != tc.errStr {
				t.Errorf("#%d got error %v, want %v", i, err, tc.errStr)
			}
		}
	}
}

func BenchmarkHTTPOverKCP(b *testing.B) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	ln, err := KCPListener("", nil)
	if err != nil {
		b.Error(err)
	}
	b.Log(ln.Addr())
	client := &Client{
		Connector:   HTTPConnector(url.UserPassword("admin", "123456")),
		Transporter: KCPTransporter(nil),
	}

	server := &Server{
		Listener: ln,
		Handler: HTTPHandler(
			UsersHandlerOption(url.UserPassword("admin", "123456")),
		),
	}
	go server.Run()
	defer server.Close()

	for i := 0; i < b.N; i++ {
		if err := proxyRoundtrip(client, server, httpSrv.URL, sendData); err != nil {
			b.Error(err)
		}
	}
}

func BenchmarkHTTPOverKCPParallel(b *testing.B) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	ln, err := KCPListener("", nil)
	if err != nil {
		b.Error(err)
	}

	client := &Client{
		Connector:   HTTPConnector(url.UserPassword("admin", "123456")),
		Transporter: KCPTransporter(nil),
	}

	server := &Server{
		Listener: ln,
		Handler: HTTPHandler(
			UsersHandlerOption(url.UserPassword("admin", "123456")),
		),
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

func socks5OverKCPRoundtrip(targetURL string, data []byte,
	clientInfo *url.Userinfo, serverInfo []*url.Userinfo) error {

	ln, err := KCPListener("localhost:0", nil)
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   SOCKS5Connector(clientInfo),
		Transporter: KCPTransporter(nil),
	}

	server := &Server{
		Listener: ln,
		Handler: SOCKS5Handler(
			UsersHandlerOption(serverInfo...),
		),
	}

	go server.Run()
	defer server.Close()

	return proxyRoundtrip(client, server, targetURL, data)
}

func TestSOCKS5OverKCP(t *testing.T) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	for i, tc := range socks5ProxyTests {
		err := socks5OverKCPRoundtrip(httpSrv.URL, sendData,
			tc.cliUser,
			tc.srvUsers,
		)
		if err == nil {
			if !tc.pass {
				t.Errorf("#%d should failed", i)
			}
		} else {
			// t.Logf("#%d %v", i, err)
			if tc.pass {
				t.Errorf("#%d got error: %v", i, err)
			}
		}
	}
}

func socks4OverKCPRoundtrip(targetURL string, data []byte) error {
	ln, err := KCPListener("localhost:0", nil)
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   SOCKS4Connector(),
		Transporter: KCPTransporter(nil),
	}

	server := &Server{
		Listener: ln,
		Handler:  SOCKS4Handler(),
	}

	go server.Run()
	defer server.Close()

	return proxyRoundtrip(client, server, targetURL, data)
}

func TestSOCKS4OverKCP(t *testing.T) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	err := socks4OverKCPRoundtrip(httpSrv.URL, sendData)
	// t.Logf("#%d %v", i, err)
	if err != nil {
		t.Errorf("got error: %v", err)
	}
}

func socks4aOverKCPRoundtrip(targetURL string, data []byte) error {
	ln, err := KCPListener("localhost:0", nil)
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   SOCKS4AConnector(),
		Transporter: KCPTransporter(nil),
	}

	server := &Server{
		Listener: ln,
		Handler:  SOCKS4Handler(),
	}

	go server.Run()
	defer server.Close()

	return proxyRoundtrip(client, server, targetURL, data)
}

func TestSOCKS4AOverKCP(t *testing.T) {

	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	err := socks4aOverKCPRoundtrip(httpSrv.URL, sendData)
	// t.Logf("#%d %v", i, err)
	if err != nil {
		t.Errorf("got error: %v", err)
	}
}

func ssOverKCPRoundtrip(targetURL string, data []byte,
	clientInfo, serverInfo *url.Userinfo) error {

	ln, err := KCPListener("localhost:0", nil)
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   ShadowConnector(clientInfo),
		Transporter: KCPTransporter(nil),
	}

	server := &Server{
		Listener: ln,
		Handler: ShadowHandler(
			UsersHandlerOption(serverInfo),
		),
	}

	go server.Run()
	defer server.Close()

	return proxyRoundtrip(client, server, targetURL, data)
}

func TestSSOverKCP(t *testing.T) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	for i, tc := range ssProxyTests {
		err := ssOverKCPRoundtrip(httpSrv.URL, sendData,
			tc.clientCipher,
			tc.serverCipher,
		)
		if err == nil {
			if !tc.pass {
				t.Errorf("#%d should failed", i)
			}
		} else {
			// t.Logf("#%d %v", i, err)
			if tc.pass {
				t.Errorf("#%d got error: %v", i, err)
			}
		}
	}
}
