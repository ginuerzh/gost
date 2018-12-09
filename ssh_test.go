package gost

import (
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"net/http/httptest"
	"net/url"
	"testing"
)

func httpOverSSHTunnelRoundtrip(targetURL string, data []byte, tlsConfig *tls.Config,
	clientInfo *url.Userinfo, serverInfo []*url.Userinfo) error {

	ln, err := SSHTunnelListener("", nil)
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   HTTPConnector(clientInfo),
		Transporter: SSHTunnelTransporter(),
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

func TestHTTPOverSSHTunnel(t *testing.T) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	for i, tc := range httpProxyTests {
		tc := tc
		t.Run(fmt.Sprintf("#%d", i), func(t *testing.T) {
			err := httpOverSSHTunnelRoundtrip(httpSrv.URL, sendData, nil, tc.cliUser, tc.srvUsers)
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
		})
	}
}

func BenchmarkHTTPOverSSHTunnel(b *testing.B) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	ln, err := SSHTunnelListener("", nil)
	if err != nil {
		b.Error(err)
	}

	client := &Client{
		Connector:   HTTPConnector(url.UserPassword("admin", "123456")),
		Transporter: SSHTunnelTransporter(),
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

func BenchmarkHTTPOverSSHTunnelParallel(b *testing.B) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	ln, err := SSHTunnelListener("", nil)
	if err != nil {
		b.Error(err)
	}

	client := &Client{
		Connector:   HTTPConnector(url.UserPassword("admin", "123456")),
		Transporter: SSHTunnelTransporter(),
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

func socks5OverSSHTunnelRoundtrip(targetURL string, data []byte, tlsConfig *tls.Config,
	clientInfo *url.Userinfo, serverInfo []*url.Userinfo) error {

	ln, err := SSHTunnelListener("", nil)
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   SOCKS5Connector(clientInfo),
		Transporter: SSHTunnelTransporter(),
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

func TestSOCKS5OverSSHTunnel(t *testing.T) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	for i, tc := range socks5ProxyTests {
		tc := tc
		t.Run(fmt.Sprintf("#%d", i), func(t *testing.T) {
			err := socks5OverSSHTunnelRoundtrip(httpSrv.URL, sendData,
				nil,
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
		})
	}
}

func socks4OverSSHTunnelRoundtrip(targetURL string, data []byte, tlsConfig *tls.Config) error {
	ln, err := SSHTunnelListener("", nil)
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   SOCKS4Connector(),
		Transporter: SSHTunnelTransporter(),
	}

	server := &Server{
		Listener: ln,
		Handler:  SOCKS4Handler(),
	}

	go server.Run()
	defer server.Close()

	return proxyRoundtrip(client, server, targetURL, data)
}

func TestSOCKS4OverSSHTunnel(t *testing.T) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	err := socks4OverSSHTunnelRoundtrip(httpSrv.URL, sendData, nil)
	// t.Logf("#%d %v", i, err)
	if err != nil {
		t.Errorf("got error: %v", err)
	}
}

func socks4aOverSSHTunnelRoundtrip(targetURL string, data []byte, tlsConfig *tls.Config) error {
	ln, err := SSHTunnelListener("", nil)
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   SOCKS4AConnector(),
		Transporter: SSHTunnelTransporter(),
	}

	server := &Server{
		Listener: ln,
		Handler:  SOCKS4Handler(),
	}

	go server.Run()
	defer server.Close()

	return proxyRoundtrip(client, server, targetURL, data)
}

func TestSOCKS4AOverSSHTunnel(t *testing.T) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	err := socks4aOverSSHTunnelRoundtrip(httpSrv.URL, sendData, nil)
	// t.Logf("#%d %v", i, err)
	if err != nil {
		t.Errorf("got error: %v", err)
	}
}

func ssOverSSHTunnelRoundtrip(targetURL string, data []byte, tlsConfig *tls.Config,
	clientInfo, serverInfo *url.Userinfo) error {

	ln, err := SSHTunnelListener("", nil)
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   ShadowConnector(clientInfo),
		Transporter: SSHTunnelTransporter(),
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

func TestSSOverSSHTunnel(t *testing.T) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	for i, tc := range ssProxyTests {
		tc := tc
		t.Run(fmt.Sprintf("#%d", i), func(t *testing.T) {
			err := ssOverSSHTunnelRoundtrip(httpSrv.URL, sendData,
				nil,
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
		})
	}
}
