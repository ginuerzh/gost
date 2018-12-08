package gost

import (
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"net/http/httptest"
	"net/url"
	"testing"
)

func httpOverTLSRoundtrip(targetURL string, data []byte, tlsConfig *tls.Config,
	clientInfo *url.Userinfo, serverInfo []*url.Userinfo) error {

	ln, err := TLSListener("", tlsConfig)
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   HTTPConnector(clientInfo),
		Transporter: TLSTransporter(),
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

func TestHTTPOverTLS(t *testing.T) {
	cert, err := GenCertificate()
	if err != nil {
		t.Error(err)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	for i, tc := range httpProxyTests {
		tc := tc
		t.Run(fmt.Sprintf("#%d", i), func(t *testing.T) {
			err := httpOverTLSRoundtrip(httpSrv.URL, sendData, tlsConfig, tc.cliUser, tc.srvUsers)
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

func BenchmarkHTTPOverTLS(b *testing.B) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	cert, err := GenCertificate()
	if err != nil {
		b.Error(err)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	ln, err := TLSListener("", tlsConfig)
	if err != nil {
		b.Error(err)
	}

	client := &Client{
		Connector:   HTTPConnector(url.UserPassword("admin", "123456")),
		Transporter: TLSTransporter(),
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

func BenchmarkHTTPOverTLSParallel(b *testing.B) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	cert, err := GenCertificate()
	if err != nil {
		b.Error(err)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	ln, err := TLSListener("", tlsConfig)
	if err != nil {
		b.Error(err)
	}

	client := &Client{
		Connector:   HTTPConnector(url.UserPassword("admin", "123456")),
		Transporter: TLSTransporter(),
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

func socks5OverTLSRoundtrip(targetURL string, data []byte, tlsConfig *tls.Config,
	clientInfo *url.Userinfo, serverInfo []*url.Userinfo) error {

	ln, err := TLSListener("", tlsConfig)
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   SOCKS5Connector(clientInfo),
		Transporter: TLSTransporter(),
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

func TestSOCKS5OverTLS(t *testing.T) {
	cert, err := GenCertificate()
	if err != nil {
		t.Error(err)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	DefaultTLSConfig = tlsConfig

	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	for i, tc := range socks5ProxyTests {
		tc := tc
		t.Run(fmt.Sprintf("#%d", i), func(t *testing.T) {
			err := socks5OverTLSRoundtrip(httpSrv.URL, sendData,
				tlsConfig,
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

func socks4OverTLSRoundtrip(targetURL string, data []byte, tlsConfig *tls.Config) error {
	ln, err := TLSListener("", tlsConfig)
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   SOCKS4Connector(),
		Transporter: TLSTransporter(),
	}

	server := &Server{
		Listener: ln,
		Handler:  SOCKS4Handler(),
	}

	go server.Run()
	defer server.Close()

	return proxyRoundtrip(client, server, targetURL, data)
}

func TestSOCKS4OverTLS(t *testing.T) {
	cert, err := GenCertificate()
	if err != nil {
		t.Error(err)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	err = socks4OverTLSRoundtrip(httpSrv.URL, sendData, tlsConfig)
	// t.Logf("#%d %v", i, err)
	if err != nil {
		t.Errorf("got error: %v", err)
	}
}

func socks4aOverTLSRoundtrip(targetURL string, data []byte, tlsConfig *tls.Config) error {
	ln, err := TLSListener("", tlsConfig)
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   SOCKS4AConnector(),
		Transporter: TLSTransporter(),
	}

	server := &Server{
		Listener: ln,
		Handler:  SOCKS4Handler(),
	}

	go server.Run()
	defer server.Close()

	return proxyRoundtrip(client, server, targetURL, data)
}

func TestSOCKS4AOverTLS(t *testing.T) {
	cert, err := GenCertificate()
	if err != nil {
		t.Error(err)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	err = socks4aOverTLSRoundtrip(httpSrv.URL, sendData, tlsConfig)
	// t.Logf("#%d %v", i, err)
	if err != nil {
		t.Errorf("got error: %v", err)
	}
}

func ssOverTLSRoundtrip(targetURL string, data []byte, tlsConfig *tls.Config,
	clientInfo, serverInfo *url.Userinfo) error {

	ln, err := TLSListener("", tlsConfig)
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   ShadowConnector(clientInfo),
		Transporter: TLSTransporter(),
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

func TestSSOverTLS(t *testing.T) {
	cert, err := GenCertificate()
	if err != nil {
		t.Error(err)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	DefaultTLSConfig = tlsConfig

	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	for i, tc := range ssProxyTests {
		tc := tc
		t.Run(fmt.Sprintf("#%d", i), func(t *testing.T) {
			err := ssOverTLSRoundtrip(httpSrv.URL, sendData,
				tlsConfig,
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
