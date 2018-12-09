package gost

import (
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"net/http/httptest"
	"net/url"
	"testing"
)

func http2ProxyRoundtrip(targetURL string, data []byte, clientInfo *url.Userinfo, serverInfo []*url.Userinfo) error {
	ln, err := HTTP2Listener("", nil)
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   HTTP2Connector(clientInfo),
		Transporter: HTTP2Transporter(nil),
	}

	server := &Server{
		Listener: ln,
		Handler: HTTP2Handler(
			UsersHandlerOption(serverInfo...),
		),
	}

	go server.Run()
	defer server.Close()

	return proxyRoundtrip(client, server, targetURL, data)
}

func TestHTTP2Proxy(t *testing.T) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	for i, tc := range httpProxyTests {
		tc := tc
		t.Run(fmt.Sprintf("#%d", i), func(t *testing.T) {
			err := http2ProxyRoundtrip(httpSrv.URL, sendData, tc.cliUser, tc.srvUsers)
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

func BenchmarkHTTP2Proxy(b *testing.B) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	ln, err := HTTP2Listener("", nil)
	if err != nil {
		b.Error(err)
	}

	client := &Client{
		Connector:   HTTP2Connector(url.UserPassword("admin", "123456")),
		Transporter: HTTP2Transporter(nil),
	}

	server := &Server{
		Listener: ln,
		Handler: HTTP2Handler(
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

func BenchmarkHTTP2ProxyParallel(b *testing.B) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	ln, err := HTTP2Listener("", nil)
	if err != nil {
		b.Error(err)
	}

	client := &Client{
		Connector:   HTTP2Connector(url.UserPassword("admin", "123456")),
		Transporter: HTTP2Transporter(nil),
	}

	server := &Server{
		Listener: ln,
		Handler: HTTP2Handler(
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

func httpOverH2Roundtrip(targetURL string, data []byte, tlsConfig *tls.Config,
	clientInfo *url.Userinfo, serverInfo []*url.Userinfo) error {

	ln, err := H2Listener("", tlsConfig)
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   HTTPConnector(clientInfo),
		Transporter: H2Transporter(nil),
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

func TestHTTPOverH2(t *testing.T) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	for i, tc := range httpProxyTests {
		tc := tc
		t.Run(fmt.Sprintf("#%d", i), func(t *testing.T) {
			err := httpOverH2Roundtrip(httpSrv.URL, sendData, nil, tc.cliUser, tc.srvUsers)
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

func BenchmarkHTTPOverH2(b *testing.B) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	ln, err := H2Listener("", nil)
	if err != nil {
		b.Error(err)
	}

	client := &Client{
		Connector:   HTTPConnector(url.UserPassword("admin", "123456")),
		Transporter: H2Transporter(nil),
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

func BenchmarkHTTPOverH2Parallel(b *testing.B) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	ln, err := H2Listener("", nil)
	if err != nil {
		b.Error(err)
	}

	client := &Client{
		Connector:   HTTPConnector(url.UserPassword("admin", "123456")),
		Transporter: H2Transporter(nil),
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

func socks5OverH2Roundtrip(targetURL string, data []byte, tlsConfig *tls.Config,
	clientInfo *url.Userinfo, serverInfo []*url.Userinfo) error {

	ln, err := H2Listener("", tlsConfig)
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   SOCKS5Connector(clientInfo),
		Transporter: H2Transporter(nil),
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

func TestSOCKS5OverH2(t *testing.T) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	for i, tc := range socks5ProxyTests {
		tc := tc
		t.Run(fmt.Sprintf("#%d", i), func(t *testing.T) {
			err := socks5OverH2Roundtrip(httpSrv.URL, sendData,
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

func socks4OverH2Roundtrip(targetURL string, data []byte, tlsConfig *tls.Config) error {
	ln, err := H2Listener("", tlsConfig)
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   SOCKS4Connector(),
		Transporter: H2Transporter(nil),
	}

	server := &Server{
		Listener: ln,
		Handler:  SOCKS4Handler(),
	}

	go server.Run()
	defer server.Close()

	return proxyRoundtrip(client, server, targetURL, data)
}

func TestSOCKS4OverH2(t *testing.T) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	err := socks4OverH2Roundtrip(httpSrv.URL, sendData, nil)
	// t.Logf("#%d %v", i, err)
	if err != nil {
		t.Errorf("got error: %v", err)
	}
}

func socks4aOverH2Roundtrip(targetURL string, data []byte, tlsConfig *tls.Config) error {
	ln, err := H2Listener("", tlsConfig)
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   SOCKS4AConnector(),
		Transporter: H2Transporter(nil),
	}

	server := &Server{
		Listener: ln,
		Handler:  SOCKS4Handler(),
	}

	go server.Run()
	defer server.Close()

	return proxyRoundtrip(client, server, targetURL, data)
}

func TestSOCKS4AOverH2(t *testing.T) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	err := socks4aOverH2Roundtrip(httpSrv.URL, sendData, nil)
	// t.Logf("#%d %v", i, err)
	if err != nil {
		t.Errorf("got error: %v", err)
	}
}

func ssOverH2Roundtrip(targetURL string, data []byte, tlsConfig *tls.Config,
	clientInfo, serverInfo *url.Userinfo) error {

	ln, err := H2Listener("", tlsConfig)
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   ShadowConnector(clientInfo),
		Transporter: H2Transporter(nil),
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

func TestSSOverH2(t *testing.T) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	var ssProxyTests = []struct {
		clientCipher *url.Userinfo
		serverCipher *url.Userinfo
		pass         bool
	}{
		{nil, nil, false},
		{&url.Userinfo{}, &url.Userinfo{}, false},
		{url.User("abc"), url.User("abc"), false},
		{url.UserPassword("abc", "def"), url.UserPassword("abc", "def"), false},

		{url.User("aes-128-cfb"), url.User("aes-128-cfb"), false},
		{url.User("aes-128-cfb"), url.UserPassword("aes-128-cfb", "123456"), false},
		{url.UserPassword("aes-128-cfb", "123456"), url.User("aes-128-cfb"), false},
		{url.UserPassword("aes-128-cfb", "123456"), url.UserPassword("aes-128-cfb", "abc"), false},
		{url.UserPassword("aes-128-cfb", "123456"), url.UserPassword("aes-128-cfb", "123456"), true},
	}
	for i, tc := range ssProxyTests {
		tc := tc
		t.Run(fmt.Sprintf("#%d", i), func(t *testing.T) {
			err := ssOverH2Roundtrip(httpSrv.URL, sendData,
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

func httpOverH2CRoundtrip(targetURL string, data []byte,
	clientInfo *url.Userinfo, serverInfo []*url.Userinfo) error {

	ln, err := H2CListener("")
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   HTTPConnector(clientInfo),
		Transporter: H2CTransporter(),
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

func TestHTTPOverH2C(t *testing.T) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	for i, tc := range httpProxyTests {
		tc := tc
		t.Run(fmt.Sprintf("#%d", i), func(t *testing.T) {
			err := httpOverH2CRoundtrip(httpSrv.URL, sendData, tc.cliUser, tc.srvUsers)
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

func BenchmarkHTTPOverH2C(b *testing.B) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	ln, err := H2CListener("")
	if err != nil {
		b.Error(err)
	}

	client := &Client{
		Connector:   HTTPConnector(url.UserPassword("admin", "123456")),
		Transporter: H2CTransporter(),
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

func BenchmarkHTTPOverH2CParallel(b *testing.B) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	ln, err := H2CListener("")
	if err != nil {
		b.Error(err)
	}

	client := &Client{
		Connector:   HTTPConnector(url.UserPassword("admin", "123456")),
		Transporter: H2CTransporter(),
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

func socks5OverH2CRoundtrip(targetURL string, data []byte,
	clientInfo *url.Userinfo, serverInfo []*url.Userinfo) error {

	ln, err := H2CListener("")
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   SOCKS5Connector(clientInfo),
		Transporter: H2CTransporter(),
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

func TestSOCKS5OverH2C(t *testing.T) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	for i, tc := range socks5ProxyTests {
		tc := tc
		t.Run(fmt.Sprintf("#%d", i), func(t *testing.T) {
			err := socks5OverH2CRoundtrip(httpSrv.URL, sendData,
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

func socks4OverH2CRoundtrip(targetURL string, data []byte) error {
	ln, err := H2CListener("")
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   SOCKS4Connector(),
		Transporter: H2CTransporter(),
	}

	server := &Server{
		Listener: ln,
		Handler:  SOCKS4Handler(),
	}

	go server.Run()
	defer server.Close()

	return proxyRoundtrip(client, server, targetURL, data)
}

func TestSOCKS4OverH2C(t *testing.T) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	err := socks4OverH2CRoundtrip(httpSrv.URL, sendData)
	// t.Logf("#%d %v", i, err)
	if err != nil {
		t.Errorf("got error: %v", err)
	}
}

func socks4aOverH2CRoundtrip(targetURL string, data []byte) error {
	ln, err := H2CListener("")
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   SOCKS4AConnector(),
		Transporter: H2CTransporter(),
	}

	server := &Server{
		Listener: ln,
		Handler:  SOCKS4Handler(),
	}

	go server.Run()
	defer server.Close()

	return proxyRoundtrip(client, server, targetURL, data)
}

func TestSOCKS4AOverH2C(t *testing.T) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	err := socks4aOverH2CRoundtrip(httpSrv.URL, sendData)
	// t.Logf("#%d %v", i, err)
	if err != nil {
		t.Errorf("got error: %v", err)
	}
}

func ssOverH2CRoundtrip(targetURL string, data []byte,
	clientInfo, serverInfo *url.Userinfo) error {

	ln, err := H2CListener("")
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   ShadowConnector(clientInfo),
		Transporter: H2CTransporter(),
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

func TestSSOverH2C(t *testing.T) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	var ssProxyTests = []struct {
		clientCipher *url.Userinfo
		serverCipher *url.Userinfo
		pass         bool
	}{
		{nil, nil, false},
		{&url.Userinfo{}, &url.Userinfo{}, false},
		{url.User("abc"), url.User("abc"), false},
		{url.UserPassword("abc", "def"), url.UserPassword("abc", "def"), false},

		{url.User("aes-128-cfb"), url.User("aes-128-cfb"), false},
		{url.User("aes-128-cfb"), url.UserPassword("aes-128-cfb", "123456"), false},
		{url.UserPassword("aes-128-cfb", "123456"), url.User("aes-128-cfb"), false},
		{url.UserPassword("aes-128-cfb", "123456"), url.UserPassword("aes-128-cfb", "abc"), false},
		{url.UserPassword("aes-128-cfb", "123456"), url.UserPassword("aes-128-cfb", "123456"), true},
	}

	for i, tc := range ssProxyTests {
		tc := tc
		t.Run(fmt.Sprintf("#%d", i), func(t *testing.T) {
			err := ssOverH2CRoundtrip(httpSrv.URL, sendData,
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
