package gost

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
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

func TestHTTP2ProxyAuth(t *testing.T) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	for i, tc := range httpProxyTests {
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

	ln, err := H2Listener("", tlsConfig, "/h2")
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   HTTPConnector(clientInfo),
		Transporter: H2Transporter(nil, "/h2"),
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
	}
}

func BenchmarkHTTPOverH2(b *testing.B) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	ln, err := H2Listener("", nil, "/h2")
	if err != nil {
		b.Error(err)
	}

	client := &Client{
		Connector:   HTTPConnector(url.UserPassword("admin", "123456")),
		Transporter: H2Transporter(nil, "/h2"),
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

	ln, err := H2Listener("", nil, "/h2")
	if err != nil {
		b.Error(err)
	}

	client := &Client{
		Connector:   HTTPConnector(url.UserPassword("admin", "123456")),
		Transporter: H2Transporter(nil, "/h2"),
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

	ln, err := H2Listener("", tlsConfig, "/h2")
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   SOCKS5Connector(clientInfo),
		Transporter: H2Transporter(nil, "/h2"),
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
	}
}

func socks4OverH2Roundtrip(targetURL string, data []byte, tlsConfig *tls.Config) error {
	ln, err := H2Listener("", tlsConfig, "/h2")
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   SOCKS4Connector(),
		Transporter: H2Transporter(nil, "/h2"),
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
	ln, err := H2Listener("", tlsConfig, "/h2")
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   SOCKS4AConnector(),
		Transporter: H2Transporter(nil, "/h2"),
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

	ln, err := H2Listener("", tlsConfig, "/h2")
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   ShadowConnector(clientInfo),
		Transporter: H2Transporter(nil, "/h2"),
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

	for i, tc := range ssProxyTests {
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
	}
}

func sniOverH2Roundtrip(targetURL string, data []byte, host string) error {
	ln, err := H2Listener("", nil, "/h2")
	if err != nil {
		return err
	}

	u, err := url.Parse(targetURL)
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   SNIConnector(host),
		Transporter: H2Transporter(nil, "/h2"),
	}

	server := &Server{
		Listener: ln,
		Handler:  SNIHandler(HostHandlerOption(u.Host)),
	}

	go server.Run()
	defer server.Close()

	return sniRoundtrip(client, server, targetURL, data)
}

func TestSNIOverH2(t *testing.T) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()
	httpsSrv := httptest.NewTLSServer(httpTestHandler)
	defer httpsSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	var sniProxyTests = []struct {
		targetURL string
		host      string
		pass      bool
	}{
		{httpSrv.URL, "", true},
		{httpSrv.URL, "example.com", true},
		{httpsSrv.URL, "", true},
		{httpsSrv.URL, "example.com", true},
	}

	for i, tc := range sniProxyTests {
		tc := tc
		t.Run(fmt.Sprintf("#%d", i), func(t *testing.T) {
			err := sniOverH2Roundtrip(tc.targetURL, sendData, tc.host)
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

func h2ForwardTunnelRoundtrip(targetURL string, data []byte) error {
	ln, err := H2Listener("", nil, "")
	if err != nil {
		return err
	}

	u, err := url.Parse(targetURL)
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   ForwardConnector(),
		Transporter: H2Transporter(nil, ""),
	}

	server := &Server{
		Listener: ln,
		Handler:  TCPDirectForwardHandler(u.Host),
	}
	server.Handler.Init()

	go server.Run()
	defer server.Close()

	return proxyRoundtrip(client, server, targetURL, data)
}

func TestH2ForwardTunnel(t *testing.T) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	err := h2ForwardTunnelRoundtrip(httpSrv.URL, sendData)
	if err != nil {
		t.Error(err)
	}
}

func httpOverH2CRoundtrip(targetURL string, data []byte,
	clientInfo *url.Userinfo, serverInfo []*url.Userinfo) error {

	ln, err := H2CListener("", "/h2c")
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   HTTPConnector(clientInfo),
		Transporter: H2CTransporter("/h2c"),
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
	}
}

func BenchmarkHTTPOverH2C(b *testing.B) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	ln, err := H2CListener("", "/h2c")
	if err != nil {
		b.Error(err)
	}

	client := &Client{
		Connector:   HTTPConnector(url.UserPassword("admin", "123456")),
		Transporter: H2CTransporter("/h2c"),
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

	ln, err := H2CListener("", "/h2c")
	if err != nil {
		b.Error(err)
	}

	client := &Client{
		Connector:   HTTPConnector(url.UserPassword("admin", "123456")),
		Transporter: H2CTransporter("/h2c"),
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

	ln, err := H2CListener("", "/h2c")
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   SOCKS5Connector(clientInfo),
		Transporter: H2CTransporter("/h2c"),
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
	}
}

func socks4OverH2CRoundtrip(targetURL string, data []byte) error {
	ln, err := H2CListener("", "/h2c")
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   SOCKS4Connector(),
		Transporter: H2CTransporter("/h2c"),
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
	ln, err := H2CListener("", "/h2c")
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   SOCKS4AConnector(),
		Transporter: H2CTransporter("/h2c"),
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

	ln, err := H2CListener("", "/h2c")
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   ShadowConnector(clientInfo),
		Transporter: H2CTransporter("/h2c"),
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

	for i, tc := range ssProxyTests {
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
	}
}

func sniOverH2CRoundtrip(targetURL string, data []byte, host string) error {
	ln, err := H2CListener("", "/h2c")
	if err != nil {
		return err
	}

	u, err := url.Parse(targetURL)
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   SNIConnector(host),
		Transporter: H2CTransporter("/h2c"),
	}

	server := &Server{
		Listener: ln,
		Handler:  SNIHandler(HostHandlerOption(u.Host)),
	}

	go server.Run()
	defer server.Close()

	return sniRoundtrip(client, server, targetURL, data)
}

func TestSNIOverH2C(t *testing.T) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()
	httpsSrv := httptest.NewTLSServer(httpTestHandler)
	defer httpsSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	var sniProxyTests = []struct {
		targetURL string
		host      string
		pass      bool
	}{
		{httpSrv.URL, "", true},
		{httpSrv.URL, "example.com", true},
		{httpsSrv.URL, "", true},
		{httpsSrv.URL, "example.com", true},
	}

	for i, tc := range sniProxyTests {
		tc := tc
		t.Run(fmt.Sprintf("#%d", i), func(t *testing.T) {
			err := sniOverH2CRoundtrip(tc.targetURL, sendData, tc.host)
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

func h2cForwardTunnelRoundtrip(targetURL string, data []byte) error {
	ln, err := H2CListener("", "")
	if err != nil {
		return err
	}

	u, err := url.Parse(targetURL)
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   ForwardConnector(),
		Transporter: H2CTransporter(""),
	}

	server := &Server{
		Listener: ln,
		Handler:  TCPDirectForwardHandler(u.Host),
	}
	server.Handler.Init()

	go server.Run()
	defer server.Close()

	return proxyRoundtrip(client, server, targetURL, data)
}

func TestH2CForwardTunnel(t *testing.T) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	err := h2cForwardTunnelRoundtrip(httpSrv.URL, sendData)
	if err != nil {
		t.Error(err)
	}
}

func TestHTTP2ProxyWithCodeProbeResist(t *testing.T) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	ln, err := HTTP2Listener("", nil)
	if err != nil {
		t.Error(err)
	}

	client := &Client{
		Connector:   HTTP2Connector(nil),
		Transporter: HTTP2Transporter(nil),
	}

	server := &Server{
		Listener: ln,
		Handler: HTTP2Handler(
			UsersHandlerOption(url.UserPassword("admin", "123456")),
			ProbeResistHandlerOption("code:400"),
		),
	}
	go server.Run()
	defer server.Close()

	err = proxyRoundtrip(client, server, httpSrv.URL, nil)
	if err == nil {
		t.Error("should failed with status code 400")
	} else if err.Error() != "400 Bad Request" {
		t.Error("should failed with status code 400, got", err.Error())
	}
}

func TestHTTP2ProxyWithWebProbeResist(t *testing.T) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	ln, err := HTTP2Listener("", nil)
	if err != nil {
		t.Error(err)
	}

	client := &Client{
		Connector:   HTTP2Connector(nil),
		Transporter: HTTP2Transporter(nil),
	}

	u, err := url.Parse(httpSrv.URL)
	if err != nil {
		t.Error(err)
	}
	server := &Server{
		Listener: ln,
		Handler: HTTP2Handler(
			UsersHandlerOption(url.UserPassword("admin", "123456")),
			ProbeResistHandlerOption("web:"+u.Host),
		),
	}
	go server.Run()
	defer server.Close()

	conn, err := proxyConn(client, server)
	if err != nil {
		t.Error(err)
	}
	defer conn.Close()

	conn, err = client.Connect(conn, "github.com:443")
	if err != nil {
		t.Error(err)
	}
	recv, _ := ioutil.ReadAll(conn)
	if !bytes.Equal(recv, []byte("Hello World!")) {
		t.Error("data not equal")
	}
}

func TestHTTP2ProxyWithHostProbeResist(t *testing.T) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	ln, err := HTTP2Listener("", nil)
	if err != nil {
		t.Error(err)
	}

	client := &Client{
		Connector:   HTTP2Connector(nil),
		Transporter: HTTP2Transporter(nil),
	}

	u, err := url.Parse(httpSrv.URL)
	if err != nil {
		t.Error(err)
	}

	server := &Server{
		Listener: ln,
		Handler: HTTP2Handler(
			UsersHandlerOption(url.UserPassword("admin", "123456")),
			ProbeResistHandlerOption("host:"+u.Host),
		),
	}
	go server.Run()
	defer server.Close()

	conn, err := proxyConn(client, server)
	if err != nil {
		t.Error(err)
	}
	defer conn.Close()

	cc, ok := conn.(*http2ClientConn)
	if !ok {
		t.Error("wrong connection type")
	}

	req := &http.Request{
		Method:        http.MethodConnect,
		URL:           &url.URL{Scheme: "https", Host: cc.addr},
		Header:        make(http.Header),
		Proto:         "HTTP/2.0",
		ProtoMajor:    2,
		ProtoMinor:    0,
		Body:          ioutil.NopCloser(bytes.NewReader(sendData)),
		Host:          "github.com:443",
		ContentLength: int64(len(sendData)),
	}

	resp, err := cc.client.Do(req)
	if err != nil {
		t.Error(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Error("got non-200 status:", resp.Status)
	}

	recv, _ := ioutil.ReadAll(resp.Body)
	if !bytes.Equal(sendData, recv) {
		t.Error("data not equal")
	}
}

func TestHTTP2ProxyWithFileProbeResist(t *testing.T) {
	ln, err := HTTP2Listener("", nil)
	if err != nil {
		t.Error(err)
	}

	client := &Client{
		Connector:   HTTP2Connector(nil),
		Transporter: HTTP2Transporter(nil),
	}

	server := &Server{
		Listener: ln,
		Handler: HTTP2Handler(
			UsersHandlerOption(url.UserPassword("admin", "123456")),
			ProbeResistHandlerOption("file:.config/probe_resist.txt"),
		),
	}
	go server.Run()
	defer server.Close()

	conn, err := proxyConn(client, server)
	if err != nil {
		t.Error(err)
	}
	defer conn.Close()

	conn, err = client.Connect(conn, "github.com:443")
	if err != nil {
		t.Error(err)
	}
	recv, _ := ioutil.ReadAll(conn)
	if !bytes.Equal(recv, []byte("Hello World!")) {
		t.Error("data not equal")
	}
}

func TestHTTP2ProxyWithBypass(t *testing.T) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	u, err := url.Parse(httpSrv.URL)
	if err != nil {
		t.Error(err)
	}
	ln, err := HTTP2Listener("", nil)
	if err != nil {
		t.Error(err)
	}

	client := &Client{
		Connector:   HTTP2Connector(nil),
		Transporter: HTTP2Transporter(nil),
	}

	host := u.Host
	if h, _, _ := net.SplitHostPort(u.Host); h != "" {
		host = h
	}
	server := &Server{
		Listener: ln,
		Handler: HTTP2Handler(
			BypassHandlerOption(NewBypassPatterns(false, host)),
		),
	}
	go server.Run()
	defer server.Close()

	if err = proxyRoundtrip(client, server, httpSrv.URL, sendData); err == nil {
		t.Error("should failed")
	}
}
