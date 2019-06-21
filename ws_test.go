package gost

import (
	"crypto/rand"
	"fmt"
	"net/http/httptest"
	"net/url"
	"testing"
)

func httpOverWSRoundtrip(targetURL string, data []byte,
	clientInfo *url.Userinfo, serverInfo []*url.Userinfo) error {

	ln, err := WSListener("", nil)
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   HTTPConnector(clientInfo),
		Transporter: WSTransporter(nil),
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

func TestHTTPOverWS(t *testing.T) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	for i, tc := range httpProxyTests {
		err := httpOverWSRoundtrip(httpSrv.URL, sendData, tc.cliUser, tc.srvUsers)
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

func BenchmarkHTTPOverWS(b *testing.B) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	ln, err := WSListener("", nil)
	if err != nil {
		b.Error(err)
	}

	client := &Client{
		Connector:   HTTPConnector(url.UserPassword("admin", "123456")),
		Transporter: WSTransporter(nil),
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

func BenchmarkHTTPOverWSParallel(b *testing.B) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	ln, err := WSListener("", nil)
	if err != nil {
		b.Error(err)
	}

	client := &Client{
		Connector:   HTTPConnector(url.UserPassword("admin", "123456")),
		Transporter: WSTransporter(nil),
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

func socks5OverWSRoundtrip(targetURL string, data []byte,
	clientInfo *url.Userinfo, serverInfo []*url.Userinfo) error {

	ln, err := WSListener("", nil)
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   SOCKS5Connector(clientInfo),
		Transporter: WSTransporter(nil),
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

func TestSOCKS5OverWS(t *testing.T) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	for i, tc := range socks5ProxyTests {
		err := socks5OverWSRoundtrip(httpSrv.URL, sendData,
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

func socks4OverWSRoundtrip(targetURL string, data []byte) error {
	ln, err := WSListener("", nil)
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   SOCKS4Connector(),
		Transporter: WSTransporter(nil),
	}

	server := &Server{
		Listener: ln,
		Handler:  SOCKS4Handler(),
	}

	go server.Run()
	defer server.Close()

	return proxyRoundtrip(client, server, targetURL, data)
}

func TestSOCKS4OverWS(t *testing.T) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	err := socks4OverWSRoundtrip(httpSrv.URL, sendData)
	// t.Logf("#%d %v", i, err)
	if err != nil {
		t.Errorf("got error: %v", err)
	}
}

func socks4aOverWSRoundtrip(targetURL string, data []byte) error {
	ln, err := WSListener("", nil)
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   SOCKS4AConnector(),
		Transporter: WSTransporter(nil),
	}

	server := &Server{
		Listener: ln,
		Handler:  SOCKS4Handler(),
	}

	go server.Run()
	defer server.Close()

	return proxyRoundtrip(client, server, targetURL, data)
}

func TestSOCKS4AOverWS(t *testing.T) {

	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	err := socks4aOverWSRoundtrip(httpSrv.URL, sendData)
	// t.Logf("#%d %v", i, err)
	if err != nil {
		t.Errorf("got error: %v", err)
	}
}

func ssOverWSRoundtrip(targetURL string, data []byte,
	clientInfo, serverInfo *url.Userinfo) error {

	ln, err := WSListener("", nil)
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   ShadowConnector(clientInfo),
		Transporter: WSTransporter(nil),
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

func TestSSOverWS(t *testing.T) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	for i, tc := range ssProxyTests {
		err := ssOverWSRoundtrip(httpSrv.URL, sendData,
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

func sniOverWSRoundtrip(targetURL string, data []byte, host string) error {
	ln, err := WSListener("", nil)
	if err != nil {
		return err
	}

	u, err := url.Parse(targetURL)
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   SNIConnector(host),
		Transporter: WSTransporter(nil),
	}

	server := &Server{
		Listener: ln,
		Handler:  SNIHandler(HostHandlerOption(u.Host)),
	}

	go server.Run()
	defer server.Close()

	return sniRoundtrip(client, server, targetURL, data)
}

func TestSNIOverWS(t *testing.T) {
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
			err := sniOverWSRoundtrip(tc.targetURL, sendData, tc.host)
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

func wsForwardTunnelRoundtrip(targetURL string, data []byte) error {
	ln, err := WSListener("", nil)
	if err != nil {
		return err
	}

	u, err := url.Parse(targetURL)
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   ForwardConnector(),
		Transporter: WSTransporter(nil),
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

func TestWSForwardTunnel(t *testing.T) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	err := wsForwardTunnelRoundtrip(httpSrv.URL, sendData)
	if err != nil {
		t.Error(err)
	}
}

func httpOverMWSRoundtrip(targetURL string, data []byte,
	clientInfo *url.Userinfo, serverInfo []*url.Userinfo) error {

	ln, err := MWSListener("", nil)
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   HTTPConnector(clientInfo),
		Transporter: MWSTransporter(nil),
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

func TestHTTPOverMWS(t *testing.T) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	for i, tc := range httpProxyTests {
		err := httpOverMWSRoundtrip(httpSrv.URL, sendData, tc.cliUser, tc.srvUsers)
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

func BenchmarkHTTPOverMWS(b *testing.B) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	ln, err := MWSListener("", nil)
	if err != nil {
		b.Error(err)
	}

	client := &Client{
		Connector:   HTTPConnector(url.UserPassword("admin", "123456")),
		Transporter: MWSTransporter(nil),
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

func BenchmarkHTTPOverMWSParallel(b *testing.B) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	ln, err := MWSListener("", nil)
	if err != nil {
		b.Error(err)
	}

	b.Log(ln.Addr())
	client := &Client{
		Connector:   HTTPConnector(url.UserPassword("admin", "123456")),
		Transporter: MWSTransporter(nil),
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

func socks5OverMWSRoundtrip(targetURL string, data []byte,
	clientInfo *url.Userinfo, serverInfo []*url.Userinfo) error {

	ln, err := MWSListener("", nil)
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   SOCKS5Connector(clientInfo),
		Transporter: MWSTransporter(nil),
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

func TestSOCKS5OverMWS(t *testing.T) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	for i, tc := range socks5ProxyTests {
		err := socks5OverMWSRoundtrip(httpSrv.URL, sendData,
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

func socks4OverMWSRoundtrip(targetURL string, data []byte) error {
	ln, err := MWSListener("", nil)
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   SOCKS4Connector(),
		Transporter: MWSTransporter(nil),
	}

	server := &Server{
		Listener: ln,
		Handler:  SOCKS4Handler(),
	}

	go server.Run()
	defer server.Close()

	return proxyRoundtrip(client, server, targetURL, data)
}

func TestSOCKS4OverMWS(t *testing.T) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	err := socks4OverMWSRoundtrip(httpSrv.URL, sendData)
	// t.Logf("#%d %v", i, err)
	if err != nil {
		t.Errorf("got error: %v", err)
	}
}

func socks4aOverMWSRoundtrip(targetURL string, data []byte) error {
	ln, err := MWSListener("", nil)
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   SOCKS4AConnector(),
		Transporter: MWSTransporter(nil),
	}

	server := &Server{
		Listener: ln,
		Handler:  SOCKS4Handler(),
	}

	go server.Run()
	defer server.Close()

	return proxyRoundtrip(client, server, targetURL, data)
}

func TestSOCKS4AOverMWS(t *testing.T) {

	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	err := socks4aOverMWSRoundtrip(httpSrv.URL, sendData)
	// t.Logf("#%d %v", i, err)
	if err != nil {
		t.Errorf("got error: %v", err)
	}
}

func ssOverMWSRoundtrip(targetURL string, data []byte,
	clientInfo, serverInfo *url.Userinfo) error {

	ln, err := MWSListener("", nil)
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   ShadowConnector(clientInfo),
		Transporter: MWSTransporter(nil),
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

func TestSSOverMWS(t *testing.T) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	for i, tc := range ssProxyTests {
		err := ssOverMWSRoundtrip(httpSrv.URL, sendData,
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

func sniOverMWSRoundtrip(targetURL string, data []byte, host string) error {
	ln, err := MWSListener("", nil)
	if err != nil {
		return err
	}

	u, err := url.Parse(targetURL)
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   SNIConnector(host),
		Transporter: MWSTransporter(nil),
	}

	server := &Server{
		Listener: ln,
		Handler:  SNIHandler(HostHandlerOption(u.Host)),
	}

	go server.Run()
	defer server.Close()

	return sniRoundtrip(client, server, targetURL, data)
}

func TestSNIOverMWS(t *testing.T) {
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
			err := sniOverMWSRoundtrip(tc.targetURL, sendData, tc.host)
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

func mwsForwardTunnelRoundtrip(targetURL string, data []byte) error {
	ln, err := MWSListener("", nil)
	if err != nil {
		return err
	}

	u, err := url.Parse(targetURL)
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   ForwardConnector(),
		Transporter: MWSTransporter(nil),
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

func TestMWSForwardTunnel(t *testing.T) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	err := mwsForwardTunnelRoundtrip(httpSrv.URL, sendData)
	if err != nil {
		t.Error(err)
	}
}
