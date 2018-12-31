package gost

import (
	"crypto/rand"
	"net/http/httptest"
	"net/url"
	"testing"
)

var httpProxyTests = []struct {
	cliUser  *url.Userinfo
	srvUsers []*url.Userinfo
	errStr   string
}{
	{nil, nil, ""},
	{nil, []*url.Userinfo{url.User("admin")}, "407 Proxy Authentication Required"},
	{nil, []*url.Userinfo{url.UserPassword("", "123456")}, "407 Proxy Authentication Required"},
	{url.User("admin"), []*url.Userinfo{url.User("test")}, "407 Proxy Authentication Required"},
	{url.User("admin"), []*url.Userinfo{url.UserPassword("admin", "123456")}, "407 Proxy Authentication Required"},
	{url.User("admin"), []*url.Userinfo{url.User("admin")}, ""},
	{url.User("admin"), []*url.Userinfo{url.UserPassword("admin", "")}, ""},
	{url.UserPassword("admin", "123456"), nil, ""},
	{url.UserPassword("admin", "123456"), []*url.Userinfo{url.User("admin")}, ""},
	{url.UserPassword("admin", "123456"), []*url.Userinfo{url.UserPassword("", "123456")}, ""},
	{url.UserPassword("", "123456"), []*url.Userinfo{url.UserPassword("", "123456")}, ""},
	{url.UserPassword("admin", "123456"), []*url.Userinfo{url.UserPassword("admin", "123456")}, ""},
	{url.UserPassword("admin", "123456"), []*url.Userinfo{url.UserPassword("user", "pass"), url.UserPassword("admin", "123456")}, ""},
}

func httpProxyRoundtrip(targetURL string, data []byte, clientInfo *url.Userinfo, serverInfo []*url.Userinfo) error {
	ln, err := TCPListener("")
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   HTTPConnector(clientInfo),
		Transporter: TCPTransporter(),
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

func TestHTTPProxy(t *testing.T) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	for i, tc := range httpProxyTests {
		err := httpProxyRoundtrip(httpSrv.URL, sendData, tc.cliUser, tc.srvUsers)
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

func BenchmarkHTTPProxy(b *testing.B) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	ln, err := TCPListener("")
	if err != nil {
		b.Error(err)
	}

	client := &Client{
		Connector:   HTTPConnector(url.UserPassword("admin", "123456")),
		Transporter: TCPTransporter(),
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

func BenchmarkHTTPProxyParallel(b *testing.B) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	ln, err := TCPListener("")
	if err != nil {
		b.Error(err)
	}

	client := &Client{
		Connector:   HTTPConnector(url.UserPassword("admin", "123456")),
		Transporter: TCPTransporter(),
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
