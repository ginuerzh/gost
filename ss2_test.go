package gost

import (
	"crypto/rand"
	"fmt"
	"net/http/httptest"
	"net/url"
	"testing"
)

func init() {
	// ss.Debug = true
}

var ss2Tests = []struct {
	clientCipher *url.Userinfo
	serverCipher *url.Userinfo
	pass         bool
}{
	{nil, nil, false},
	{&url.Userinfo{}, &url.Userinfo{}, false},
	{url.User("abc"), url.User("abc"), false},
	{url.UserPassword("abc", "def"), url.UserPassword("abc", "def"), false},

	{url.User("aes-128-cfb"), url.User("aes-128-cfb"), true},
	{url.User("aes-128-cfb"), url.UserPassword("aes-128-cfb", "123456"), false},
	{url.UserPassword("aes-128-cfb", "123456"), url.User("aes-128-cfb"), false},
	{url.UserPassword("aes-128-cfb", "123456"), url.UserPassword("aes-128-cfb", "abc"), false},
	{url.UserPassword("aes-128-cfb", "123456"), url.UserPassword("aes-128-cfb", "123456"), true},

	{url.User("aes-192-cfb"), url.User("aes-192-cfb"), true},
	{url.User("aes-192-cfb"), url.UserPassword("aes-192-cfb", "123456"), false},
	{url.UserPassword("aes-192-cfb", "123456"), url.User("aes-192-cfb"), false},
	{url.UserPassword("aes-192-cfb", "123456"), url.UserPassword("aes-192-cfb", "abc"), false},
	{url.UserPassword("aes-192-cfb", "123456"), url.UserPassword("aes-192-cfb", "123456"), true},

	{url.User("aes-256-cfb"), url.User("aes-256-cfb"), true},
	{url.User("aes-256-cfb"), url.UserPassword("aes-256-cfb", "123456"), false},
	{url.UserPassword("aes-256-cfb", "123456"), url.User("aes-256-cfb"), false},
	{url.UserPassword("aes-256-cfb", "123456"), url.UserPassword("aes-256-cfb", "abc"), false},
	{url.UserPassword("aes-256-cfb", "123456"), url.UserPassword("aes-256-cfb", "123456"), true},

	{url.User("aes-128-ctr"), url.User("aes-128-ctr"), true},
	{url.User("aes-128-ctr"), url.UserPassword("aes-128-ctr", "123456"), false},
	{url.UserPassword("aes-128-ctr", "123456"), url.User("aes-128-ctr"), false},
	{url.UserPassword("aes-128-ctr", "123456"), url.UserPassword("aes-128-ctr", "abc"), false},
	{url.UserPassword("aes-128-ctr", "123456"), url.UserPassword("aes-128-ctr", "123456"), true},

	{url.User("aes-192-ctr"), url.User("aes-192-ctr"), true},
	{url.User("aes-192-ctr"), url.UserPassword("aes-192-ctr", "123456"), false},
	{url.UserPassword("aes-192-ctr", "123456"), url.User("aes-192-ctr"), false},
	{url.UserPassword("aes-192-ctr", "123456"), url.UserPassword("aes-192-ctr", "abc"), false},
	{url.UserPassword("aes-192-ctr", "123456"), url.UserPassword("aes-192-ctr", "123456"), true},

	{url.User("aes-256-ctr"), url.User("aes-256-ctr"), true},
	{url.User("aes-256-ctr"), url.UserPassword("aes-256-ctr", "123456"), false},
	{url.UserPassword("aes-256-ctr", "123456"), url.User("aes-256-ctr"), false},
	{url.UserPassword("aes-256-ctr", "123456"), url.UserPassword("aes-256-ctr", "abc"), false},
	{url.UserPassword("aes-256-ctr", "123456"), url.UserPassword("aes-256-ctr", "123456"), true},

	{url.User("chacha20-ietf"), url.User("chacha20-ietf"), true},
	{url.User("chacha20-ietf"), url.UserPassword("chacha20-ietf", "123456"), false},
	{url.UserPassword("chacha20-ietf", "123456"), url.User("chacha20-ietf"), false},
	{url.UserPassword("chacha20-ietf", "123456"), url.UserPassword("chacha20-ietf", "abc"), false},
	{url.UserPassword("chacha20-ietf", "123456"), url.UserPassword("chacha20-ietf", "123456"), true},

	{url.User("xchacha20"), url.User("xchacha20"), true},
	{url.User("xchacha20"), url.UserPassword("xchacha20", "123456"), false},
	{url.UserPassword("xchacha20", "123456"), url.User("xchacha20"), false},
	{url.UserPassword("xchacha20", "123456"), url.UserPassword("xchacha20", "abc"), false},
	{url.UserPassword("xchacha20", "123456"), url.UserPassword("xchacha20", "123456"), true},

	{url.User("AEAD_AES_128_GCM"), url.User("AEAD_AES_128_GCM"), true},
	{url.User("AEAD_AES_128_GCM"), url.UserPassword("AEAD_AES_128_GCM", "123456"), false},
	{url.UserPassword("AEAD_AES_128_GCM", "123456"), url.User("AEAD_AES_128_GCM"), false},
	{url.UserPassword("AEAD_AES_128_GCM", "123456"), url.UserPassword("AEAD_AES_128_GCM", "abc"), false},
	{url.UserPassword("AEAD_AES_128_GCM", "123456"), url.UserPassword("AEAD_AES_128_GCM", "123456"), true},

	{url.User("AEAD_AES_192_GCM"), url.User("AEAD_AES_192_GCM"), true},
	{url.User("AEAD_AES_192_GCM"), url.UserPassword("AEAD_AES_192_GCM", "123456"), false},
	{url.UserPassword("AEAD_AES_192_GCM", "123456"), url.User("AEAD_AES_192_GCM"), false},
	{url.UserPassword("AEAD_AES_192_GCM", "123456"), url.UserPassword("AEAD_AES_192_GCM", "abc"), false},
	{url.UserPassword("AEAD_AES_192_GCM", "123456"), url.UserPassword("AEAD_AES_192_GCM", "123456"), true},

	{url.User("AEAD_AES_256_GCM"), url.User("AEAD_AES_256_GCM"), true},
	{url.User("AEAD_AES_256_GCM"), url.UserPassword("AEAD_AES_256_GCM", "123456"), false},
	{url.UserPassword("AEAD_AES_256_GCM", "123456"), url.User("AEAD_AES_256_GCM"), false},
	{url.UserPassword("AEAD_AES_256_GCM", "123456"), url.UserPassword("AEAD_AES_256_GCM", "abc"), false},
	{url.UserPassword("AEAD_AES_256_GCM", "123456"), url.UserPassword("AEAD_AES_256_GCM", "123456"), true},

	{url.User("AEAD_CHACHA20_POLY1305"), url.User("AEAD_CHACHA20_POLY1305"), true},
	{url.User("AEAD_CHACHA20_POLY1305"), url.UserPassword("AEAD_CHACHA20_POLY1305", "123456"), false},
	{url.UserPassword("AEAD_CHACHA20_POLY1305", "123456"), url.User("AEAD_CHACHA20_POLY1305"), false},
	{url.UserPassword("AEAD_CHACHA20_POLY1305", "123456"), url.UserPassword("AEAD_CHACHA20_POLY1305", "abc"), false},
	{url.UserPassword("AEAD_CHACHA20_POLY1305", "123456"), url.UserPassword("AEAD_CHACHA20_POLY1305", "123456"), true},
}

var ss2ProxyTests = []struct {
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
	// {url.UserPassword("aes-128-cfb", "123456"), url.UserPassword("aes-128-cfb", "abc"), false},
	{url.UserPassword("aes-128-cfb", "123456"), url.UserPassword("aes-128-cfb", "123456"), true},
}

func ss2ProxyRoundtrip(targetURL string, data []byte, clientInfo *url.Userinfo, serverInfo *url.Userinfo) error {
	ln, err := TCPListener("")
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   Shadow2Connector(clientInfo),
		Transporter: TCPTransporter(),
	}

	server := &Server{
		Handler:  Shadow2Handler(UsersHandlerOption(serverInfo)),
		Listener: ln,
	}

	go server.Run()
	defer server.Close()

	return proxyRoundtrip(client, server, targetURL, data)
}

func TestSS2Proxy(t *testing.T) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	for i, tc := range ss2Tests {
		tc := tc
		t.Run(fmt.Sprintf("#%d", i), func(t *testing.T) {
			err := ss2ProxyRoundtrip(httpSrv.URL, sendData,
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

func BenchmarkSS2Proxy_AES256(b *testing.B) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	ln, err := TCPListener("")
	if err != nil {
		b.Error(err)
	}

	client := &Client{
		Connector:   Shadow2Connector(url.UserPassword("aes-256-cfb", "123456")),
		Transporter: TCPTransporter(),
	}

	server := &Server{
		Handler:  Shadow2Handler(UsersHandlerOption(url.UserPassword("aes-256-cfb", "123456"))),
		Listener: ln,
	}

	go server.Run()
	defer server.Close()

	for i := 0; i < b.N; i++ {
		if err := proxyRoundtrip(client, server, httpSrv.URL, sendData); err != nil {
			b.Error(err)
		}
	}
}

func BenchmarkSS2Proxy_XChacha20(b *testing.B) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	ln, err := TCPListener("")
	if err != nil {
		b.Error(err)
	}

	client := &Client{
		Connector:   Shadow2Connector(url.UserPassword("xchacha20", "123456")),
		Transporter: TCPTransporter(),
	}

	server := &Server{
		Handler:  Shadow2Handler(UsersHandlerOption(url.UserPassword("xchacha20", "123456"))),
		Listener: ln,
	}

	go server.Run()
	defer server.Close()

	for i := 0; i < b.N; i++ {
		if err := proxyRoundtrip(client, server, httpSrv.URL, sendData); err != nil {
			b.Error(err)
		}
	}
}

func BenchmarkSS2Proxy_Chacha20_ietf(b *testing.B) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	ln, err := TCPListener("")
	if err != nil {
		b.Error(err)
	}

	client := &Client{
		Connector:   Shadow2Connector(url.UserPassword("chacha20-ietf", "123456")),
		Transporter: TCPTransporter(),
	}

	server := &Server{
		Handler:  Shadow2Handler(UsersHandlerOption(url.UserPassword("chacha20-ietf", "123456"))),
		Listener: ln,
	}

	go server.Run()
	defer server.Close()

	for i := 0; i < b.N; i++ {
		if err := proxyRoundtrip(client, server, httpSrv.URL, sendData); err != nil {
			b.Error(err)
		}
	}
}

func BenchmarkSS2Proxy_CHACHA20_IETF_Parallel(b *testing.B) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	ln, err := TCPListener("")
	if err != nil {
		b.Error(err)
	}

	client := &Client{
		Connector:   Shadow2Connector(url.UserPassword("chacha20-ietf", "123456")),
		Transporter: TCPTransporter(),
	}

	server := &Server{
		Handler:  Shadow2Handler(UsersHandlerOption(url.UserPassword("chacha20-ietf", "123456"))),
		Listener: ln,
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

func BenchmarkSS2Proxy_AEAD_AES_256_GCM(b *testing.B) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	ln, err := TCPListener("")
	if err != nil {
		b.Error(err)
	}

	client := &Client{
		Connector:   Shadow2Connector(url.UserPassword("AEAD_AES_256_GCM", "123456")),
		Transporter: TCPTransporter(),
	}

	server := &Server{
		Handler:  Shadow2Handler(UsersHandlerOption(url.UserPassword("AEAD_AES_256_GCM", "123456"))),
		Listener: ln,
	}

	go server.Run()
	defer server.Close()

	for i := 0; i < b.N; i++ {
		if err := proxyRoundtrip(client, server, httpSrv.URL, sendData); err != nil {
			b.Error(err)
		}
	}
}

func BenchmarkSS2Proxy_AEAD_AES_256_GCM_Parallel(b *testing.B) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	ln, err := TCPListener("")
	if err != nil {
		b.Error(err)
	}

	client := &Client{
		Connector:   Shadow2Connector(url.UserPassword("AEAD_AES_256_GCM", "123456")),
		Transporter: TCPTransporter(),
	}

	server := &Server{
		Handler:  Shadow2Handler(UsersHandlerOption(url.UserPassword("AEAD_AES_256_GCM", "123456"))),
		Listener: ln,
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

func BenchmarkSS2Proxy_AEAD_CHACHA20_POLY1305(b *testing.B) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	ln, err := TCPListener("")
	if err != nil {
		b.Error(err)
	}

	client := &Client{
		Connector:   Shadow2Connector(url.UserPassword("AEAD_CHACHA20_POLY1305", "123456")),
		Transporter: TCPTransporter(),
	}

	server := &Server{
		Handler:  Shadow2Handler(UsersHandlerOption(url.UserPassword("AEAD_CHACHA20_POLY1305", "123456"))),
		Listener: ln,
	}

	go server.Run()
	defer server.Close()

	for i := 0; i < b.N; i++ {
		if err := proxyRoundtrip(client, server, httpSrv.URL, sendData); err != nil {
			b.Error(err)
		}
	}
}

func BenchmarkSS2Proxy_AEAD_CHACHA20_POLY1305_Parallel(b *testing.B) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	ln, err := TCPListener("")
	if err != nil {
		b.Error(err)
	}

	client := &Client{
		Connector:   Shadow2Connector(url.UserPassword("AEAD_CHACHA20_POLY1305", "123456")),
		Transporter: TCPTransporter(),
	}

	server := &Server{
		Handler:  Shadow2Handler(UsersHandlerOption(url.UserPassword("AEAD_CHACHA20_POLY1305", "123456"))),
		Listener: ln,
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
