package gost

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func init() {
	// ss.Debug = true
}

var ssTests = []struct {
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

	{url.User("aes-192-cfb"), url.User("aes-192-cfb"), false},
	{url.User("aes-192-cfb"), url.UserPassword("aes-192-cfb", "123456"), false},
	{url.UserPassword("aes-192-cfb", "123456"), url.User("aes-192-cfb"), false},
	{url.UserPassword("aes-192-cfb", "123456"), url.UserPassword("aes-192-cfb", "abc"), false},
	{url.UserPassword("aes-192-cfb", "123456"), url.UserPassword("aes-192-cfb", "123456"), true},

	{url.User("aes-256-cfb"), url.User("aes-256-cfb"), false},
	{url.User("aes-256-cfb"), url.UserPassword("aes-256-cfb", "123456"), false},
	{url.UserPassword("aes-256-cfb", "123456"), url.User("aes-256-cfb"), false},
	{url.UserPassword("aes-256-cfb", "123456"), url.UserPassword("aes-256-cfb", "abc"), false},
	{url.UserPassword("aes-256-cfb", "123456"), url.UserPassword("aes-256-cfb", "123456"), true},

	{url.User("aes-128-ctr"), url.User("aes-128-ctr"), false},
	{url.User("aes-128-ctr"), url.UserPassword("aes-128-ctr", "123456"), false},
	{url.UserPassword("aes-128-ctr", "123456"), url.User("aes-128-ctr"), false},
	{url.UserPassword("aes-128-ctr", "123456"), url.UserPassword("aes-128-ctr", "abc"), false},
	{url.UserPassword("aes-128-ctr", "123456"), url.UserPassword("aes-128-ctr", "123456"), true},

	{url.User("aes-192-ctr"), url.User("aes-192-ctr"), false},
	{url.User("aes-192-ctr"), url.UserPassword("aes-192-ctr", "123456"), false},
	{url.UserPassword("aes-192-ctr", "123456"), url.User("aes-192-ctr"), false},
	{url.UserPassword("aes-192-ctr", "123456"), url.UserPassword("aes-192-ctr", "abc"), false},
	{url.UserPassword("aes-192-ctr", "123456"), url.UserPassword("aes-192-ctr", "123456"), true},

	{url.User("aes-256-ctr"), url.User("aes-256-ctr"), false},
	{url.User("aes-256-ctr"), url.UserPassword("aes-256-ctr", "123456"), false},
	{url.UserPassword("aes-256-ctr", "123456"), url.User("aes-256-ctr"), false},
	{url.UserPassword("aes-256-ctr", "123456"), url.UserPassword("aes-256-ctr", "abc"), false},
	{url.UserPassword("aes-256-ctr", "123456"), url.UserPassword("aes-256-ctr", "123456"), true},

	{url.User("des-cfb"), url.User("des-cfb"), false},
	{url.User("des-cfb"), url.UserPassword("des-cfb", "123456"), false},
	{url.UserPassword("des-cfb", "123456"), url.User("des-cfb"), false},
	{url.UserPassword("des-cfb", "123456"), url.UserPassword("des-cfb", "abc"), false},
	{url.UserPassword("des-cfb", "123456"), url.UserPassword("des-cfb", "123456"), true},

	{url.User("bf-cfb"), url.User("bf-cfb"), false},
	{url.User("bf-cfb"), url.UserPassword("bf-cfb", "123456"), false},
	{url.UserPassword("bf-cfb", "123456"), url.User("bf-cfb"), false},
	{url.UserPassword("bf-cfb", "123456"), url.UserPassword("bf-cfb", "abc"), false},
	{url.UserPassword("bf-cfb", "123456"), url.UserPassword("bf-cfb", "123456"), true},

	{url.User("cast5-cfb"), url.User("cast5-cfb"), false},
	{url.User("cast5-cfb"), url.UserPassword("cast5-cfb", "123456"), false},
	{url.UserPassword("cast5-cfb", "123456"), url.User("cast5-cfb"), false},
	{url.UserPassword("cast5-cfb", "123456"), url.UserPassword("cast5-cfb", "abc"), false},
	{url.UserPassword("cast5-cfb", "123456"), url.UserPassword("cast5-cfb", "123456"), true},

	{url.User("rc4-md5"), url.User("rc4-md5"), false},
	{url.User("rc4-md5"), url.UserPassword("rc4-md5", "123456"), false},
	{url.UserPassword("rc4-md5", "123456"), url.User("rc4-md5"), false},
	{url.UserPassword("rc4-md5", "123456"), url.UserPassword("rc4-md5", "abc"), false},
	{url.UserPassword("rc4-md5", "123456"), url.UserPassword("rc4-md5", "123456"), true},

	{url.User("chacha20"), url.User("chacha20"), false},
	{url.User("chacha20"), url.UserPassword("chacha20", "123456"), false},
	{url.UserPassword("chacha20", "123456"), url.User("chacha20"), false},
	{url.UserPassword("chacha20", "123456"), url.UserPassword("chacha20", "abc"), false},
	{url.UserPassword("chacha20", "123456"), url.UserPassword("chacha20", "123456"), true},

	{url.User("chacha20-ietf"), url.User("chacha20-ietf"), false},
	{url.User("chacha20-ietf"), url.UserPassword("chacha20-ietf", "123456"), false},
	{url.UserPassword("chacha20-ietf", "123456"), url.User("chacha20-ietf"), false},
	{url.UserPassword("chacha20-ietf", "123456"), url.UserPassword("chacha20-ietf", "abc"), false},
	{url.UserPassword("chacha20-ietf", "123456"), url.UserPassword("chacha20-ietf", "123456"), true},

	{url.User("salsa20"), url.User("salsa20"), false},
	{url.User("salsa20"), url.UserPassword("salsa20", "123456"), false},
	{url.UserPassword("salsa20", "123456"), url.User("salsa20"), false},
	{url.UserPassword("salsa20", "123456"), url.UserPassword("salsa20", "abc"), false},
	{url.UserPassword("salsa20", "123456"), url.UserPassword("salsa20", "123456"), true},
}

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
	// {url.UserPassword("aes-128-cfb", "123456"), url.UserPassword("aes-128-cfb", "abc"), false},
	{url.UserPassword("aes-128-cfb", "123456"), url.UserPassword("aes-128-cfb", "123456"), true},
}

func ssProxyRoundtrip(targetURL string, data []byte, clientInfo *url.Userinfo, serverInfo *url.Userinfo) error {
	ln, err := TCPListener("")
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   ShadowConnector(clientInfo),
		Transporter: TCPTransporter(),
	}

	server := &Server{
		Handler:  ShadowHandler(UsersHandlerOption(serverInfo)),
		Listener: ln,
	}

	go server.Run()
	defer server.Close()

	return proxyRoundtrip(client, server, targetURL, data)
}

func TestSSProxy(t *testing.T) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	for i, tc := range ssTests {
		tc := tc
		t.Run(fmt.Sprintf("#%d", i), func(t *testing.T) {
			err := ssProxyRoundtrip(httpSrv.URL, sendData,
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

func BenchmarkSSProxy_AES256(b *testing.B) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	ln, err := TCPListener("")
	if err != nil {
		b.Error(err)
	}

	client := &Client{
		Connector:   ShadowConnector(url.UserPassword("aes-256-cfb", "123456")),
		Transporter: TCPTransporter(),
	}

	server := &Server{
		Handler:  ShadowHandler(UsersHandlerOption(url.UserPassword("aes-256-cfb", "123456"))),
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

func BenchmarkSSProxy_Chacha20(b *testing.B) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	ln, err := TCPListener("")
	if err != nil {
		b.Error(err)
	}

	client := &Client{
		Connector:   ShadowConnector(url.UserPassword("chacha20", "123456")),
		Transporter: TCPTransporter(),
	}

	server := &Server{
		Handler:  ShadowHandler(UsersHandlerOption(url.UserPassword("chacha20", "123456"))),
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

func BenchmarkSSProxy_Chacha20_ietf(b *testing.B) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	ln, err := TCPListener("")
	if err != nil {
		b.Error(err)
	}

	client := &Client{
		Connector:   ShadowConnector(url.UserPassword("chacha20-ietf", "123456")),
		Transporter: TCPTransporter(),
	}

	server := &Server{
		Handler:  ShadowHandler(UsersHandlerOption(url.UserPassword("chacha20-ietf", "123456"))),
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

func BenchmarkSSProxyParallel(b *testing.B) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	ln, err := TCPListener("")
	if err != nil {
		b.Error(err)
	}

	client := &Client{
		Connector:   ShadowConnector(url.UserPassword("chacha20-ietf", "123456")),
		Transporter: TCPTransporter(),
	}

	server := &Server{
		Handler:  ShadowHandler(UsersHandlerOption(url.UserPassword("chacha20-ietf", "123456"))),
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

func shadowUDPRoundtrip(t *testing.T, host string, data []byte,
	clientInfo *url.Userinfo, serverInfo *url.Userinfo) error {
	ln, err := ShadowUDPListener("localhost:0", serverInfo, 0)
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   ShadowUDPConnector(clientInfo),
		Transporter: UDPTransporter(),
	}

	server := &Server{
		Handler:  ShadowUDPdHandler(),
		Listener: ln,
	}

	go server.Run()
	defer server.Close()

	return udpRoundtrip(t, client, server, host, data)
}

func TestShadowUDP(t *testing.T) {
	sendData := make([]byte, 128)
	rand.Read(sendData)

	for i, tc := range ssTests {
		tc := tc
		t.Run(fmt.Sprintf("#%d", i), func(t *testing.T) {
			udpSrv := newUDPTestServer(udpTestHandler)
			udpSrv.Start()
			defer udpSrv.Close()

			err := shadowUDPRoundtrip(t, udpSrv.Addr(), sendData,
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

// TODO: fix shadowsocks UDP relay benchmark.
func BenchmarkShadowUDP(b *testing.B) {
	udpSrv := newUDPTestServer(udpTestHandler)
	udpSrv.Start()
	defer udpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	ln, err := ShadowUDPListener("localhost:0", url.UserPassword("chacha20-ietf", "123456"), 0)
	if err != nil {
		b.Error(err)
	}

	client := &Client{
		Connector:   ShadowUDPConnector(url.UserPassword("chacha20-ietf", "123456")),
		Transporter: UDPTransporter(),
	}

	server := &Server{
		Handler:  ShadowUDPdHandler(),
		Listener: ln,
	}

	go server.Run()
	defer server.Close()

	conn, err := proxyConn(client, server)
	if err != nil {
		b.Error(err)
	}
	defer conn.Close()

	conn, err = client.Connect(conn, udpSrv.Addr())
	if err != nil {
		return
	}

	for i := 0; i < b.N; i++ {
		conn.SetDeadline(time.Now().Add(3 * time.Second))

		if _, err = conn.Write(sendData); err != nil {
			b.Error(err)
		}

		recv := make([]byte, len(sendData))
		if _, err = conn.Read(recv); err != nil {
			b.Error(err)
		}

		conn.SetDeadline(time.Time{})

		if !bytes.Equal(sendData, recv) {
			b.Error("data not equal")
		}
	}
}
