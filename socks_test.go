package gost

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"net"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

var socks5ProxyTests = []struct {
	cliUser  *url.Userinfo
	srvUsers []*url.Userinfo
	pass     bool
}{
	{nil, nil, true},
	{nil, []*url.Userinfo{url.User("admin")}, false},
	{nil, []*url.Userinfo{url.UserPassword("", "123456")}, false},
	{url.User("admin"), []*url.Userinfo{url.User("test")}, false},
	{url.User("admin"), []*url.Userinfo{url.UserPassword("admin", "123456")}, false},
	{url.User("admin"), []*url.Userinfo{url.User("admin")}, true},
	{url.User("admin"), []*url.Userinfo{url.UserPassword("admin", "")}, true},
	{url.UserPassword("admin", "123456"), nil, true},
	{url.UserPassword("admin", "123456"), []*url.Userinfo{url.User("admin")}, true},
	{url.UserPassword("admin", "123456"), []*url.Userinfo{url.UserPassword("", "123456")}, true},
	{url.UserPassword("", "123456"), []*url.Userinfo{url.UserPassword("", "123456")}, true},
	{url.UserPassword("admin", "123456"), []*url.Userinfo{url.UserPassword("admin", "123456")}, true},
	{url.UserPassword("admin", "123456"), []*url.Userinfo{url.UserPassword("user", "pass"), url.UserPassword("admin", "123456")}, true},
}

func socks5ProxyRoundtrip(targetURL string, data []byte, clientInfo *url.Userinfo, serverInfo []*url.Userinfo) error {
	ln, err := TCPListener("")
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   SOCKS5Connector(clientInfo),
		Transporter: TCPTransporter(),
	}

	server := &Server{
		Handler:  SOCKS5Handler(UsersHandlerOption(serverInfo...)),
		Listener: ln,
	}

	go server.Run()
	defer server.Close()

	return proxyRoundtrip(client, server, targetURL, data)
}

func TestSOCKS5Proxy(t *testing.T) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	for i, tc := range socks5ProxyTests {
		err := socks5ProxyRoundtrip(httpSrv.URL, sendData,
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

func BenchmarkSOCKS5Proxy(b *testing.B) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	ln, err := TCPListener("")
	if err != nil {
		b.Error(err)
	}

	client := &Client{
		Connector:   SOCKS5Connector(url.UserPassword("admin", "123456")),
		Transporter: TCPTransporter(),
	}

	server := &Server{
		Handler:  SOCKS5Handler(UsersHandlerOption(url.UserPassword("admin", "123456"))),
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

func BenchmarkSOCKS5ProxyParallel(b *testing.B) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	ln, err := TCPListener("")
	if err != nil {
		b.Error(err)
	}

	client := &Client{
		Connector:   SOCKS5Connector(url.UserPassword("admin", "123456")),
		Transporter: TCPTransporter(),
	}

	server := &Server{
		Handler:  SOCKS5Handler(UsersHandlerOption(url.UserPassword("admin", "123456"))),
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

func socks4ProxyRoundtrip(targetURL string, data []byte) error {
	ln, err := TCPListener("")
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   SOCKS4Connector(),
		Transporter: TCPTransporter(),
	}

	server := &Server{
		Listener: ln,
		Handler:  SOCKS4Handler(),
	}
	go server.Run()
	defer server.Close()

	return proxyRoundtrip(client, server, targetURL, data)
}

func TestSOCKS4Proxy(t *testing.T) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	err := socks4ProxyRoundtrip(httpSrv.URL, sendData)
	// t.Logf("#%d %v", i, err)
	if err != nil {
		t.Errorf("got error: %v", err)
	}
}

func BenchmarkSOCKS4Proxy(b *testing.B) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	ln, err := TCPListener("")
	if err != nil {
		b.Error(err)
	}

	client := &Client{
		Connector:   SOCKS4Connector(),
		Transporter: TCPTransporter(),
	}

	server := &Server{
		Listener: ln,
		Handler:  SOCKS4Handler(),
	}
	go server.Run()
	defer server.Close()

	for i := 0; i < b.N; i++ {
		if err := proxyRoundtrip(client, server, httpSrv.URL, sendData); err != nil {
			b.Error(err)
		}
	}
}

func BenchmarkSOCKS4ProxyParallel(b *testing.B) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	ln, err := TCPListener("")
	if err != nil {
		b.Error(err)
	}

	client := &Client{
		Connector:   SOCKS4Connector(),
		Transporter: TCPTransporter(),
	}

	server := &Server{
		Listener: ln,
		Handler:  SOCKS4Handler(),
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

func socks4aProxyRoundtrip(targetURL string, data []byte) error {
	ln, err := TCPListener("")
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   SOCKS4AConnector(),
		Transporter: TCPTransporter(),
	}

	server := &Server{
		Listener: ln,
		Handler:  SOCKS4Handler(),
	}

	go server.Run()
	defer server.Close()

	return proxyRoundtrip(client, server, targetURL, data)
}

func TestSOCKS4AProxy(t *testing.T) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	err := socks4aProxyRoundtrip(httpSrv.URL, sendData)
	// t.Logf("#%d %v", i, err)
	if err != nil {
		t.Errorf("got error: %v", err)
	}
}

func BenchmarkSOCKS4AProxy(b *testing.B) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	ln, err := TCPListener("")
	if err != nil {
		b.Error(err)
	}

	client := &Client{
		Connector:   SOCKS4AConnector(),
		Transporter: TCPTransporter(),
	}

	server := &Server{
		Listener: ln,
		Handler:  SOCKS4Handler(),
	}

	go server.Run()
	defer server.Close()

	for i := 0; i < b.N; i++ {
		if err := proxyRoundtrip(client, server, httpSrv.URL, sendData); err != nil {
			b.Error(err)
		}
	}
}

func BenchmarkSOCKS4AProxyParallel(b *testing.B) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	ln, err := TCPListener("")
	if err != nil {
		b.Error(err)
	}

	client := &Client{
		Connector:   SOCKS4AConnector(),
		Transporter: TCPTransporter(),
	}

	server := &Server{
		Listener: ln,
		Handler:  SOCKS4Handler(),
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

func socks5BindRoundtrip(t *testing.T, targetURL string, data []byte) (err error) {
	ln, err := TCPListener("")
	if err != nil {
		return
	}

	client := &Client{
		Connector:   SOCKS5BindConnector(url.UserPassword("admin", "123456")),
		Transporter: TCPTransporter(),
	}

	server := &Server{
		Handler:  SOCKS5Handler(UsersHandlerOption(url.UserPassword("admin", "123456"))),
		Listener: ln,
	}

	go server.Run()
	defer server.Close()

	conn, err := proxyConn(client, server)
	if err != nil {
		return
	}
	defer conn.Close()

	conn, err = client.Connect(conn, "")
	if err != nil {
		return
	}

	cc, err := net.Dial("tcp", conn.LocalAddr().String())
	if err != nil {
		return
	}
	defer cc.Close()

	if err = conn.(*socks5BindConn).Handshake(); err != nil {
		return
	}

	u, err := url.Parse(targetURL)
	if err != nil {
		return
	}
	hc, err := net.Dial("tcp", u.Host)
	if err != nil {
		return
	}
	go transport(hc, conn)

	return httpRoundtrip(cc, targetURL, data)
}

func TestSOCKS5Bind(t *testing.T) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	if err := socks5BindRoundtrip(t, httpSrv.URL, sendData); err != nil {
		t.Errorf("got error: %v", err)
	}
}

func socks5MuxBindRoundtrip(t *testing.T, targetURL string, data []byte) (err error) {
	ln, err := TCPListener("")
	if err != nil {
		return
	}

	l, err := net.Listen("tcp", "")
	if err != nil {
		return err
	}
	bindAddr := l.Addr().String()
	l.Close()

	client := &Client{
		Connector:   Socks5MuxBindConnector(),
		Transporter: SOCKS5MuxBindTransporter(bindAddr),
	}

	server := &Server{
		Handler:  SOCKS5Handler(UsersHandlerOption(url.UserPassword("admin", "123456"))),
		Listener: ln,
	}

	go server.Run()
	defer server.Close()

	return muxBindRoundtrip(client, server, bindAddr, targetURL, data)
}

func muxBindRoundtrip(client *Client, server *Server, bindAddr, targetURL string, data []byte) (err error) {
	cn, err := client.Dial(server.Addr().String())
	if err != nil {
		return err
	}

	conn, err := client.Handshake(cn,
		AddrHandshakeOption(server.Addr().String()),
		UserHandshakeOption(url.UserPassword("admin", "123456")),
	)
	if err != nil {
		cn.Close()
		return err
	}
	defer conn.Close()

	cc, err := net.Dial("tcp", bindAddr)
	if err != nil {
		return
	}
	defer cc.Close()

	conn, err = client.Connect(conn, "")
	if err != nil {
		return
	}

	u, err := url.Parse(targetURL)
	if err != nil {
		return
	}
	hc, err := net.Dial("tcp", u.Host)
	if err != nil {
		return
	}
	defer hc.Close()

	go transport(hc, conn)

	return httpRoundtrip(cc, targetURL, data)
}

func TestSOCKS5MuxBind(t *testing.T) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	if err := socks5MuxBindRoundtrip(t, httpSrv.URL, sendData); err != nil {
		t.Errorf("got error: %v", err)
	}
}

func BenchmarkSOCKS5MuxBind(b *testing.B) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	ln, err := TCPListener("")
	if err != nil {
		b.Error(err)
	}

	l, err := net.Listen("tcp", "")
	if err != nil {
		b.Error(err)
	}
	bindAddr := l.Addr().String()
	l.Close()

	client := &Client{
		Connector:   Socks5MuxBindConnector(),
		Transporter: SOCKS5MuxBindTransporter(bindAddr),
	}

	server := &Server{
		Handler:  SOCKS5Handler(UsersHandlerOption(url.UserPassword("admin", "123456"))),
		Listener: ln,
	}

	go server.Run()
	defer server.Close()

	for i := 0; i < b.N; i++ {
		if err := muxBindRoundtrip(client, server, bindAddr, httpSrv.URL, sendData); err != nil {
			b.Error(err)
		}
	}
}

func socks5UDPRoundtrip(t *testing.T, host string, data []byte) (err error) {
	ln, err := TCPListener("")
	if err != nil {
		return
	}

	client := &Client{
		Connector:   SOCKS5UDPConnector(url.UserPassword("admin", "123456")),
		Transporter: TCPTransporter(),
	}

	server := &Server{
		Handler:  SOCKS5Handler(UsersHandlerOption(url.UserPassword("admin", "123456"))),
		Listener: ln,
	}
	go server.Run()
	defer server.Close()

	return udpRoundtrip(client, server, host, data)
}

func TestSOCKS5UDP(t *testing.T) {
	udpSrv := newUDPTestServer(udpTestHandler)
	udpSrv.Start()
	defer udpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	if err := socks5UDPRoundtrip(t, udpSrv.Addr(), sendData); err != nil {
		t.Errorf("got error: %v", err)
	}
}

// TODO: fix a probability of timeout.
func BenchmarkSOCKS5UDP(b *testing.B) {
	udpSrv := newUDPTestServer(udpTestHandler)
	udpSrv.Start()
	defer udpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	ln, err := TCPListener("")
	if err != nil {
		b.Error(err)
	}

	client := &Client{
		Connector:   SOCKS5UDPConnector(url.UserPassword("admin", "123456")),
		Transporter: TCPTransporter(),
	}

	server := &Server{
		Handler:  SOCKS5Handler(UsersHandlerOption(url.UserPassword("admin", "123456"))),
		Listener: ln,
	}
	go server.Run()
	defer server.Close()

	for i := 0; i < b.N; i++ {
		if err := udpRoundtrip(client, server, udpSrv.Addr(), sendData); err != nil {
			b.Error(err)
		}
	}
}

func BenchmarkSOCKS5UDPSingleConn(b *testing.B) {
	udpSrv := newUDPTestServer(udpTestHandler)
	udpSrv.Start()
	defer udpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	ln, err := TCPListener("")
	if err != nil {
		b.Error(err)
	}

	client := &Client{
		Connector:   SOCKS5UDPConnector(url.UserPassword("admin", "123456")),
		Transporter: TCPTransporter(),
	}

	server := &Server{
		Handler:  SOCKS5Handler(UsersHandlerOption(url.UserPassword("admin", "123456"))),
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
		b.Error(err)
	}

	roundtrip := func(conn net.Conn, data []byte) error {
		conn.SetDeadline(time.Now().Add(1 * time.Second))
		defer conn.SetDeadline(time.Time{})

		if _, err = conn.Write(data); err != nil {
			return err
		}

		recv := make([]byte, len(data))
		if _, err = conn.Read(recv); err != nil {
			return err
		}

		if !bytes.Equal(data, recv) {
			return fmt.Errorf("data not equal")
		}
		return nil
	}

	for i := 0; i < b.N; i++ {
		if err := roundtrip(conn, sendData); err != nil {
			b.Error(err)
		}
	}
}

func socks5UDPTunRoundtrip(t *testing.T, host string, data []byte) (err error) {
	ln, err := TCPListener("")
	if err != nil {
		return
	}

	client := &Client{
		Connector:   SOCKS5UDPTunConnector(url.UserPassword("admin", "123456")),
		Transporter: TCPTransporter(),
	}

	server := &Server{
		Handler:  SOCKS5Handler(UsersHandlerOption(url.UserPassword("admin", "123456"))),
		Listener: ln,
	}
	go server.Run()
	defer server.Close()

	return udpRoundtrip(client, server, host, data)
}

func TestSOCKS5UDPTun(t *testing.T) {
	udpSrv := newUDPTestServer(udpTestHandler)
	udpSrv.Start()
	defer udpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	if err := socks5UDPTunRoundtrip(t, udpSrv.Addr(), sendData); err != nil {
		t.Errorf("got error: %v", err)
	}
}

func BenchmarkSOCKS5UDPTun(b *testing.B) {
	udpSrv := newUDPTestServer(udpTestHandler)
	udpSrv.Start()
	defer udpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	ln, err := TCPListener("")
	if err != nil {
		b.Error(err)
	}

	client := &Client{
		Connector:   SOCKS5UDPTunConnector(url.UserPassword("admin", "123456")),
		Transporter: TCPTransporter(),
	}

	server := &Server{
		Handler:  SOCKS5Handler(UsersHandlerOption(url.UserPassword("admin", "123456"))),
		Listener: ln,
	}
	go server.Run()
	defer server.Close()

	for i := 0; i < b.N; i++ {
		if err := udpRoundtrip(client, server, udpSrv.Addr(), sendData); err != nil {
			b.Error(err)
		}
	}
}

func BenchmarkSOCKS5UDPTunSingleConn(b *testing.B) {
	udpSrv := newUDPTestServer(udpTestHandler)
	udpSrv.Start()
	defer udpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	ln, err := TCPListener("")
	if err != nil {
		b.Error(err)
	}

	client := &Client{
		Connector:   SOCKS5UDPTunConnector(url.UserPassword("admin", "123456")),
		Transporter: TCPTransporter(),
	}

	server := &Server{
		Handler:  SOCKS5Handler(UsersHandlerOption(url.UserPassword("admin", "123456"))),
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
		b.Error(err)
	}

	roundtrip := func(conn net.Conn, data []byte) error {
		conn.SetDeadline(time.Now().Add(1 * time.Second))
		defer conn.SetDeadline(time.Time{})

		if _, err = conn.Write(data); err != nil {
			return err
		}

		recv := make([]byte, len(data))
		if _, err = conn.Read(recv); err != nil {
			return err
		}

		if !bytes.Equal(data, recv) {
			return fmt.Errorf("data not equal")
		}
		return nil
	}

	for i := 0; i < b.N; i++ {
		if err := roundtrip(conn, sendData); err != nil {
			b.Error(err)
		}
	}
}
