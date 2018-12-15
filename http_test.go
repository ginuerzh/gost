package gost

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// proxyConn obtains a connection to the proxy server.
func proxyConn(client *Client, server *Server) (net.Conn, error) {
	conn, err := client.Dial(server.Addr().String())
	if err != nil {
		return nil, err
	}

	cc, err := client.Handshake(conn, AddrHandshakeOption(server.Addr().String()))
	if err != nil {
		conn.Close()
		return nil, err
	}

	return cc, nil
}

// httpRoundtrip does a HTTP request-response roundtrip, and checks the data received.
func httpRoundtrip(conn net.Conn, targetURL string, data []byte) (err error) {
	req, err := http.NewRequest(
		http.MethodGet,
		targetURL,
		bytes.NewReader(data),
	)
	if err != nil {
		return
	}
	if err = req.Write(conn); err != nil {
		return
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return errors.New(resp.Status)
	}

	recv, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}

	if !bytes.Equal(data, recv) {
		return fmt.Errorf("data not equal")
	}
	return
}

func proxyRoundtrip(client *Client, server *Server, targetURL string, data []byte) (err error) {
	conn, err := proxyConn(client, server)
	if err != nil {
		return err
	}
	defer conn.Close()

	u, err := url.Parse(targetURL)
	if err != nil {
		return
	}

	conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
	defer conn.SetDeadline(time.Time{})

	conn, err = client.Connect(conn, u.Host)
	if err != nil {
		return
	}

	return httpRoundtrip(conn, targetURL, data)
}

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
