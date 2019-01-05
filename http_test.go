package gost

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
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

func TestHTTPProxyAuth(t *testing.T) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	for i, tc := range httpProxyTests {
		tc := tc
		t.Run(fmt.Sprintf("#%d", i), func(t *testing.T) {
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
		})
	}
}

func TestHTTPProxyWithInvalidRequest(t *testing.T) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	ln, err := TCPListener("")
	if err != nil {
		t.Error(err)
	}

	server := &Server{
		Listener: ln,
		Handler:  HTTPHandler(),
	}
	go server.Run()
	defer server.Close()

	r, err := http.NewRequest("GET", "http://"+ln.Addr().String(), bytes.NewReader(sendData))
	if err != nil {
		t.Error(err)
	}
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Error(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Error("got status:", resp.Status)
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

func TestHTTPProxyWithCodeProbeResist(t *testing.T) {
	ln, err := TCPListener("")
	if err != nil {
		t.Error(err)
	}

	server := &Server{
		Listener: ln,
		Handler: HTTPHandler(
			UsersHandlerOption(url.UserPassword("admin", "123456")),
			ProbeResistHandlerOption("code:400"),
		),
	}
	go server.Run()
	defer server.Close()

	resp, err := http.Get("http://" + ln.Addr().String())
	if err != nil {
		t.Error(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 400 {
		t.Error("should failed with status code 400, got", resp.Status)
	}
}

func TestHTTPProxyWithWebProbeResist(t *testing.T) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	ln, err := TCPListener("")
	if err != nil {
		t.Error(err)
	}

	u, err := url.Parse(httpSrv.URL)
	if err != nil {
		t.Error(err)
	}
	server := &Server{
		Listener: ln,
		Handler: HTTPHandler(
			UsersHandlerOption(url.UserPassword("admin", "123456")),
			ProbeResistHandlerOption("web:"+u.Host),
		),
	}
	go server.Run()
	defer server.Close()

	r, err := http.NewRequest("GET", "http://"+ln.Addr().String(), nil)
	if err != nil {
		t.Error(err)
	}
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Error(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Error("got status:", resp.Status)
	}

	recv, _ := ioutil.ReadAll(resp.Body)
	if !bytes.Equal(recv, []byte("Hello World!")) {
		t.Error("data not equal")
	}
}

func TestHTTPProxyWithHostProbeResist(t *testing.T) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	ln, err := TCPListener("")
	if err != nil {
		t.Error(err)
	}

	u, err := url.Parse(httpSrv.URL)
	if err != nil {
		t.Error(err)
	}

	server := &Server{
		Listener: ln,
		Handler: HTTPHandler(
			UsersHandlerOption(url.UserPassword("admin", "123456")),
			ProbeResistHandlerOption("host:"+u.Host),
		),
	}
	go server.Run()
	defer server.Close()

	r, err := http.NewRequest("GET", "http://"+ln.Addr().String(), bytes.NewReader(sendData))
	if err != nil {
		t.Error(err)
	}
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Error(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Error("got status:", resp.Status)
	}

	recv, _ := ioutil.ReadAll(resp.Body)
	if !bytes.Equal(sendData, recv) {
		t.Error("data not equal")
	}
}

func TestHTTPProxyWithFileProbeResist(t *testing.T) {
	ln, err := TCPListener("")
	if err != nil {
		t.Error(err)
	}

	server := &Server{
		Listener: ln,
		Handler: HTTPHandler(
			UsersHandlerOption(url.UserPassword("admin", "123456")),
			ProbeResistHandlerOption("file:.testdata/probe_resist.txt"),
		),
	}
	go server.Run()
	defer server.Close()

	r, err := http.NewRequest("GET", "http://"+ln.Addr().String(), nil)
	if err != nil {
		t.Error(err)
	}
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Error(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Error("got status:", resp.Status)
	}

	recv, _ := ioutil.ReadAll(resp.Body)
	if !bytes.Equal(recv, []byte("Hello World!")) {
		t.Error("data not equal, got:", string(recv))
	}
}

func TestHTTPProxyWithBypass(t *testing.T) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	u, err := url.Parse(httpSrv.URL)
	if err != nil {
		t.Error(err)
	}
	ln, err := TCPListener("")
	if err != nil {
		t.Error(err)
	}

	client := &Client{
		Connector:   HTTPConnector(nil),
		Transporter: TCPTransporter(),
	}

	host := u.Host
	if h, _, _ := net.SplitHostPort(u.Host); h != "" {
		host = h
	}
	server := &Server{
		Listener: ln,
		Handler: HTTPHandler(
			BypassHandlerOption(NewBypassPatterns(false, host)),
		),
	}
	go server.Run()
	defer server.Close()

	if err = proxyRoundtrip(client, server, httpSrv.URL, sendData); err == nil {
		t.Error("should failed")
	}
}
