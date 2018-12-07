package gost

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

var httpTestHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	io.Copy(w, r.Body)
})

func httpProxyRoundtrip(urlStr string, cliUser *url.Userinfo, srvUsers []*url.Userinfo, body io.Reader) (statusCode int, recv []byte, err error) {
	ln, err := TCPListener("")
	if err != nil {
		return
	}
	h := HTTPHandler(UsersHandlerOption(srvUsers...))
	server := &Server{Listener: ln}
	go server.Serve(h)

	exitChan := make(chan struct{})
	defer close(exitChan)
	go func() {
		defer server.Close()
		<-exitChan
	}()

	client := &Client{
		Connector:   HTTPConnector(cliUser),
		Transporter: TCPTransporter(),
	}
	conn, err := client.Dial(ln.Addr().String())
	if err != nil {
		return
	}
	defer conn.Close()
	conn, err = client.Handshake(conn)
	if err != nil {
		return
	}
	url, err := url.Parse(urlStr)
	if err != nil {
		return
	}
	conn, err = client.Connect(conn, url.Host)
	if err != nil {
		return
	}
	req, err := http.NewRequest(http.MethodGet, urlStr, body)
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
	statusCode = resp.StatusCode
	recv, err = ioutil.ReadAll(resp.Body)
	return
}

var httpProxyTests = []struct {
	url      string
	cliUser  *url.Userinfo
	srvUsers []*url.Userinfo
	errStr   string
}{
	{"", nil, nil, ""},
	{"", nil, []*url.Userinfo{url.User("admin")}, "407 Proxy Authentication Required"},
	{"", nil, []*url.Userinfo{url.UserPassword("", "123456")}, "407 Proxy Authentication Required"},
	{"", url.User("admin"), []*url.Userinfo{url.User("test")}, "407 Proxy Authentication Required"},
	{"", url.User("admin"), []*url.Userinfo{url.UserPassword("admin", "123456")}, "407 Proxy Authentication Required"},
	{"", url.User("admin"), []*url.Userinfo{url.User("admin")}, ""},
	{"", url.User("admin"), []*url.Userinfo{url.UserPassword("admin", "")}, ""},
	{"", url.UserPassword("admin", "123456"), nil, ""},
	{"", url.UserPassword("admin", "123456"), []*url.Userinfo{url.User("admin")}, ""},
	{"", url.UserPassword("admin", "123456"), []*url.Userinfo{url.UserPassword("", "123456")}, ""},
	{"", url.UserPassword("", "123456"), []*url.Userinfo{url.UserPassword("", "123456")}, ""},
	{"", url.UserPassword("admin", "123456"), []*url.Userinfo{url.UserPassword("admin", "123456")}, ""},
	{"", url.UserPassword("admin", "123456"), []*url.Userinfo{url.UserPassword("user", "pass"), url.UserPassword("admin", "123456")}, ""},
	{"http://:0", nil, nil, "503 Service Unavailable"},
}

func TestHTTPProxy(t *testing.T) {
	Debug = true
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	for _, test := range httpProxyTests {
		send := make([]byte, 16)
		rand.Read(send)
		urlStr := test.url
		if urlStr == "" {
			urlStr = httpSrv.URL
		}
		_, recv, err := httpProxyRoundtrip(urlStr, test.cliUser, test.srvUsers, bytes.NewReader(send))
		if err == nil {
			if test.errStr != "" {
				t.Errorf("HTTP proxy response should failed with error %s", test.errStr)
				continue
			}
		} else {
			if test.errStr == "" {
				t.Errorf("HTTP proxy got error %v", err)
			}
			if err.Error() != test.errStr {
				t.Errorf("HTTP proxy got error %v, want %v", err, test.errStr)
			}
			continue
		}
		if !bytes.Equal(send, recv) {
			t.Errorf("got %v, want %v", recv, send)
			continue
		}
	}
}
