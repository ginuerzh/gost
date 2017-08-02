package gost

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/go-log/log"
)

type httpConnector struct {
	User *url.Userinfo
}

// HTTPConnector creates a Connector for HTTP proxy client.
// It accepts an optional auth info for HTTP Basic Authentication.
func HTTPConnector(user *url.Userinfo) Connector {
	return &httpConnector{User: user}
}

func (c *httpConnector) Connect(conn net.Conn, addr string) (net.Conn, error) {
	req := &http.Request{
		Method:     http.MethodConnect,
		URL:        &url.URL{Host: addr},
		Host:       addr,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
	}
	req.Header.Set("Proxy-Connection", "keep-alive")

	if c.User != nil {
		s := c.User.String()
		if _, set := c.User.Password(); !set {
			s += ":"
		}
		req.Header.Set("Proxy-Authorization",
			"Basic "+base64.StdEncoding.EncodeToString([]byte(s)))
	}

	if err := req.Write(conn); err != nil {
		return nil, err
	}

	if Debug {
		dump, _ := httputil.DumpRequest(req, false)
		log.Log(string(dump))
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return nil, err
	}

	if Debug {
		dump, _ := httputil.DumpResponse(resp, false)
		log.Log(string(dump))
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s", resp.Status)
	}

	return conn, nil
}

type httpHandler struct {
	options *HandlerOptions
}

// HTTPHandler creates a server Handler for HTTP proxy server.
func HTTPHandler(opts ...HandlerOption) Handler {
	h := &httpHandler{
		options: &HandlerOptions{},
	}
	for _, opt := range opts {
		opt(h.options)
	}
	return h
}

func (h *httpHandler) Handle(conn net.Conn) {
	defer conn.Close()

	req, err := http.ReadRequest(bufio.NewReader(conn))
	if err != nil {
		log.Logf("[http] %s - %s : %s", conn.RemoteAddr(), conn.LocalAddr(), err)
		return
	}

	if Debug {
		log.Logf("[http] %s %s - %s %s", req.Method, conn.RemoteAddr(), req.Host, req.Proto)
		dump, _ := httputil.DumpRequest(req, false)
		log.Logf(string(dump))
	}

	if req.Method == "PRI" && req.ProtoMajor == 2 {
		log.Logf("[http] %s <- %s : Not an HTTP2 server", conn.RemoteAddr(), req.Host)
		resp := "HTTP/1.1 400 Bad Request\r\n" +
			"Proxy-Agent: gost/" + Version + "\r\n\r\n"
		conn.Write([]byte(resp))
		return
	}

	u, p, _ := basicProxyAuth(req.Header.Get("Proxy-Authorization"))
	if !authenticate(u, p, h.options.Users...) {
		log.Logf("[http] %s <- %s : proxy authentication required", conn.RemoteAddr(), req.Host)
		resp := "HTTP/1.1 407 Proxy Authentication Required\r\n" +
			"Proxy-Authenticate: Basic realm=\"gost\"\r\n" +
			"Proxy-Agent: gost/" + Version + "\r\n\r\n"
		conn.Write([]byte(resp))
		return
	}

	req.Header.Del("Proxy-Authorization")

	// forward http request
	//lastNode := s.Base.Chain.lastNode
	//if lastNode != nil && lastNode.Transport == "" && (lastNode.Protocol == "http" || lastNode.Protocol == "") {
	//	s.forwardRequest(req)
	//	return
	//}

	// if !s.Base.Node.Can("tcp", req.Host) {
	//	glog.Errorf("Unauthorized to tcp connect to %s", req.Host)
	//	return
	// }

	host := req.Host
	if !strings.Contains(req.Host, ":") {
		host += ":80"
	}
	cc, err := h.options.Chain.Dial(host)
	if err != nil {
		log.Logf("[http] %s -> %s : %s", conn.RemoteAddr(), req.Host, err)

		b := []byte("HTTP/1.1 503 Service unavailable\r\n" +
			"Proxy-Agent: gost/" + Version + "\r\n\r\n")
		if Debug {
			log.Logf("[http] %s <- %s\n%s", conn.RemoteAddr(), req.Host, string(b))
		}
		conn.Write(b)
		return
	}
	defer cc.Close()

	if req.Method == http.MethodConnect {
		b := []byte("HTTP/1.1 200 Connection established\r\n" +
			"Proxy-Agent: gost/" + Version + "\r\n\r\n")
		if Debug {
			log.Logf("[http] %s <- %s\n%s", conn.RemoteAddr(), req.Host, string(b))
		}
		conn.Write(b)
	} else {
		req.Header.Del("Proxy-Connection")

		if err = req.Write(cc); err != nil {
			log.Logf("[http] %s -> %s : %s", conn.RemoteAddr(), req.Host, err)
			return
		}
	}

	log.Logf("[http] %s <-> %s", conn.RemoteAddr(), req.Host)
	transport(conn, cc)
	log.Logf("[http] %s >-< %s", conn.RemoteAddr(), req.Host)
}

func basicProxyAuth(proxyAuth string) (username, password string, ok bool) {
	if proxyAuth == "" {
		return
	}

	if !strings.HasPrefix(proxyAuth, "Basic ") {
		return
	}
	c, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(proxyAuth, "Basic "))
	if err != nil {
		return
	}
	cs := string(c)
	s := strings.IndexByte(cs, ':')
	if s < 0 {
		return
	}

	return cs[:s], cs[s+1:], true
}

func authenticate(username, password string, users ...*url.Userinfo) bool {
	if len(users) == 0 {
		return true
	}

	for _, user := range users {
		u := user.Username()
		p, _ := user.Password()
		if (u == username && p == password) ||
			(u == username && p == "") ||
			(u == "" && p == password) {
			return true
		}
	}
	return false
}
