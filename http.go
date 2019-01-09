package gost

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

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

func (c *httpConnector) Connect(conn net.Conn, addr string, options ...ConnectOption) (net.Conn, error) {
	opts := &ConnectOptions{}
	for _, option := range options {
		option(opts)
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = ConnectTimeout
	}

	conn.SetDeadline(time.Now().Add(timeout))
	defer conn.SetDeadline(time.Time{})

	req := &http.Request{
		Method:     http.MethodConnect,
		URL:        &url.URL{Host: addr},
		Host:       addr,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
	}
	req.Header.Set("User-Agent", DefaultUserAgent)
	req.Header.Set("Proxy-Connection", "keep-alive")

	user := opts.User
	if user == nil {
		user = c.User
	}

	if user != nil {
		u := user.Username()
		p, _ := user.Password()
		req.Header.Set("Proxy-Authorization",
			"Basic "+base64.StdEncoding.EncodeToString([]byte(u+":"+p)))
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
	h := &httpHandler{}
	h.Init(opts...)
	return h
}

func (h *httpHandler) Init(options ...HandlerOption) {
	if h.options == nil {
		h.options = &HandlerOptions{}
	}
	for _, opt := range options {
		opt(h.options)
	}
}

func (h *httpHandler) Handle(conn net.Conn) {
	defer conn.Close()

	req, err := http.ReadRequest(bufio.NewReader(conn))
	if err != nil {
		log.Logf("[http] %s - %s : %s", conn.RemoteAddr(), conn.LocalAddr(), err)
		return
	}
	defer req.Body.Close()

	h.handleRequest(conn, req)
}

func (h *httpHandler) handleRequest(conn net.Conn, req *http.Request) {
	if req == nil {
		return
	}

	host := req.Host
	// try to get the actual host.
	if v := req.Header.Get("Gost-Target"); v != "" {
		if h, err := decodeServerName(v); err == nil {
			host = h
		}
	}

	if _, port, _ := net.SplitHostPort(host); port == "" {
		host = net.JoinHostPort(host, "80")
	}

	u, _, _ := basicProxyAuth(req.Header.Get("Proxy-Authorization"))
	if u != "" {
		u += "@"
	}
	log.Logf("[http] %s%s -> %s -> %s",
		u, conn.RemoteAddr(), h.options.Node.String(), host)

	if Debug {
		dump, _ := httputil.DumpRequest(req, false)
		log.Logf("[http] %s -> %s\n%s", conn.RemoteAddr(), conn.LocalAddr(), string(dump))
	}

	req.Host = host
	req.Header.Del("Gost-Target")

	resp := &http.Response{
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     http.Header{},
	}
	resp.Header.Add("Proxy-Agent", "gost/"+Version)

	if !Can("tcp", host, h.options.Whitelist, h.options.Blacklist) {
		log.Logf("[http] %s - %s : Unauthorized to tcp connect to %s",
			conn.RemoteAddr(), conn.LocalAddr(), host)
		resp.StatusCode = http.StatusForbidden

		if Debug {
			dump, _ := httputil.DumpResponse(resp, false)
			log.Logf("[http] %s <- %s\n%s", conn.RemoteAddr(), conn.LocalAddr(), string(dump))
		}

		resp.Write(conn)
		return
	}

	if h.options.Bypass.Contains(host) {
		resp.StatusCode = http.StatusForbidden

		log.Logf("[http] %s - %s bypass %s",
			conn.RemoteAddr(), conn.LocalAddr(), host)
		if Debug {
			dump, _ := httputil.DumpResponse(resp, false)
			log.Logf("[http] %s <- %s\n%s", conn.RemoteAddr(), conn.LocalAddr(), string(dump))
		}

		resp.Write(conn)
		return
	}

	if !h.authenticate(conn, req, resp) {
		return
	}

	if req.Method == "PRI" || (req.Method != http.MethodConnect && req.URL.Scheme != "http") {
		resp.StatusCode = http.StatusBadRequest

		if Debug {
			dump, _ := httputil.DumpResponse(resp, false)
			log.Logf("[http] %s <- %s\n%s",
				conn.RemoteAddr(), conn.LocalAddr(), string(dump))
		}

		resp.Write(conn)
		return
	}

	req.Header.Del("Proxy-Authorization")

	retries := 1
	if h.options.Chain != nil && h.options.Chain.Retries > 0 {
		retries = h.options.Chain.Retries
	}
	if h.options.Retries > 0 {
		retries = h.options.Retries
	}

	var err error
	var cc net.Conn
	var route *Chain
	for i := 0; i < retries; i++ {
		route, err = h.options.Chain.selectRouteFor(host)
		if err != nil {
			log.Logf("[http] %s -> %s : %s",
				conn.RemoteAddr(), conn.LocalAddr(), err)
			continue
		}

		buf := bytes.Buffer{}
		fmt.Fprintf(&buf, "%s -> %s -> ",
			conn.RemoteAddr(), h.options.Node.String())
		for _, nd := range route.route {
			fmt.Fprintf(&buf, "%d@%s -> ", nd.ID, nd.String())
		}
		fmt.Fprintf(&buf, "%s", host)
		log.Log("[route]", buf.String())

		// forward http request
		lastNode := route.LastNode()
		if req.Method != http.MethodConnect && lastNode.Protocol == "http" {
			err = h.forwardRequest(conn, req, route)
			if err == nil {
				return
			}
			log.Logf("[http] %s -> %s : %s", conn.RemoteAddr(), conn.LocalAddr(), err)
			continue
		}

		cc, err = route.Dial(host,
			TimeoutChainOption(h.options.Timeout),
			HostsChainOption(h.options.Hosts),
			ResolverChainOption(h.options.Resolver),
		)
		if err == nil {
			break
		}
		log.Logf("[http] %s -> %s : %s", conn.RemoteAddr(), conn.LocalAddr(), err)
	}

	if err != nil {
		resp.StatusCode = http.StatusServiceUnavailable

		if Debug {
			dump, _ := httputil.DumpResponse(resp, false)
			log.Logf("[http] %s <- %s\n%s", conn.RemoteAddr(), conn.LocalAddr(), string(dump))
		}

		resp.Write(conn)
		return
	}
	defer cc.Close()

	if req.Method == http.MethodConnect {
		b := []byte("HTTP/1.1 200 Connection established\r\n" +
			"Proxy-Agent: gost/" + Version + "\r\n\r\n")
		if Debug {
			log.Logf("[http] %s <- %s\n%s", conn.RemoteAddr(), conn.LocalAddr(), string(b))
		}
		conn.Write(b)
	} else {
		req.Header.Del("Proxy-Connection")

		if err = req.Write(cc); err != nil {
			log.Logf("[http] %s -> %s : %s", conn.RemoteAddr(), conn.LocalAddr(), err)
			return
		}
	}

	log.Logf("[http] %s <-> %s", conn.RemoteAddr(), host)
	transport(conn, cc)
	log.Logf("[http] %s >-< %s", conn.RemoteAddr(), host)
}

func (h *httpHandler) authenticate(conn net.Conn, req *http.Request, resp *http.Response) (ok bool) {
	u, p, _ := basicProxyAuth(req.Header.Get("Proxy-Authorization"))
	if Debug && (u != "" || p != "") {
		log.Logf("[http] %s -> %s : Authorization '%s' '%s'",
			conn.RemoteAddr(), conn.LocalAddr(), u, p)
	}
	if h.options.Authenticator == nil || h.options.Authenticator.Authenticate(u, p) {
		return true
	}

	// probing resistance is enabled
	if ss := strings.SplitN(h.options.ProbeResist, ":", 2); len(ss) == 2 {
		switch ss[0] {
		case "code":
			resp.StatusCode, _ = strconv.Atoi(ss[1])
		case "web":
			url := ss[1]
			if !strings.HasPrefix(url, "http") {
				url = "http://" + url
			}
			if r, err := http.Get(url); err == nil {
				resp = r
			}
		case "host":
			cc, err := net.Dial("tcp", ss[1])
			if err == nil {
				defer cc.Close()

				req.Write(cc)
				log.Logf("[http] %s <-> %s : forward to %s",
					conn.RemoteAddr(), conn.LocalAddr(), ss[1])
				transport(conn, cc)
				log.Logf("[http] %s >-< %s : forward to %s",
					conn.RemoteAddr(), conn.LocalAddr(), ss[1])
				return
			}
		case "file":
			f, _ := os.Open(ss[1])
			if f != nil {
				resp.StatusCode = http.StatusOK
				if finfo, _ := f.Stat(); finfo != nil {
					resp.ContentLength = finfo.Size()
				}
				resp.Header.Set("Content-Type", "text/html")
				resp.Body = f
			}
		}
	}

	if resp.StatusCode == 0 {
		log.Logf("[http] %s <- %s : proxy authentication required",
			conn.RemoteAddr(), conn.LocalAddr())
		resp.StatusCode = http.StatusProxyAuthRequired
		resp.Header.Add("Proxy-Authenticate", "Basic realm=\"gost\"")
	} else {
		resp.Header = http.Header{}
		resp.Header.Set("Server", "nginx/1.14.1")
		resp.Header.Set("Date", time.Now().Format(http.TimeFormat))
		if resp.StatusCode == http.StatusOK {
			resp.Header.Set("Connection", "keep-alive")
		}
	}

	if Debug {
		dump, _ := httputil.DumpResponse(resp, false)
		log.Logf("[http] %s <- %s\n%s",
			conn.RemoteAddr(), conn.LocalAddr(), string(dump))
	}

	resp.Write(conn)
	return
}

func (h *httpHandler) forwardRequest(conn net.Conn, req *http.Request, route *Chain) error {
	if route.IsEmpty() {
		return nil
	}
	lastNode := route.LastNode()

	cc, err := route.Conn()
	if err != nil {
		return err
	}
	defer cc.Close()

	if lastNode.User != nil {
		s := lastNode.User.String()
		if _, set := lastNode.User.Password(); !set {
			s += ":"
		}
		req.Header.Set("Proxy-Authorization",
			"Basic "+base64.StdEncoding.EncodeToString([]byte(s)))
	}

	cc.SetWriteDeadline(time.Now().Add(WriteTimeout))
	if !req.URL.IsAbs() {
		req.URL.Scheme = "http" // make sure that the URL is absolute
	}
	if err = req.WriteProxy(cc); err != nil {
		log.Logf("[http] %s -> %s : %s", conn.RemoteAddr(), conn.LocalAddr(), err)
		return nil
	}
	cc.SetWriteDeadline(time.Time{})

	log.Logf("[http] %s <-> %s", conn.RemoteAddr(), req.Host)
	transport(conn, cc)
	log.Logf("[http] %s >-< %s", conn.RemoteAddr(), req.Host)
	return nil
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
