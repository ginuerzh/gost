package main

import (
	"encoding/base64"
	"github.com/golang/glog"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
)

func handleHttpRequest(req *http.Request, conn net.Conn, arg Args) {
	if glog.V(LDEBUG) {
		dump, err := httputil.DumpRequest(req, false)
		if err != nil {
			glog.Infoln(err)
		} else {
			glog.Infoln(string(dump))
		}
	}
	glog.V(LINFO).Infoln("[http] CONNECT", req.Host)

	var username, password string
	if arg.User != nil {
		username = arg.User.Username()
		password, _ = arg.User.Password()
	}

	u, p, _ := basicAuth(req.Header.Get("Proxy-Authorization"))
	req.Header.Del("Proxy-Authorization")

	if (username != "" && u != username) || (password != "" && p != password) {
		resp := "HTTP/1.1 407 Proxy Authentication Required\r\n" +
			"Proxy-Authenticate: Basic realm=\"gost\"\r\n" +
			"Proxy-Agent: gost/" + Version + "\r\n\r\n"

		if _, err := conn.Write([]byte(resp)); err != nil {
			glog.V(LWARNING).Infoln(err)
		}
		glog.V(LDEBUG).Infoln(resp)

		glog.V(LWARNING).Infoln("http: proxy authentication required")
		return
	}

	c, err := Connect(req.Host)
	if err != nil {
		glog.V(LWARNING).Infoln("[http] CONNECT", req.Host, err)

		b := []byte("HTTP/1.1 503 Service unavailable\r\n" +
			"Proxy-Agent: gost/" + Version + "\r\n\r\n")
		glog.V(LDEBUG).Infoln(string(b))
		conn.Write(b)
		return
	}
	defer c.Close()

	if req.Method == "CONNECT" {
		b := []byte("HTTP/1.1 200 Connection established\r\n" +
			"Proxy-Agent: gost/" + Version + "\r\n\r\n")
		glog.V(LDEBUG).Infoln(string(b))

		if _, err := conn.Write(b); err != nil {
			glog.V(LWARNING).Infoln(err)
			return
		}
	} else {
		if len(forwardArgs) > 0 {
			err = req.WriteProxy(c)
		} else {
			err = req.Write(c)
		}
		if err != nil {
			glog.V(LWARNING).Infoln(err)
			return
		}
	}

	glog.V(LINFO).Infoln("[http] CONNECT", req.Host, "OK")
	Transport(conn, c)
}

func basicAuth(authInfo string) (username, password string, ok bool) {
	if authInfo == "" {
		return
	}

	if !strings.HasPrefix(authInfo, "Basic ") {
		return
	}
	c, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(authInfo, "Basic "))
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
