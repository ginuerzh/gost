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

	var username, password string
	if arg.User != nil {
		username = arg.User.Username()
		password, _ = arg.User.Password()
	}

	u, p, _ := proxyBasicAuth(req.Header.Get("Proxy-Authorization"))
	req.Header.Del("Proxy-Authorization")

	if (username != "" && u != username) || (password != "" && p != password) {
		resp := "HTTP/1.1 407 Proxy Authentication Required\r\n" +
			"Proxy-Authenticate: Basic realm=\"gost\"\r\n" +
			"Proxy-Agent: gost/" + Version + "\r\n\r\n"

		if _, err := conn.Write([]byte(resp)); err != nil {
			if glog.V(LWARNING) {
				glog.Warningln(err)
			}
		}
		if glog.V(LDEBUG) {
			glog.Infoln(resp)
		}
		if glog.V(LWARNING) {
			glog.Warningln("http: proxy authentication required")
		}
		return
	}
}

func proxyBasicAuth(authInfo string) (username, password string, ok bool) {
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
