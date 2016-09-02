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
	glog.V(LINFO).Infof("[http] %s - %s", conn.RemoteAddr(), req.Host)

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
			glog.V(LWARNING).Infof("[http] %s <- %s : %s", conn.RemoteAddr(), req.Host, err)
		}
		glog.V(LDEBUG).Infof("[http] %s <- %s\n%s", conn.RemoteAddr(), req.Host, resp)

		glog.V(LWARNING).Infof("[http] %s <- %s : proxy authentication required", conn.RemoteAddr(), req.Host)
		return
	}

	c, err := Connect(req.Host)
	if err != nil {
		glog.V(LWARNING).Infof("[http] %s -> %s : %s", conn.RemoteAddr(), req.Host, err)

		b := []byte("HTTP/1.1 503 Service unavailable\r\n" +
			"Proxy-Agent: gost/" + Version + "\r\n\r\n")
		glog.V(LDEBUG).Infof("[http] %s <- %s\n%s", conn.RemoteAddr(), req.Host, string(b))
		conn.Write(b)
		return
	}
	defer c.Close()

	if req.Method == "CONNECT" {
		b := []byte("HTTP/1.1 200 Connection established\r\n" +
			"Proxy-Agent: gost/" + Version + "\r\n\r\n")
		glog.V(LDEBUG).Infof("[http] %s <- %s\n%s", conn.RemoteAddr(), req.Host, string(b))

		if _, err := conn.Write(b); err != nil {
			glog.V(LWARNING).Infof("[http] %s <- %s : %s", conn.RemoteAddr(), req.Host, err)
			return
		}
	} else {
		req.Header.Del("Proxy-Connection")
		req.Header.Set("Connection", "Keep-Alive")

		if err = req.Write(c); err != nil {
			glog.V(LWARNING).Infof("[http] %s -> %s : %s", conn.RemoteAddr(), req.Host, err)
			return
		}
	}

	glog.V(LINFO).Infof("[http] %s <-> %s", conn.RemoteAddr(), req.Host)
	Transport(conn, c)
	glog.V(LINFO).Infof("[http] %s >-< %s", conn.RemoteAddr(), req.Host)
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
