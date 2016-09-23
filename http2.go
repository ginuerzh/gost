package main

import (
	"github.com/golang/glog"
	"golang.org/x/net/http2"
	"net"
	"net/http"
	"net/http/httputil"
)

func init() {
	http2.VerboseLogs = true
}

func handlerHttp2Request(w http.ResponseWriter, req *http.Request) {
	glog.V(LINFO).Infof("[http2] %s - %s", req.RemoteAddr, req.Host)

	if glog.V(LDEBUG) {
		dump, err := httputil.DumpRequest(req, false)
		if err != nil {
			glog.Infoln(err)
		} else {
			glog.Infoln(string(dump))
		}
	}

	var c net.Conn
	var err error

	c, err = Connect(req.Host)
	if err != nil {
		glog.V(LWARNING).Infof("[http2] %s -> %s : %s", req.RemoteAddr, req.Host, err)
		b := []byte("HTTP/1.1 503 Service unavailable\r\n" +
			"Proxy-Agent: gost/" + Version + "\r\n\r\n")
		glog.V(LDEBUG).Infof("[http2] %s <- %s\n%s", req.RemoteAddr, req.Host, string(b))
		//w.WriteHeader(http.StatusServiceUnavailable)
		w.Write(b)
		return
	}
	defer c.Close()

	if req.Method == http.MethodConnect {
		b := []byte("HTTP/2.0 200 Connection established\r\n" +
			"Proxy-Agent: gost/" + Version + "\r\n\r\n")
		glog.V(LDEBUG).Infof("[http2] %s <- %s\n%s", req.RemoteAddr, req.Host, string(b))
		w.Write(b)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	} else {
		req.Header.Set("Connection", "Keep-Alive")
		if err = req.Write(c); err != nil {
			glog.V(LWARNING).Infof("[http2] %s -> %s : %s", req.RemoteAddr, req.Host, err)
			return
		}
	}

	glog.V(LINFO).Infof("[http2] %s <-> %s", req.RemoteAddr, req.Host)

	rChan := make(chan error, 1)
	wChan := make(chan error, 1)
	go Pipe(c, w, wChan)
	go Pipe(req.Body, c, rChan)

	select {
	case err = <-wChan:
		glog.V(LWARNING).Infoln("w exit", err)
	case err = <-rChan:
		glog.V(LWARNING).Infoln("r exit", err)
	}

	glog.V(LINFO).Infof("[http2] %s >-< %s", req.RemoteAddr, req.Host)
}
