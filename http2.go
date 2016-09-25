package main

import (
	"bufio"
	"github.com/golang/glog"
	"golang.org/x/net/http2"
	"io"
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

	fw := flushWriter{w}

	c, err = Connect(req.Host)
	if err != nil {
		glog.V(LWARNING).Infof("[http2] %s -> %s : %s", req.RemoteAddr, req.Host, err)
		b := []byte("HTTP/1.1 503 Service unavailable\r\n" +
			"Proxy-Agent: gost/" + Version + "\r\n\r\n")
		glog.V(LDEBUG).Infof("[http2] %s <- %s\n%s", req.RemoteAddr, req.Host, string(b))
		//w.WriteHeader(http.StatusServiceUnavailable)
		fw.Write(b)
		return
	}
	defer c.Close()

	rChan := make(chan error, 1)
	wChan := make(chan error, 1)

	if req.Method == http.MethodConnect {
		w.Header().Set("Proxy-Agent", "gost/"+Version)
		w.WriteHeader(http.StatusOK)

		if fw, ok := w.(http.Flusher); ok {
			fw.Flush()
		}

		// compatible with HTTP 1.x
		if hj, ok := w.(http.Hijacker); ok && req.ProtoMajor == 1 {
			conn, _, err := hj.Hijack()
			if err != nil {
				glog.V(LWARNING).Infoln(err)
				return
			}
			defer conn.Close()

			go Pipe(conn, c, rChan)
			go Pipe(c, conn, wChan)
		} else {
			go Pipe(req.Body, c, rChan)
			go Pipe(c, fw, wChan)
		}

		select {
		case err := <-rChan:
			glog.V(LWARNING).Infoln("r exit", err)
		case err := <-wChan:
			glog.V(LWARNING).Infoln("w exit", err)
		}

	} else {
		req.Header.Set("Connection", "Keep-Alive")
		if err = req.Write(c); err != nil {
			glog.V(LWARNING).Infof("[http2] %s -> %s : %s", req.RemoteAddr, req.Host, err)
			return
		}

		resp, err := http.ReadResponse(bufio.NewReader(c), req)
		if err != nil {
			glog.V(LWARNING).Infoln(err)
			return
		}
		defer resp.Body.Close()

		for k, v := range resp.Header {
			for _, vv := range v {
				w.Header().Add(k, vv)
			}
		}

		w.WriteHeader(resp.StatusCode)
		if _, err := io.Copy(fw, resp.Body); err != nil {
			glog.V(LWARNING).Infoln(err)
		}
	}

	//glog.V(LINFO).Infof("[http2] %s <-> %s", req.RemoteAddr, req.Host)

	//glog.V(LINFO).Infof("[http2] %s >-< %s", req.RemoteAddr, req.Host)
}

type flushWriter struct {
	w io.Writer
}

func (fw flushWriter) Write(p []byte) (n int, err error) {
	n, err = fw.w.Write(p)
	if f, ok := fw.w.(http.Flusher); ok {
		f.Flush()
	}
	return
}
