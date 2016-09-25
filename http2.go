package main

import (
	"bufio"
	"github.com/golang/glog"
	"golang.org/x/net/http2"
	"io"
	//"net"
	"net/http"
	"net/http/httputil"
)

func init() {
	if glog.V(LDEBUG) {
		http2.VerboseLogs = true
	}
}

func handlerHttp2Request(w http.ResponseWriter, req *http.Request) {
	glog.V(LINFO).Infof("[http2] %s - %s", req.RemoteAddr, req.Host)
	if glog.V(LDEBUG) {
		dump, _ := httputil.DumpRequest(req, false)
		glog.Infoln(string(dump))
	}

	c, err := Connect(req.Host)
	if err != nil {
		glog.V(LWARNING).Infof("[http2] %s -> %s : %s", req.RemoteAddr, req.Host, err)
		w.Header().Set("Proxy-Agent", "gost/"+Version)
		w.WriteHeader(http.StatusServiceUnavailable)
		if fw, ok := w.(http.Flusher); ok {
			fw.Flush()
		}
		return
	}
	defer c.Close()

	glog.V(LINFO).Infof("[http2] %s <-> %s", req.RemoteAddr, req.Host)
	errc := make(chan error, 2)

	if req.Method == http.MethodConnect {
		w.Header().Set("Proxy-Agent", "gost/"+Version)
		w.WriteHeader(http.StatusOK)
		if fw, ok := w.(http.Flusher); ok {
			fw.Flush()
		}

		// compatible with HTTP 1.x
		if hj, ok := w.(http.Hijacker); ok && req.ProtoMajor == 1 {
			// we take over the underly connection
			conn, _, err := hj.Hijack()
			if err != nil {
				glog.V(LWARNING).Infof("[http2] %s -> %s : %s", req.RemoteAddr, req.Host, err)
				return
			}
			defer conn.Close()

			go Pipe(conn, c, errc)
			go Pipe(c, conn, errc)
		} else {
			go Pipe(req.Body, c, errc)
			go Pipe(c, flushWriter{w}, errc)
		}

		select {
		case <-errc:
			// glog.V(LWARNING).Infoln("exit", err)
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

		if _, err := io.Copy(flushWriter{w}, resp.Body); err != nil {
			glog.V(LWARNING).Infof("[http2] %s <- %s : %s", req.RemoteAddr, req.Host, err)
		}
	}

	glog.V(LINFO).Infof("[http2] %s >-< %s", req.RemoteAddr, req.Host)
}

func handleHttp2Transport(w http.ResponseWriter, req *http.Request) {
	glog.V(LINFO).Infof("[http2] %s - %s", req.RemoteAddr, req.Host)
	if glog.V(LDEBUG) {
		dump, _ := httputil.DumpRequest(req, false)
		glog.Infoln(string(dump))
	}
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
