package main

import (
	"github.com/golang/glog"
	"net/http"
	"net/http/httputil"
)

func handlerHttp2Request(w http.ResponseWriter, r *http.Request) {
	glog.V(LINFO).Infof("[http2] %s - %s", r.RemoteAddr, r.Host)

	if glog.V(LDEBUG) {
		dump, err := httputil.DumpRequest(r, false)
		if err != nil {
			glog.Infoln(err)
		} else {
			glog.Infoln(string(dump))
		}
	}

}
