package gost

import (
	"bufio"
	"crypto/tls"
	"github.com/golang/glog"
	"github.com/lucas-clemente/quic-go/h2quic"
	"io"
	"net/http"
	"net/http/httputil"
)

type QuicServer struct {
	Base      *ProxyServer
	Handler   http.Handler
	TLSConfig *tls.Config
}

func NewQuicServer(base *ProxyServer) *QuicServer {
	return &QuicServer{Base: base}
}

func (s *QuicServer) ListenAndServeTLS(config *tls.Config) error {
	server := &h2quic.Server{
		Server: &http.Server{
			Addr:      s.Base.Node.Addr,
			Handler:   s.Handler,
			TLSConfig: config,
		},
	}
	if server.Handler == nil {
		// server.Handler = http.HandlerFunc(s.HandleRequest)
		server.Handler = http.HandlerFunc(NewHttp2Server(s.Base).HandleRequest)
	}
	return server.ListenAndServe()
}

func (s *QuicServer) HandleRequest(w http.ResponseWriter, req *http.Request) {
	target := req.Host
	glog.V(LINFO).Infof("[quic] %s %s - %s %s", req.Method, req.RemoteAddr, target, req.Proto)

	if glog.V(LDEBUG) {
		dump, _ := httputil.DumpRequest(req, false)
		glog.Infoln(string(dump))
	}

	c, err := s.Base.Chain.Dial(target)
	if err != nil {
		glog.V(LWARNING).Infof("[quic] %s -> %s : %s", req.RemoteAddr, target, err)
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	defer c.Close()

	glog.V(LINFO).Infof("[quic] %s <-> %s", req.RemoteAddr, target)

	req.Header.Set("Connection", "Keep-Alive")
	if err = req.Write(c); err != nil {
		glog.V(LWARNING).Infof("[quic] %s -> %s : %s", req.RemoteAddr, target, err)
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
		glog.V(LWARNING).Infof("[quic] %s <- %s : %s", req.RemoteAddr, target, err)
	}

	glog.V(LINFO).Infof("[quic] %s >-< %s", req.RemoteAddr, target)
}
