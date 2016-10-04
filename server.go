package gost

import (
	"bufio"
	"crypto/tls"
	"github.com/ginuerzh/gosocks5"
	"github.com/golang/glog"
	"io"
	"net"
	"net/http"
)

type ProxyServer struct {
	Node      ProxyNode
	Chain     *ProxyChain
	TLSConfig *tls.Config
	selector  *serverSelector
}

func NewProxyServer(node ProxyNode, chain *ProxyChain, config *tls.Config) *ProxyServer {
	if chain == nil {
		chain = NewProxyChain()
	}
	if config == nil {
		config = &tls.Config{}
	}
	return &ProxyServer{
		Node:      node,
		Chain:     chain,
		TLSConfig: config,
		selector: &serverSelector{ // socks5 server selector
			// methods that socks5 server supported
			methods: []uint8{
				gosocks5.MethodNoAuth,
				gosocks5.MethodUserPass,
				MethodTLS,
				MethodTLSAuth,
			},
			user:      node.User,
			tlsConfig: config,
		},
	}
}

func (s *ProxyServer) Serve() error {
	var ln net.Listener
	var err error
	node := s.Node

	switch node.Transport {
	case "ws": // websocket connection
		return NewWebsocketServer(s).ListenAndServe()
	case "wss": // websocket security connection
		return NewWebsocketServer(s).ListenAndServeTLS(s.TLSConfig)
	case "tls": // tls connection
		ln, err = tls.Listen("tcp", node.Addr, s.TLSConfig)
	case "http2": // Standard HTTP2 proxy server, compatible with HTTP1.x.
		server := NewHttp2Server(s)
		server.Handler = http.HandlerFunc(server.HandleRequest)
		return server.ListenAndServeTLS(s.TLSConfig)
	case "tcp": // Local TCP port forwarding
	//	return listenAndServeTcpForward(arg)
	case "udp": // Local UDP port forwarding
	//	return listenAndServeUdpForward(arg)
	case "rtcp": // Remote TCP port forwarding
	//	return serveRTcpForward(arg)
	case "rudp": // Remote UDP port forwarding
	//	return serveRUdpForward(arg)
	default:
		ln, err = net.Listen("tcp", node.Addr)
	}

	if err != nil {
		return err
	}

	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			glog.V(LWARNING).Infoln(err)
			continue
		}

		setKeepAlive(conn, KeepAliveTime)

		go s.handleConn(conn)
	}
}

func (s *ProxyServer) handleConn(conn net.Conn) {
	defer conn.Close()

	switch s.Node.Protocol {
	case "ss": // shadowsocks
		NewShadowServer(conn, s).Serve()
		return
	case "http":
		req, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			glog.V(LWARNING).Infoln("[http]", err)
			return
		}
		NewHttpServer(conn, s).HandleRequest(req)
		return
	case "socks", "socks5":
		conn = gosocks5.ServerConn(conn, s.selector)
		req, err := gosocks5.ReadRequest(conn)
		if err != nil {
			glog.V(LWARNING).Infoln("[socks5]", err)
			return
		}
		NewSocks5Server(conn, s).HandleRequest(req)
		return
	}

	glog.V(LINFO).Infof("%s - %s", conn.RemoteAddr(), s.Node.Addr)
	// http or socks5
	b := make([]byte, MediumBufferSize)

	n, err := io.ReadAtLeast(conn, b, 2)
	if err != nil {
		glog.V(LWARNING).Infoln(err)
		return
	}

	// TODO: use bufio.Reader
	if b[0] == gosocks5.Ver5 {
		mn := int(b[1]) // methods count
		length := 2 + mn
		if n < length {
			if _, err := io.ReadFull(conn, b[n:length]); err != nil {
				glog.V(LWARNING).Infoln("[socks5]", err)
				return
			}
		}
		// TODO: use gosocks5.ServerConn
		methods := b[2 : 2+mn]
		method := s.selector.Select(methods...)
		if _, err := conn.Write([]byte{gosocks5.Ver5, method}); err != nil {
			glog.V(LWARNING).Infoln("[socks5] select:", err)
			return
		}
		c, err := s.selector.OnSelected(method, conn)
		if err != nil {
			glog.V(LWARNING).Infoln("[socks5] onselected:", err)
			return
		}
		conn = c

		req, err := gosocks5.ReadRequest(conn)
		if err != nil {
			glog.V(LWARNING).Infoln("[socks5] request:", err)
			return
		}
		NewSocks5Server(conn, s).HandleRequest(req)
		return
	}

	req, err := http.ReadRequest(bufio.NewReader(&reqReader{b: b[:n], r: conn}))
	if err != nil {
		glog.V(LWARNING).Infoln("[http]", err)
		return
	}
	NewHttpServer(conn, s).HandleRequest(req)
}

func (s *ProxyServer) transport(conn1, conn2 net.Conn) (err error) {
	errc := make(chan error, 2)

	go func() {
		_, err := io.Copy(conn1, conn2)
		errc <- err
	}()

	go func() {
		_, err := io.Copy(conn2, conn1)
		errc <- err
	}()

	select {
	case err = <-errc:
		//glog.V(LWARNING).Infoln("transport exit", err)
	}

	return
}

type reqReader struct {
	b []byte
	r io.Reader
}

func (r *reqReader) Read(p []byte) (n int, err error) {
	if len(r.b) == 0 {
		return r.r.Read(p)
	}
	n = copy(p, r.b)
	r.b = r.b[n:]

	return
}
