package gost

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/ginuerzh/gosocks4"
	"github.com/ginuerzh/gosocks5"
	"github.com/golang/glog"
	ss "github.com/shadowsocks/shadowsocks-go/shadowsocks"
	"golang.org/x/crypto/ssh"
)

type ProxyServer struct {
	Node      ProxyNode
	Chain     *ProxyChain
	TLSConfig *tls.Config
	selector  *serverSelector
	cipher    *ss.Cipher
	ota       bool
}

func NewProxyServer(node ProxyNode, chain *ProxyChain) *ProxyServer {
	certFile, keyFile := node.certFile(), node.keyFile()

	cert, err := LoadCertificate(certFile, keyFile)
	if err != nil {
		glog.Fatal(err)
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	if chain == nil {
		chain = NewProxyChain()
	}

	var cipher *ss.Cipher
	var ota bool
	if node.Protocol == "ss" || node.Transport == "ssu" {
		var err error
		var method, password string

		if len(node.Users) > 0 {
			method = node.Users[0].Username()
			password, _ = node.Users[0].Password()
		}
		ota = node.getBool("ota")
		if strings.HasSuffix(method, "-auth") {
			ota = true
			method = strings.TrimSuffix(method, "-auth")
		}
		cipher, err = ss.NewCipher(method, password)
		if err != nil {
			glog.Fatal(err)
		}
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
			users:     node.Users,
			tlsConfig: config,
		},
		cipher: cipher,
		ota:    ota,
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
		return NewTcpForwardServer(s).ListenAndServe()
	case "udp": // Local UDP port forwarding
		ttl, _ := strconv.Atoi(s.Node.Get("ttl"))
		if ttl <= 0 {
			ttl = DefaultTTL
		}
		return NewUdpForwardServer(s, ttl).ListenAndServe()
	case "rtcp": // Remote TCP port forwarding
		return NewRTcpForwardServer(s).Serve()
	case "rudp": // Remote UDP port forwarding
		return NewRUdpForwardServer(s).Serve()
	case "quic":
		return NewQuicServer(s).ListenAndServeTLS(s.TLSConfig)
	case "kcp":
		config, err := ParseKCPConfig(s.Node.Get("c"))
		if err != nil {
			glog.V(LWARNING).Infoln("[kcp]", err)
		}
		if config == nil {
			config = DefaultKCPConfig
		}
		// override crypt and key if specified explicitly
		if s.Node.Users != nil {
			config.Crypt = s.Node.Users[0].Username()
			config.Key, _ = s.Node.Users[0].Password()
		}
		return NewKCPServer(s, config).ListenAndServe()
	case "redirect":
		return NewRedsocksTCPServer(s).ListenAndServe()
	case "ssu": // shadowsocks udp relay
		ttl, _ := strconv.Atoi(s.Node.Get("ttl"))
		if ttl <= 0 {
			ttl = DefaultTTL
		}
		return NewShadowUdpServer(s, ttl).ListenAndServe()
	case "pht": // pure http tunnel
		return NewPureHttpServer(s).ListenAndServe()
	case "ssh": // SSH tunnel
		/*
			key := s.Node.Get("key")
			privateBytes, err := ioutil.ReadFile(key)
			if err != nil {
				glog.V(LWARNING).Infoln("[ssh]", err)
				privateBytes = defaultRawKey
			}
			private, err := ssh.ParsePrivateKey(privateBytes)
			if err != nil {
				return err
			}
		*/
		config := ssh.ServerConfig{
			PasswordCallback: DefaultPasswordCallback(s.Node.Users),
		}
		if len(s.Node.Users) == 0 {
			config.NoClientAuth = true
		}
		signer, err := ssh.NewSignerFromKey(s.TLSConfig.Certificates[0].PrivateKey)
		if err != nil {
			return err
		}
		config.AddHostKey(signer)
		s := &SSHServer{
			Addr:   node.Addr,
			Base:   s,
			Config: &config,
		}
		return s.ListenAndServe()
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
		server := NewShadowServer(ss.NewConn(conn, s.cipher.Copy()), s)
		server.OTA = s.ota
		server.Serve()
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
	case "socks4", "socks4a":
		req, err := gosocks4.ReadRequest(conn)
		if err != nil {
			glog.V(LWARNING).Infoln("[socks4]", err)
			return
		}
		NewSocks4Server(conn, s).HandleRequest(req)
		return
	}

	br := bufio.NewReader(conn)
	b, err := br.Peek(1)
	if err != nil {
		glog.V(LWARNING).Infoln(err)
		return
	}

	switch b[0] {
	case gosocks4.Ver4:
		req, err := gosocks4.ReadRequest(br)
		if err != nil {
			glog.V(LWARNING).Infoln("[socks4]", err)
			return
		}
		NewSocks4Server(conn, s).HandleRequest(req)

	case gosocks5.Ver5:
		methods, err := gosocks5.ReadMethods(br)
		if err != nil {
			glog.V(LWARNING).Infoln("[socks5]", err)
			return
		}
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

	default: // http
		req, err := http.ReadRequest(br)
		if err != nil {
			glog.V(LWARNING).Infoln("[http]", err)
			return
		}
		NewHttpServer(conn, s).HandleRequest(req)
	}
}

func (_ *ProxyServer) transport(conn1, conn2 net.Conn) (err error) {
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
		// glog.V(LWARNING).Infoln("transport exit", err)
	}

	return
}
