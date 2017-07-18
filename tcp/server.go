package tcp

import (
	"bufio"
	"net"
	"net/http"

	"github.com/ginuerzh/gosocks4"
	"github.com/ginuerzh/gosocks5"
	"github.com/ginuerzh/gost"
	"github.com/ginuerzh/gost/ssocks"
	"github.com/go-log/log"
)

type nodeServer struct {
	options *nodeOptions
	chain   *gost.Chain
}

func (s *nodeServer) Chain() *gost.Chain {
	return s.chain
}

func (s *nodeServer) SetChain(chain *gost.Chain) {
	s.chain = chain
}

func (s *nodeServer) Options() gost.Options {
	return s.options
}

func (s *nodeServer) Run() error {
	ln, err := net.Listen("tcp", s.options.BaseOptions().Addr)
	if err != nil {
		return err
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go func(c net.Conn) {
			defer c.Close()
			s.handleConn(c)
		}(conn)
	}
}

func (s *nodeServer) handleConn(conn net.Conn) {

	switch s.options.BaseOptions().Protocol {
	case "ss": // shadowsocks
		server, err := ssocks.NewServer(conn, s)
		if err != nil {
			log.Log("[ss]", err)
		}
		server.Serve()
		return

	case "http":
		req, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			log.Log("[http]", err)
			return
		}
		NewHttpServer(conn, s).HandleRequest(req)
		return
	case "socks", "socks5":
		conn = gosocks5.ServerConn(conn, s.selector)
		req, err := gosocks5.ReadRequest(conn)
		if err != nil {
			log.Log("[socks5]", err)
			return
		}
		NewSocks5Server(conn, s).HandleRequest(req)
		return
	case "socks4", "socks4a":
		req, err := gosocks4.ReadRequest(conn)
		if err != nil {
			log.Log("[socks4]", err)
			return
		}
		NewSocks4Server(conn, s).HandleRequest(req)
		return
	}

	br := bufio.NewReader(conn)
	b, err := br.Peek(1)
	if err != nil {
		log.Log(err)
		return
	}

	switch b[0] {
	case gosocks4.Ver4:
		req, err := gosocks4.ReadRequest(br)
		if err != nil {
			log.Log("[socks4]", err)
			return
		}
		NewSocks4Server(conn, s).HandleRequest(req)

	case gosocks5.Ver5:
		methods, err := gosocks5.ReadMethods(br)
		if err != nil {
			log.Log("[socks5]", err)
			return
		}
		method := s.selector.Select(methods...)
		if _, err := conn.Write([]byte{gosocks5.Ver5, method}); err != nil {
			log.Log("[socks5] select:", err)
			return
		}
		c, err := s.selector.OnSelected(method, conn)
		if err != nil {
			log.Log("[socks5] onselected:", err)
			return
		}
		conn = c

		req, err := gosocks5.ReadRequest(conn)
		if err != nil {
			log.Log("[socks5] request:", err)
			return
		}
		NewSocks5Server(conn, s).HandleRequest(req)

	default: // http
		req, err := http.ReadRequest(br)
		if err != nil {
			log.Log("[http]", err)
			return
		}
		NewHttpServer(conn, s).HandleRequest(req)
	}
}
