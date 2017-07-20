package tcp

import (
	"net"

	"github.com/ginuerzh/gost"
	"github.com/ginuerzh/gost/server"
)

type nodeServer struct {
	options *server.Server
}

func (s *nodeServer) Init(opts ...server.Option) {
	for _, opt := range opts {
		opt(s.options)
	}
}

func (s *nodeServer) Options() *server.Options {
	return s.options
}

func (s *nodeServer) Run() error {
	ln, err := net.Listen("tcp", s.options.Addr)
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
			gost.DefaultHandler(s).Handle(conn)
		}(conn)
	}
}
