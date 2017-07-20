package gost

import (
	"net"
)

type Handler interface {
	Handle(net.Conn)
}

type defaultHandler struct {
	server Server
}

func DefaultHandler(server Server) Handler {
	return &defaultHandler{server: server}
}

func (h *defaultHandler) Handle(conn net.Conn) {
	var handler Handler

	switch h.server.Options().BaseOptions().Protocol {
	case "http":
		handler = HTTPHandler(h.server)
	case "socks", "socks5":
	case "ss": // shadowsocks
		handler = ShadowHandler(h.server)

	}

	handler.Handle(conn)
}
