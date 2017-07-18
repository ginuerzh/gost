package gost

import (
	"net"
)

type Handler interface {
	Handle(net.Conn)
}

type DefaultHandler struct {
	server Server
}

func (h *DefaultHandler) Handle(conn net.Conn) {
	var handler Handler

	switch h.server.Options().BaseOptions().Protocol {
	case "http":
	case "ss": // shadowsocks
		handler = ShadowHandler(h.server)

	}

	handler.Handle(conn)
}
