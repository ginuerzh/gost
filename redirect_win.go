// +build windows

package gost

import (
	"net"

	"github.com/go-log/log"
)

type tcpRedirectHandler struct {
	options *HandlerOptions
}

// TCPRedirectHandler creates a server Handler for TCP redirect server.
func TCPRedirectHandler(opts ...HandlerOption) Handler {
	h := &tcpRedirectHandler{
		options: &HandlerOptions{
			Chain: new(Chain),
		},
	}
	for _, opt := range opts {
		opt(h.options)
	}
	return h
}

func (h *tcpRedirectHandler) Init(options ...HandlerOption) {
	log.Log("[red-tcp] TCP redirect is not available on the Windows platform")
}

func (h *tcpRedirectHandler) Handle(c net.Conn) {
	log.Log("[red-tcp] TCP redirect is not available on the Windows platform")
	c.Close()
}
