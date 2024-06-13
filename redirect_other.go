//go:build !linux
// +build !linux

package gost

import (
	"errors"
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

type udpRedirectHandler struct{}

// UDPRedirectHandler creates a server Handler for UDP transparent server.
func UDPRedirectHandler(opts ...HandlerOption) Handler {
	return &udpRedirectHandler{}
}

func (h *udpRedirectHandler) Init(options ...HandlerOption) {
}

func (h *udpRedirectHandler) Handle(conn net.Conn) {
	log.Log("[red-udp] UDP redirect is not available on the Windows platform")
	conn.Close()
}

// UDPRedirectListener creates a Listener for UDP transparent proxy server.
func UDPRedirectListener(addr string, cfg *UDPListenConfig) (Listener, error) {
	return nil, errors.New("UDP redirect is not available on the Windows platform")
}
