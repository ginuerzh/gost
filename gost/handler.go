package gost

import (
	"crypto/tls"
	"net"
	"net/url"
)

type Handler interface {
	Handle(net.Conn)
}

type HandlerOptions struct {
	Chain     *Chain
	Users     []*url.Userinfo
	TLSConfig *tls.Config
}

type HandlerOption func(opts *HandlerOptions)

func ChainHandlerOption(chain *Chain) HandlerOption {
	return func(opts *HandlerOptions) {
		opts.Chain = chain
	}
}

func UsersHandlerOption(users ...*url.Userinfo) HandlerOption {
	return func(opts *HandlerOptions) {
		opts.Users = users
	}
}

func TLSConfigHandlerOption(config *tls.Config) HandlerOption {
	return func(opts *HandlerOptions) {
		opts.TLSConfig = config
	}
}
