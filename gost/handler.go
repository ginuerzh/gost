package gost

import (
	"crypto/tls"
	"net"
	"net/url"
)

// Handler is a proxy server handler
type Handler interface {
	Handle(net.Conn)
}

// HandlerOptions describes the options for Handler.
type HandlerOptions struct {
	Chain     *Chain
	Users     []*url.Userinfo
	TLSConfig *tls.Config
}

// HandlerOption allows a common way to set handler options.
type HandlerOption func(opts *HandlerOptions)

// ChainHandlerOption sets the Chain option of HandlerOptions.
func ChainHandlerOption(chain *Chain) HandlerOption {
	return func(opts *HandlerOptions) {
		opts.Chain = chain
	}
}

// UsersHandlerOption sets the Users option of HandlerOptions.
func UsersHandlerOption(users ...*url.Userinfo) HandlerOption {
	return func(opts *HandlerOptions) {
		opts.Users = users
	}
}

// TLSConfigHandlerOption sets the TLSConfig option of HandlerOptions.
func TLSConfigHandlerOption(config *tls.Config) HandlerOption {
	return func(opts *HandlerOptions) {
		opts.TLSConfig = config
	}
}
