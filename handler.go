package gost

import (
	"bufio"
	"crypto/tls"
	"net"
	"net/url"

	"github.com/ginuerzh/gosocks4"
	"github.com/ginuerzh/gosocks5"
	"github.com/go-log/log"
)

// Handler is a proxy server handler
type Handler interface {
	Handle(net.Conn)
}

// HandlerOptions describes the options for Handler.
type HandlerOptions struct {
	Addr      string
	Chain     *Chain
	Users     []*url.Userinfo
	TLSConfig *tls.Config
	Whitelist *Permissions
	Blacklist *Permissions
}

// HandlerOption allows a common way to set handler options.
type HandlerOption func(opts *HandlerOptions)

// AddrHandlerOption sets the Addr option of HandlerOptions.
func AddrHandlerOption(addr string) HandlerOption {
	return func(opts *HandlerOptions) {
		opts.Addr = addr
	}
}

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

// WhitelistHandlerOption sets the Whitelist option of HandlerOptions.
func WhitelistHandlerOption(whitelist *Permissions) HandlerOption {
	return func(opts *HandlerOptions) {
		opts.Whitelist = whitelist
	}
}

// BlacklistHandlerOption sets the Blacklist option of HandlerOptions.
func BlacklistHandlerOption(blacklist *Permissions) HandlerOption {
	return func(opts *HandlerOptions) {
		opts.Blacklist = blacklist
	}
}

type autoHandler struct {
	options []HandlerOption
}

// AutoHandler creates a server Handler for auto proxy server.
func AutoHandler(opts ...HandlerOption) Handler {
	h := &autoHandler{
		options: opts,
	}
	return h
}

func (h *autoHandler) Handle(conn net.Conn) {
	defer conn.Close()

	br := bufio.NewReader(conn)
	b, err := br.Peek(1)
	if err != nil {
		log.Log(err)
		return
	}

	cc := &bufferdConn{Conn: conn, br: br}
	switch b[0] {
	case gosocks4.Ver4:
		SOCKS4Handler(h.options...).Handle(cc)
	case gosocks5.Ver5:
		SOCKS5Handler(h.options...).Handle(cc)
	default: // http
		HTTPHandler(h.options...).Handle(cc)
	}
}

type bufferdConn struct {
	net.Conn
	br *bufio.Reader
}

func (c *bufferdConn) Read(b []byte) (int, error) {
	return c.br.Read(b)
}
