package gost

import (
	"bufio"
	"crypto/tls"
	"net"
	"net/url"
	"time"

	"github.com/go-gost/gosocks4"
	"github.com/go-gost/gosocks5"
	"github.com/go-log/log"
)

// Handler is a proxy server handler
type Handler interface {
	Init(options ...HandlerOption)
	Handle(net.Conn)
}

// HandlerOptions describes the options for Handler.
type HandlerOptions struct {
	Addr          string
	Chain         *Chain
	Users         []*url.Userinfo
	Authenticator Authenticator
	TLSConfig     *tls.Config
	Whitelist     *Permissions
	Blacklist     *Permissions
	Strategy      Strategy
	MaxFails      int
	FailTimeout   time.Duration
	Bypass        *Bypass
	Retries       int
	Timeout       time.Duration
	Resolver      Resolver
	Hosts         *Hosts
	ProbeResist   string
	KnockingHost  string
	Node          Node
	Host          string
	IPs           []string
	TCPMode       bool
	IPRoutes      []IPRoute
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

		kvs := make(map[string]string)
		for _, u := range users {
			if u != nil {
				kvs[u.Username()], _ = u.Password()
			}
		}
		if len(kvs) > 0 {
			opts.Authenticator = NewLocalAuthenticator(kvs)
		}
	}
}

// AuthenticatorHandlerOption sets the Authenticator option of HandlerOptions.
func AuthenticatorHandlerOption(au Authenticator) HandlerOption {
	return func(opts *HandlerOptions) {
		opts.Authenticator = au
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

// BypassHandlerOption sets the bypass option of HandlerOptions.
func BypassHandlerOption(bypass *Bypass) HandlerOption {
	return func(opts *HandlerOptions) {
		opts.Bypass = bypass
	}
}

// StrategyHandlerOption sets the strategy option of HandlerOptions.
func StrategyHandlerOption(strategy Strategy) HandlerOption {
	return func(opts *HandlerOptions) {
		opts.Strategy = strategy
	}
}

// MaxFailsHandlerOption sets the max_fails option of HandlerOptions.
func MaxFailsHandlerOption(n int) HandlerOption {
	return func(opts *HandlerOptions) {
		opts.MaxFails = n
	}
}

// FailTimeoutHandlerOption sets the fail_timeout option of HandlerOptions.
func FailTimeoutHandlerOption(d time.Duration) HandlerOption {
	return func(opts *HandlerOptions) {
		opts.FailTimeout = d
	}
}

// RetryHandlerOption sets the retry option of HandlerOptions.
func RetryHandlerOption(retries int) HandlerOption {
	return func(opts *HandlerOptions) {
		opts.Retries = retries
	}
}

// TimeoutHandlerOption sets the timeout option of HandlerOptions.
func TimeoutHandlerOption(timeout time.Duration) HandlerOption {
	return func(opts *HandlerOptions) {
		opts.Timeout = timeout
	}
}

// ResolverHandlerOption sets the resolver option of HandlerOptions.
func ResolverHandlerOption(resolver Resolver) HandlerOption {
	return func(opts *HandlerOptions) {
		opts.Resolver = resolver
	}
}

// HostsHandlerOption sets the Hosts option of HandlerOptions.
func HostsHandlerOption(hosts *Hosts) HandlerOption {
	return func(opts *HandlerOptions) {
		opts.Hosts = hosts
	}
}

// ProbeResistHandlerOption adds the probe resistance for HTTP proxy.
func ProbeResistHandlerOption(pr string) HandlerOption {
	return func(opts *HandlerOptions) {
		opts.ProbeResist = pr
	}
}

// KnockingHandlerOption adds the knocking host for probe resistance.
func KnockingHandlerOption(host string) HandlerOption {
	return func(opts *HandlerOptions) {
		opts.KnockingHost = host
	}
}

// NodeHandlerOption set the server node for server handler.
func NodeHandlerOption(node Node) HandlerOption {
	return func(opts *HandlerOptions) {
		opts.Node = node
	}
}

// HostHandlerOption sets the target host for SNI proxy.
func HostHandlerOption(host string) HandlerOption {
	return func(opts *HandlerOptions) {
		opts.Host = host
	}
}

// IPsHandlerOption sets the ip list for port forward.
func IPsHandlerOption(ips []string) HandlerOption {
	return func(opts *HandlerOptions) {
		opts.IPs = ips
	}
}

// TCPModeHandlerOption sets the tcp mode for tun/tap device.
func TCPModeHandlerOption(b bool) HandlerOption {
	return func(opts *HandlerOptions) {
		opts.TCPMode = b
	}
}

// IPRoutesHandlerOption sets the IP routes for tun tunnel.
func IPRoutesHandlerOption(routes ...IPRoute) HandlerOption {
	return func(opts *HandlerOptions) {
		opts.IPRoutes = routes
	}
}

type autoHandler struct {
	options *HandlerOptions
}

// AutoHandler creates a server Handler for auto proxy server.
func AutoHandler(opts ...HandlerOption) Handler {
	h := &autoHandler{}
	h.Init(opts...)
	return h
}

func (h *autoHandler) Init(options ...HandlerOption) {
	if h.options == nil {
		h.options = &HandlerOptions{}
	}
	for _, opt := range options {
		opt(h.options)
	}
}

func (h *autoHandler) Handle(conn net.Conn) {
	br := bufio.NewReader(conn)
	b, err := br.Peek(1)
	if err != nil {
		log.Logf("[auto] %s - %s: %s", conn.RemoteAddr(), conn.LocalAddr(), err)
		conn.Close()
		return
	}

	cc := &bufferdConn{Conn: conn, br: br}
	var handler Handler
	switch b[0] {
	case gosocks4.Ver4:
		// SOCKS4(a) does not suppport authentication method,
		// so we ignore it when credentials are specified for security reason.
		if len(h.options.Users) > 0 {
			cc.Close()
			return
		}
		handler = &socks4Handler{options: h.options}
	case gosocks5.Ver5: // socks5
		handler = &socks5Handler{options: h.options}
	default: // http
		handler = &httpHandler{options: h.options}
	}
	handler.Init()
	handler.Handle(cc)
}

type bufferdConn struct {
	net.Conn
	br *bufio.Reader
}

func (c *bufferdConn) Read(b []byte) (int, error) {
	return c.br.Read(b)
}
