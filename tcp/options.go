package tcp

import (
	"net/url"

	"github.com/ginuerzh/gost"
)

type nodeOptions struct {
	base         *gost.BaseOptions
	users        []url.Userinfo `opt:"users"` // authentication for proxy
	certFile     string         `opt:"cert"`
	keyFile      string         `opt:"key"`
	serverName   string         `opt:"server_name"`
	secureVerify bool           `opt:"secure"`
}

func (o *nodeOptions) BaseOptions() *gost.BaseOptions {
	return o.base
}

func UsersOption(users ...url.Userinfo) gost.Option {
	return func(opts gost.Options) {
		if o, ok := opts.(*nodeOptions); ok {
			o.users = users
		}
	}
}

func (o *nodeOptions) ServerNameOption(n string) gost.Option {
	return func(opts gost.Options) {
		if o, ok := opts.(*nodeOptions); ok {
			o.serverName = n
		}
	}
}

func (o *nodeOptions) SecureVerifyOption(b bool) gost.Option {
	return func(opts gost.Options) {
		if o, ok := opts.(*nodeOptions); ok {
			o.secureVerify = b
		}
	}
}

func (o *nodeOptions) CertFileOption(f string) gost.Option {
	return func(opts gost.Options) {
		if o, ok := opts.(*nodeOptions); ok {
			o.certFile = f
		}
	}
}

func (o *nodeOptions) KeyFileOption(f string) gost.Option {
	return func(opts gost.Options) {
		if o, ok := opts.(*nodeOptions); ok {
			o.keyFile = f
		}
	}
}
