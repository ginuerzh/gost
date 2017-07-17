package tcp

import (
	"net/url"

	"github.com/ginuerzh/gost"
)

type tcpNodeOptions struct {
	*gost.DefaultOptions
	Users []url.Userinfo `opt:"users"` // authentication for proxy
}

func (o *tcpNodeOptions) Get(opt string) interface{} {
	return gost.GetOption(o, opt)
}

func (o *tcpNodeOptions) Set(opt string, v interface{}) {
	gost.SetOption(o, opt, v)
}

func UsersOption(users ...url.Userinfo) gost.Option {
	return func(opts gost.Options) {
		gost.SetOption(opts, "users", users)
	}
}
