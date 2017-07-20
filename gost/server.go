package gost

import (
	"crypto/tls"
	"net/url"
)

type Server struct {
	Addr      string `opt:"addr"`     // [host]:port
	Protocol  string `opt:"protocol"` // protocol: http/socks5/ss
	TLSConfig *tls.Config
	Chain     *Chain
	Users     []url.Userinfo `opt:"user"` // authentication for proxy
}

func (s *Server) Run() error {
	return nil
}
