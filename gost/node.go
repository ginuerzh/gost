package gost

import (
	"net/url"
)

// Node is a proxy node, mainly used to construct a proxy chain.
type Node struct {
	Addr      string
	Protocol  string
	Transport string
	User      *url.Userinfo
	Client    *Client
	Server    *Server
}
