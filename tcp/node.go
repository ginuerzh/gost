package tcp

import (
	"github.com/ginuerzh/gost"
)

type tcpNode struct {
	options *tcpNodeOptions
	client  *nodeClient
	server  *nodeServer
}

// NewNode creates a tcpNode with options
func NewNode(opts ...gost.Option) gost.Node {
	node := &tcpNode{
		options: new(tcpNodeOptions),
	}
	for _, opt := range opts {
		opt(node.options)
	}

	return node
}

func (node *tcpNode) Init(opts ...gost.Option) error {
	for _, opt := range opts {
		opt(node.options)
	}

	return nil
}

func (node *tcpNode) Client() gost.Client {
	return node.client
}

func (node *tcpNode) Server() gost.Server {
	return node.server
}

func (node *tcpNode) Options() gost.Options {
	return node.options
}
