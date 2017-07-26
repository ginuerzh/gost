package gost

import (
	"errors"
	"net"
)

var (
	// ErrEmptyChain is an error that implies the chain is empty.
	ErrEmptyChain = errors.New("empty chain")
)

// Chain is a proxy chain that holds a list of proxy nodes.
type Chain struct {
	nodes []Node
}

// NewChain creates a proxy chain with proxy nodes nodes.
func NewChain(nodes ...Node) *Chain {
	return &Chain{
		nodes: nodes,
	}
}

// Nodes returns the proxy nodes that the chain holds.
func (c *Chain) Nodes() []Node {
	return c.nodes
}

// LastNode returns the last node of the node list.
// If the chain is empty, an empty node is returns.
func (c *Chain) LastNode() Node {
	if c.IsEmpty() {
		return Node{}
	}
	return c.nodes[len(c.nodes)-1]
}

// AddNode appends the node(s) to the chain.
func (c *Chain) AddNode(nodes ...Node) {
	if c == nil {
		return
	}
	c.nodes = append(c.nodes, nodes...)
}

// IsEmpty checks if the chain is empty.
// An empty chain means that there is no proxy node in the chain.
func (c *Chain) IsEmpty() bool {
	return c == nil || len(c.nodes) == 0
}

// Dial connects to the target address addr through the chain.
// If the chain is empty, it will use the net.Dial directly.
func (c *Chain) Dial(addr string) (net.Conn, error) {
	if c.IsEmpty() {
		return net.Dial("tcp", addr)
	}

	conn, err := c.Conn()
	if err != nil {
		return nil, err
	}

	cc, err := c.LastNode().Client.Connect(conn, addr)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return cc, nil
}

// Conn obtains a handshaked connection to the last node of the chain.
// If the chain is empty, it returns an ErrEmptyChain error.
func (c *Chain) Conn() (net.Conn, error) {
	if c.IsEmpty() {
		return nil, ErrEmptyChain
	}

	nodes := c.nodes
	conn, err := nodes[0].Client.Dial(nodes[0].Addr, TimeoutDialOption(DialTimeout))
	if err != nil {
		return nil, err
	}

	conn, err = nodes[0].Client.Handshake(conn, AddrHandshakeOption(nodes[0].Addr))
	if err != nil {
		return nil, err
	}

	for i, node := range nodes {
		if i == len(nodes)-1 {
			break
		}

		next := nodes[i+1]
		cc, err := node.Client.Connect(conn, next.Addr)
		if err != nil {
			conn.Close()
			return nil, err
		}
		cc, err = next.Client.Handshake(cc, AddrHandshakeOption(next.Addr))
		if err != nil {
			conn.Close()
			return nil, err
		}
		conn = cc
	}
	return conn, nil
}
