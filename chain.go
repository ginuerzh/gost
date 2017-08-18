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
	nodeGroups []*NodeGroup
}

// NewChain creates a proxy chain with a list of proxy nodes.
func NewChain(nodes ...Node) *Chain {
	chain := &Chain{}
	for _, node := range nodes {
		chain.nodeGroups = append(chain.nodeGroups, NewNodeGroup(node))
	}
	return chain
}

// Nodes returns the proxy nodes that the chain holds.
// If a node is a node group, the first node in the group will be returned.
func (c *Chain) Nodes() (nodes []Node) {
	for _, group := range c.nodeGroups {
		if ns := group.Nodes(); len(ns) > 0 {
			nodes = append(nodes, ns[0])
		}
	}
	return
}

// NodeGroups returns the list of node group.
func (c *Chain) NodeGroups() []*NodeGroup {
	return c.nodeGroups
}

// LastNode returns the last node of the node list.
// If the chain is empty, an empty node is returns.
// If the last node is a node group, the first node in the group will be returned.
func (c *Chain) LastNode() Node {
	if c.IsEmpty() {
		return Node{}
	}
	last := c.nodeGroups[len(c.nodeGroups)-1]
	return last.nodes[0]
}

// LastNodeGroup returns the last group of the group list.
func (c *Chain) LastNodeGroup() *NodeGroup {
	if c.IsEmpty() {
		return nil
	}
	return c.nodeGroups[len(c.nodeGroups)-1]
}

// AddNode appends the node(s) to the chain.
func (c *Chain) AddNode(nodes ...Node) {
	if c == nil {
		return
	}
	for _, node := range nodes {
		c.nodeGroups = append(c.nodeGroups, NewNodeGroup(node))
	}
}

// AddNodeGroup appends the group(s) to the chain.
func (c *Chain) AddNodeGroup(groups ...*NodeGroup) {
	if c == nil {
		return
	}
	for _, group := range groups {
		c.nodeGroups = append(c.nodeGroups, group)
	}
}

// IsEmpty checks if the chain is empty.
// An empty chain means that there is no proxy node or node group in the chain.
func (c *Chain) IsEmpty() bool {
	return c == nil || len(c.nodeGroups) == 0
}

// Dial connects to the target address addr through the chain.
// If the chain is empty, it will use the net.Dial directly.
func (c *Chain) Dial(addr string) (net.Conn, error) {
	if c.IsEmpty() {
		return net.Dial("tcp", addr)
	}

	conn, nodes, err := c.getConn()
	if err != nil {
		return nil, err
	}

	cc, err := nodes[len(nodes)-1].Client.Connect(conn, addr)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return cc, nil
}

// Conn obtains a handshaked connection to the last node of the chain.
// If the chain is empty, it returns an ErrEmptyChain error.
func (c *Chain) Conn() (conn net.Conn, err error) {
	conn, _, err = c.getConn()
	return
}

func (c *Chain) getConn() (conn net.Conn, nodes []Node, err error) {
	if c.IsEmpty() {
		err = ErrEmptyChain
		return
	}
	groups := c.nodeGroups
	selector := groups[0].Selector
	if selector == nil {
		selector = &defaultSelector{}
	}
	node, err := selector.Select(groups[0].Nodes(), groups[0].Options...)
	if err != nil {
		return
	}
	nodes = append(nodes, node)

	cn, err := node.Client.Dial(node.Addr, node.DialOptions...)
	if err != nil {
		return
	}

	cn, err = node.Client.Handshake(cn, node.HandshakeOptions...)
	if err != nil {
		return
	}

	preNode := node
	for i := range groups {
		if i == len(groups)-1 {
			break
		}
		selector = groups[i+1].Selector
		if selector == nil {
			selector = &defaultSelector{}
		}
		node, err = selector.Select(groups[i+1].Nodes(), groups[i+1].Options...)
		if err != nil {
			cn.Close()
			return
		}
		nodes = append(nodes, node)

		var cc net.Conn
		cc, err = preNode.Client.Connect(cn, node.Addr)
		if err != nil {
			cn.Close()
			return
		}
		cc, err = node.Client.Handshake(cc, node.HandshakeOptions...)
		if err != nil {
			cn.Close()
			return
		}
		cn = cc
		preNode = node
	}

	conn = cn
	return
}
