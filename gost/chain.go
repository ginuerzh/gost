package gost

import (
	"net"
)

type Chain struct {
	Nodes []Node
}

func NewChain(nodes ...Node) *Chain {
	return &Chain{
		Nodes: nodes,
	}
}

func (c *Chain) Dial(addr string) (net.Conn, error) {
	if len(c.Nodes) == 0 {
		return net.Dial("tcp", addr)
	}

	nodes := c.Nodes
	conn, err := nodes[0].Client.Dial(nodes[0].Addr)
	if err != nil {
		return nil, err
	}

	conn, err = nodes[0].Client.Handshake(conn)
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
		cc, err = next.Client.Handshake(cc)
		if err != nil {
			conn.Close()
			return nil, err
		}

		conn = cc
	}

	cc, err := nodes[len(nodes)-1].Client.Connect( conn, addr)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return cc, nil
}
