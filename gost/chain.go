package gost

import (
	"context"
	"net"
)

type Chain struct {
	Nodes []Node
}

func (c *Chain) Dial(ctx context.Context, addr string) (net.Conn, error) {
	if len(c.Nodes) == 0 {
		return net.Dial("tcp", addr)
	}

	nodes := c.Nodes
	conn, err := nodes[0].Client.Dial(ctx, nodes[0].Addr)
	if err != nil {
		return nil, err
	}

	for i, node := range nodes {
		if i == len(nodes)-1 {
			break
		}

		cn, err := node.Client.Connect(ctx, conn, nodes[i+1].Addr)
		if err != nil {
			conn.Close()
			return nil, err
		}
		conn = cn
	}

	cn, err := nodes[len(nodes)-1].Client.Connect(ctx, conn, addr)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return cn, nil
}
