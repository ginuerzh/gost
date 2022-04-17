package gost

import (
	"context"
	"errors"
	"net"
	"syscall"
	"time"

	"github.com/go-log/log"
)

var (
	// ErrEmptyChain is an error that implies the chain is empty.
	ErrEmptyChain = errors.New("empty chain")
)

// Chain is a proxy chain that holds a list of proxy node groups.
type Chain struct {
	isRoute    bool
	Retries    int
	Mark       int
	Interface  string
	nodeGroups []*NodeGroup
	route      []Node // nodes in the selected route
}

// NewChain creates a proxy chain with a list of proxy nodes.
// It creates the node groups automatically, one group per node.
func NewChain(nodes ...Node) *Chain {
	chain := &Chain{}
	for _, node := range nodes {
		chain.nodeGroups = append(chain.nodeGroups, NewNodeGroup(node))
	}
	return chain
}

// newRoute creates a chain route.
// a chain route is the final route after node selection.
func (c *Chain) newRoute(nodes ...Node) *Chain {
	chain := NewChain(nodes...)
	chain.isRoute = true
	chain.Interface = c.Interface
	chain.Mark = c.Mark
	return chain
}

// Nodes returns the proxy nodes that the chain holds.
// The first node in each group will be returned.
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
// If the chain is empty, an empty node will be returned.
// If the last node is a node group, the first node in the group will be returned.
func (c *Chain) LastNode() Node {
	if c.IsEmpty() {
		return Node{}
	}
	group := c.nodeGroups[len(c.nodeGroups)-1]
	return group.GetNode(0)
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

// Dial connects to the target TCP address addr through the chain.
// Deprecated: use DialContext instead.
func (c *Chain) Dial(address string, opts ...ChainOption) (conn net.Conn, err error) {
	return c.DialContext(context.Background(), "tcp", address, opts...)
}

// DialContext connects to the address on the named network using the provided context.
func (c *Chain) DialContext(ctx context.Context, network, address string, opts ...ChainOption) (conn net.Conn, err error) {
	options := &ChainOptions{}
	for _, opt := range opts {
		opt(options)
	}

	retries := 1
	if c != nil && c.Retries > 0 {
		retries = c.Retries
	}
	if options.Retries > 0 {
		retries = options.Retries
	}

	for i := 0; i < retries; i++ {
		conn, err = c.dialWithOptions(ctx, network, address, options)
		if err == nil {
			break
		}
	}
	return
}

func (c *Chain) dialWithOptions(ctx context.Context, network, address string, options *ChainOptions) (net.Conn, error) {
	if options == nil {
		options = &ChainOptions{}
	}
	route, err := c.selectRouteFor(address)
	if err != nil {
		return nil, err
	}

	ipAddr := address
	if address != "" {
		ipAddr = c.resolve(address, options.Resolver, options.Hosts)
	}

	timeout := options.Timeout
	if timeout <= 0 {
		timeout = DialTimeout
	}

	var controlFunction func(_ string, _ string, c syscall.RawConn) error = nil
	if c.Mark > 0 {
		controlFunction = func(_, _ string, cc syscall.RawConn) error {
			return cc.Control(func(fd uintptr) {
				ex := setSocketMark(int(fd), c.Mark)
				if ex != nil {
					log.Logf("net dialer set mark %d error: %s", c.Mark, ex)
				} else {
					// log.Logf("net dialer set mark %d success", options.Mark)
				}
			})
		}
	}

	if c.Interface != "" {
		controlFunction = func(_, _ string, cc syscall.RawConn) error {
			return cc.Control(func(fd uintptr) {
				err := setSocketInterface(int(fd), c.Interface)

				if err != nil {
					log.Logf("net dialer set interface %s error: %s", c.Interface, err)
				}
			})
		}
	}

	if route.IsEmpty() {
		switch network {
		case "udp", "udp4", "udp6":
			if address == "" {
				return net.ListenUDP(network, nil)
			}
		default:
		}
		d := &net.Dialer{
			Timeout: timeout,
			Control: controlFunction,
			// LocalAddr: laddr, // TODO: optional local address
		}
		return d.DialContext(ctx, network, ipAddr)
	}

	conn, err := route.getConn(ctx)
	if err != nil {
		return nil, err
	}

	cOpts := append([]ConnectOption{AddrConnectOption(address)}, route.LastNode().ConnectOptions...)
	cc, err := route.LastNode().Client.ConnectContext(ctx, conn, network, ipAddr, cOpts...)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return cc, nil
}

func (*Chain) resolve(addr string, resolver Resolver, hosts *Hosts) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}

	if ip := hosts.Lookup(host); ip != nil {
		return net.JoinHostPort(ip.String(), port)
	}
	if resolver != nil {
		ips, err := resolver.Resolve(host)
		if err != nil {
			log.Logf("[resolver] %s: %v", host, err)
		}
		if len(ips) > 0 {
			return net.JoinHostPort(ips[0].String(), port)
		}
	}
	return addr
}

// Conn obtains a handshaked connection to the last node of the chain.
func (c *Chain) Conn(opts ...ChainOption) (conn net.Conn, err error) {
	options := &ChainOptions{}
	for _, opt := range opts {
		opt(options)
	}

	ctx := context.Background()

	retries := 1
	if c != nil && c.Retries > 0 {
		retries = c.Retries
	}
	if options.Retries > 0 {
		retries = options.Retries
	}

	for i := 0; i < retries; i++ {
		var route *Chain
		route, err = c.selectRoute()
		if err != nil {
			continue
		}
		conn, err = route.getConn(ctx)
		if err == nil {
			break
		}
	}
	return
}

// getConn obtains a connection to the last node of the chain.
func (c *Chain) getConn(ctx context.Context) (conn net.Conn, err error) {
	if c.IsEmpty() {
		err = ErrEmptyChain
		return
	}
	nodes := c.Nodes()
	node := nodes[0]

	cc, err := node.Client.Dial(node.Addr, node.DialOptions...)
	if err != nil {
		node.MarkDead()
		return
	}

	cn, err := node.Client.Handshake(cc, node.HandshakeOptions...)
	if err != nil {
		cc.Close()
		node.MarkDead()
		return
	}
	node.ResetDead()

	preNode := node
	for _, node := range nodes[1:] {
		var cc net.Conn
		cc, err = preNode.Client.ConnectContext(ctx, cn, "tcp", node.Addr, preNode.ConnectOptions...)
		if err != nil {
			cn.Close()
			node.MarkDead()
			return
		}
		cc, err = node.Client.Handshake(cc, node.HandshakeOptions...)
		if err != nil {
			cn.Close()
			node.MarkDead()
			return
		}
		node.ResetDead()

		cn = cc
		preNode = node
	}

	conn = cn
	return
}

func (c *Chain) selectRoute() (route *Chain, err error) {
	return c.selectRouteFor("")
}

// selectRouteFor selects route with bypass testing.
func (c *Chain) selectRouteFor(addr string) (route *Chain, err error) {
	if c.IsEmpty() {
		return c.newRoute(), nil
	}
	if c.isRoute {
		return c, nil
	}

	route = c.newRoute()
	var nl []Node

	for _, group := range c.nodeGroups {
		var node Node
		node, err = group.Next()
		if err != nil {
			return
		}

		if node.Bypass.Contains(addr) {
			break
		}

		if node.Client.Transporter.Multiplex() {
			node.DialOptions = append(node.DialOptions,
				ChainDialOption(route),
			)
			route = c.newRoute() // cutoff the chain for multiplex node.
		}

		route.AddNode(node)
		nl = append(nl, node)
	}

	route.route = nl

	return
}

// ChainOptions holds options for Chain.
type ChainOptions struct {
	Retries  int
	Timeout  time.Duration
	Hosts    *Hosts
	Resolver Resolver
	Mark     int
}

// ChainOption allows a common way to set chain options.
type ChainOption func(opts *ChainOptions)

// RetryChainOption specifies the times of retry used by Chain.Dial.
func RetryChainOption(retries int) ChainOption {
	return func(opts *ChainOptions) {
		opts.Retries = retries
	}
}

// TimeoutChainOption specifies the timeout used by Chain.Dial.
func TimeoutChainOption(timeout time.Duration) ChainOption {
	return func(opts *ChainOptions) {
		opts.Timeout = timeout
	}
}

// HostsChainOption specifies the hosts used by Chain.Dial.
func HostsChainOption(hosts *Hosts) ChainOption {
	return func(opts *ChainOptions) {
		opts.Hosts = hosts
	}
}

// ResolverChainOption specifies the Resolver used by Chain.Dial.
func ResolverChainOption(resolver Resolver) ChainOption {
	return func(opts *ChainOptions) {
		opts.Resolver = resolver
	}
}
