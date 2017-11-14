package gost

import (
	"fmt"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

// Node is a proxy node, mainly used to construct a proxy chain.
type Node struct {
	ID               int
	Addr             string
	Host             string
	Protocol         string
	Transport        string
	Remote           string // remote address, used by tcp/udp port forwarding
	User             *url.Userinfo
	Values           url.Values
	DialOptions      []DialOption
	HandshakeOptions []HandshakeOption
	Client           *Client
	group            *NodeGroup
	failCount        uint32
	failTime         time.Time
}

// ParseNode parses the node info.
// The proxy node string pattern is [scheme://][user:pass@host]:port.
// Scheme can be divided into two parts by character '+', such as: http+tls.
func ParseNode(s string) (node Node, err error) {
	if s == "" {
		return Node{}, nil
	}

	if !strings.Contains(s, "://") {
		s = "auto://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return
	}

	node = Node{
		Addr:   u.Host,
		Host:   u.Host,
		Remote: strings.Trim(u.EscapedPath(), "/"),
		Values: u.Query(),
		User:   u.User,
	}

	schemes := strings.Split(u.Scheme, "+")
	if len(schemes) == 1 {
		node.Protocol = schemes[0]
		node.Transport = schemes[0]
	}
	if len(schemes) == 2 {
		node.Protocol = schemes[0]
		node.Transport = schemes[1]
	}

	switch node.Transport {
	case "tls", "mtls", "ws", "mws", "wss", "mwss", "kcp", "ssh", "quic", "ssu", "http2", "h2", "h2c", "obfs4":
	case "https":
		node.Protocol = "http"
		node.Transport = "tls"
	case "tcp", "udp": // started from v2.1, tcp and udp are for local port forwarding
	case "rtcp", "rudp": // rtcp and rudp are for remote port forwarding
	case "ohttp": // obfs-http
	default:
		node.Transport = "tcp"
	}

	switch node.Protocol {
	case "http", "http2", "socks4", "socks4a", "ss", "ssu", "sni":
	case "socks", "socks5":
		node.Protocol = "socks5"
	case "tcp", "udp", "rtcp", "rudp": // port forwarding
	case "direct", "remote", "forward": // forwarding
	case "redirect": // TCP transparent proxy
	default:
		node.Protocol = ""
	}

	return
}

// MarkDead marks the node fail status.
func (node *Node) MarkDead() {
	atomic.AddUint32(&node.failCount, 1)
	node.failTime = time.Now()

	if node.group == nil {
		return
	}
	for i := range node.group.nodes {
		if node.group.nodes[i].ID == node.ID {
			atomic.AddUint32(&node.group.nodes[i].failCount, 1)
			node.group.nodes[i].failTime = time.Now()
			break
		}
	}
}

// ResetDead resets the node fail status.
func (node *Node) ResetDead() {
	atomic.StoreUint32(&node.failCount, 0)
	node.failTime = time.Time{}

	if node.group == nil {
		return
	}

	for i := range node.group.nodes {
		if node.group.nodes[i].ID == node.ID {
			atomic.StoreUint32(&node.group.nodes[i].failCount, 0)
			node.group.nodes[i].failTime = time.Time{}
			break
		}
	}
}

func (node *Node) String() string {
	return fmt.Sprintf("%d@%s", node.ID, node.Addr)
}

// NodeGroup is a group of nodes.
type NodeGroup struct {
	ID       int
	nodes    []Node
	Options  []SelectOption
	Selector NodeSelector
}

// NewNodeGroup creates a node group
func NewNodeGroup(nodes ...Node) *NodeGroup {
	return &NodeGroup{
		nodes: nodes,
	}
}

// AddNode adds node or node list into group
func (group *NodeGroup) AddNode(node ...Node) {
	if group == nil {
		return
	}
	group.nodes = append(group.nodes, node...)
}

// Nodes returns node list in the group
func (group *NodeGroup) Nodes() []Node {
	if group == nil {
		return nil
	}
	return group.nodes
}

// Next selects the next node from group.
// It also selects IP if the IP list exists.
func (group *NodeGroup) Next() (node Node, err error) {
	selector := group.Selector
	if selector == nil {
		selector = &defaultSelector{}
	}
	// select node from node group
	node, err = selector.Select(group.Nodes(), group.Options...)
	if err != nil {
		return
	}
	node.group = group

	return
}
