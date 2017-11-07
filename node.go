package gost

import (
	"net/url"
	"strings"
	"sync"
)

// Node is a proxy node, mainly used to construct a proxy chain.
type Node struct {
	ID               int
	Addr             string
	IPs              []string
	Protocol         string
	Transport        string
	Remote           string // remote address, used by tcp/udp port forwarding
	User             *url.Userinfo
	Values           url.Values
	DialOptions      []DialOption
	HandshakeOptions []HandshakeOption
	Client           *Client
	IPSelector       IPSelector
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

// NodeGroup is a group of nodes.
type NodeGroup struct {
	nodes       []Node
	Options     []SelectOption
	Selector    NodeSelector
	mutex       sync.Mutex
	mFails      map[string]int // node -> fail count
	MaxFails    int
	FailTimeout int
	Retries     int
}

// NewNodeGroup creates a node group
func NewNodeGroup(nodes ...Node) *NodeGroup {
	return &NodeGroup{
		nodes:  nodes,
		mFails: make(map[string]int),
	}
}

// AddNode adds node or node list into group
func (ng *NodeGroup) AddNode(node ...Node) {
	if ng == nil {
		return
	}
	ng.nodes = append(ng.nodes, node...)
}

// Nodes returns node list in the group
func (ng *NodeGroup) Nodes() []Node {
	if ng == nil {
		return nil
	}
	return ng.nodes
}
