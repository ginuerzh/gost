package gost

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
)

var (
	// ErrInvalidNode is an error that implies the node is invalid.
	ErrInvalidNode = errors.New("invalid node")
)

// Node is a proxy node, mainly used to construct a proxy chain.
type Node struct {
	ID               int
	Addr             string
	Host             string
	Protocol         string
	Transport        string
	Remote           string   // remote address, used by tcp/udp port forwarding
	url              *url.URL // raw url
	User             *url.Userinfo
	Values           url.Values
	DialOptions      []DialOption
	HandshakeOptions []HandshakeOption
	Client           *Client
	marker           *failMarker
	Bypass           *Bypass
}

// ParseNode parses the node info.
// The proxy node string pattern is [scheme://][user:pass@host]:port.
// Scheme can be divided into two parts by character '+', such as: http+tls.
func ParseNode(s string) (node Node, err error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Node{}, ErrInvalidNode
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
		marker: &failMarker{},
		url:    u,
	}

	u.RawQuery = ""
	u.User = nil

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
	if node.marker == nil {
		return
	}
	node.marker.Mark()
}

// ResetDead resets the node fail status.
func (node *Node) ResetDead() {
	if node.marker == nil {
		return
	}
	node.marker.Reset()
}

// Clone clones the node, it will prevent data race.
func (node *Node) Clone() Node {
	nd := *node
	if node.marker != nil {
		nd.marker = node.marker.Clone()
	}
	return nd
}

// Get returns node parameter specified by key.
func (node *Node) Get(key string) string {
	return node.Values.Get(key)
}

// GetBool likes Get, but convert parameter value to bool.
func (node *Node) GetBool(key string) bool {
	b, _ := strconv.ParseBool(node.Values.Get(key))
	return b
}

// GetInt likes Get, but convert parameter value to int.
func (node *Node) GetInt(key string) int {
	n, _ := strconv.Atoi(node.Values.Get(key))
	return n
}

func (node Node) String() string {
	if node.url == nil {
		return fmt.Sprintf("%s+%s://%s",
			node.Protocol, node.Transport, node.Addr)
	}
	return node.url.String()
}

// NodeGroup is a group of nodes.
type NodeGroup struct {
	ID              int
	nodes           []Node
	selectorOptions []SelectOption
	selector        NodeSelector
	mux             sync.RWMutex
}

// NewNodeGroup creates a node group
func NewNodeGroup(nodes ...Node) *NodeGroup {
	return &NodeGroup{
		nodes: nodes,
	}
}

// AddNode appends node or node list into group node.
func (group *NodeGroup) AddNode(node ...Node) {
	if group == nil {
		return
	}
	group.mux.Lock()
	defer group.mux.Unlock()

	group.nodes = append(group.nodes, node...)
}

// SetNodes replaces the group nodes to the specified nodes,
// and returns the previous nodes.
func (group *NodeGroup) SetNodes(nodes ...Node) []Node {
	if group == nil {
		return nil
	}

	group.mux.Lock()
	defer group.mux.Unlock()

	old := group.nodes
	group.nodes = nodes
	return old
}

// SetSelector sets node selector with options for the group.
func (group *NodeGroup) SetSelector(selector NodeSelector, opts ...SelectOption) {
	if group == nil {
		return
	}
	group.mux.Lock()
	defer group.mux.Unlock()

	group.selector = selector
	group.selectorOptions = opts
}

// Nodes returns the node list in the group
func (group *NodeGroup) Nodes() []Node {
	if group == nil {
		return nil
	}

	group.mux.RLock()
	defer group.mux.RUnlock()

	return group.nodes
}

// GetNode returns the node specified by index in the group.
func (group *NodeGroup) GetNode(i int) Node {
	group.mux.RLock()
	defer group.mux.RUnlock()

	if i < 0 || group == nil || len(group.nodes) <= i {
		return Node{}
	}
	return group.nodes[i]
}

// Next selects a node from group.
// It also selects IP if the IP list exists.
func (group *NodeGroup) Next() (node Node, err error) {
	if group == nil {
		return
	}

	group.mux.RLock()
	defer group.mux.RUnlock()

	selector := group.selector
	if selector == nil {
		selector = &defaultSelector{}
	}

	// select node from node group
	node, err = selector.Select(group.nodes, group.selectorOptions...)
	if err != nil {
		return
	}

	return
}
