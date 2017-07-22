package gost

// Node is a proxy node, mainly used to construct a proxy chain.
type Node struct {
	Addr      string
	Protocol  string
	Transport string
	Client    *Client
}
