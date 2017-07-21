package gost

type Node struct {
	Addr      string
	Protocol  string
	Transport string
	Client    *Client
}
