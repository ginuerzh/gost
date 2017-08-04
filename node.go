package gost

import (
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/go-log/log"
)

// Node is a proxy node, mainly used to construct a proxy chain.
type Node struct {
	Addr             string
	Protocol         string
	Transport        string
	Remote           string // remote address, used by tcp/udp port forwarding
	User             *url.Userinfo
	Values           url.Values
	Client           *Client
	DialOptions      []DialOption
	HandshakeOptions []HandshakeOption
}

func ParseNode(s string) (node Node, err error) {
	if !strings.Contains(s, "://") {
		s = "auto://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return
	}

	node = Node{
		Addr:   u.Host,
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
	case "tls", "ws", "wss", "kcp", "ssh", "quic", "ssu", "http2", "h2", "h2c", "redirect":
	case "https":
		node.Protocol = "http"
		node.Transport = "tls"
	case "tcp", "udp": // started from v2.1, tcp and udp are for local port forwarding
		node.Remote = strings.Trim(u.EscapedPath(), "/")
	case "rtcp", "rudp": // rtcp and rudp are for remote port forwarding
		node.Remote = strings.Trim(u.EscapedPath(), "/")
	default:
		node.Transport = ""
	}

	switch node.Protocol {
	case "http", "http2", "socks4", "socks4a", "ss", "ssu":
	case "socks", "socks5":
		node.Protocol = "socks5"
	case "tcp", "udp", "rtcp", "rudp": // port forwarding
	case "direct", "remote", "forward": // SSH port forwarding
	default:
		node.Protocol = ""
	}

	return
}

func Can(action string, addr string, whitelist, blacklist *Permissions) bool {
	if !strings.Contains(addr, ":") {
		addr = addr + ":80"
	}
	host, strport, err := net.SplitHostPort(addr)

	if err != nil {
		return false
	}

	port, err := strconv.Atoi(strport)

	if err != nil {
		return false
	}

	if Debug {
		log.Logf("Can action: %s, host: %s, port %d", action, host, port)
	}
	return whitelist.Can(action, host, port) && !blacklist.Can(action, host, port)
}
