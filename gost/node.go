package gost

import (
	"bufio"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/go-log/log"
)

// Node is a proxy node, mainly used to construct a proxy chain.
type Node struct {
	Addr       string
	Protocol   string
	Transport  string
	Remote     string // remote address, used by tcp/udp port forwarding
	User       *url.Userinfo
	users      []*url.Userinfo // authentication or cipher for proxy
	Whitelist  *Permissions
	Blacklist  *Permissions
	values     url.Values
	serverName string
	Client     *Client
	Server     *Server
}

func ParseNode(s string) (node Node, err error) {
	if !strings.Contains(s, "://") {
		s = "auto://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return
	}

	query := u.Query()
	node = Node{
		Addr:       u.Host,
		values:     query,
		serverName: u.Host,
	}

	if query.Get("whitelist") != "" {
		if node.Whitelist, err = ParsePermissions(query.Get("whitelist")); err != nil {
			return
		}
	} else {
		// By default allow for everyting
		node.Whitelist, _ = ParsePermissions("*:*:*")
	}

	if query.Get("blacklist") != "" {
		if node.Blacklist, err = ParsePermissions(query.Get("blacklist")); err != nil {
			return
		}
	} else {
		// By default block nothing
		node.Blacklist, _ = ParsePermissions("")
	}

	if u.User != nil {
		node.User = u.User
		node.users = append(node.users, u.User)
	}

	users, er := parseUsers(node.values.Get("secrets"))
	if users != nil {
		node.users = append(node.users, users...)
	}
	if er != nil {
		log.Log("load secrets:", er)
	}

	if strings.Contains(u.Host, ":") {
		node.serverName, _, _ = net.SplitHostPort(u.Host)
		if node.serverName == "" {
			node.serverName = "localhost" // default server name
		}
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
	case "http", "http2", "socks4", "socks4a", "socks", "socks5", "ss":
	case "tcp", "udp", "rtcp", "rudp": // port forwarding
	case "direct", "remote": // SSH port forwarding
	default:
		node.Protocol = ""
	}

	return
}

func parseUsers(authFile string) (users []*url.Userinfo, err error) {
	if authFile == "" {
		return
	}

	file, err := os.Open(authFile)
	if err != nil {
		return
	}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		s := strings.SplitN(line, " ", 2)
		if len(s) == 1 {
			users = append(users, url.User(strings.TrimSpace(s[0])))
		} else if len(s) == 2 {
			users = append(users, url.UserPassword(strings.TrimSpace(s[0]), strings.TrimSpace(s[1])))
		}
	}

	err = scanner.Err()
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

	log.Logf("Can action: %s, host: %s, port %d", action, host, port)

	return whitelist.Can(action, host, port) && !blacklist.Can(action, host, port)
}
