package gost

import (
	"bufio"
	"io"
	"net"
	"strings"

	"github.com/go-log/log"
)

// Host is a static mapping from hostname to IP.
type Host struct {
	IP       net.IP
	Hostname string
	Aliases  []string
}

// Hosts is a static table lookup for hostnames.
type Hosts struct {
	hosts []Host
}

// NewHosts creates a Hosts with optional list of host
func NewHosts(hosts ...Host) *Hosts {
	return &Hosts{
		hosts: hosts,
	}
}

// ParseHosts parses host table from r.
// For each host a single line should be present with the following information:
// IP_address canonical_hostname [aliases...]
// Fields of the entry are separated by any number of blanks and/or tab characters.
// Text from a "#" character until the end of the line is a comment, and is ignored.
func ParseHosts(r io.Reader) (*Hosts, error) {
	hosts := NewHosts()
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if n := strings.IndexByte(line, '#'); n >= 0 {
			line = line[:n]
		}
		line = strings.Replace(line, "\t", " ", -1)
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var ss []string
		for _, s := range strings.Split(line, " ") {
			if s = strings.TrimSpace(s); s != "" {
				ss = append(ss, s)
			}
		}
		if len(ss) < 2 {
			continue // invalid lines are ignored
		}
		ip := net.ParseIP(ss[0])
		if ip == nil {
			continue // invalid IP addresses are ignored
		}
		host := Host{
			IP:       ip,
			Hostname: ss[1],
		}
		if len(ss) > 2 {
			host.Aliases = ss[2:]
		}
		hosts.AddHost(host)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return hosts, nil
}

// AddHost adds host(s) to the host table.
func (h *Hosts) AddHost(host ...Host) {
	h.hosts = append(h.hosts, host...)
}

// Lookup searches the IP address corresponds to the given host from the host table.
func (h *Hosts) Lookup(host string) (ip net.IP) {
	if h == nil {
		return
	}
	for _, h := range h.hosts {
		if h.Hostname == host {
			ip = h.IP
			break
		}
		for _, alias := range h.Aliases {
			if alias == host {
				ip = h.IP
				break
			}
		}
	}
	if ip != nil && Debug {
		log.Logf("[hosts] hit: %s %s", host, ip.String())
	}
	return
}
