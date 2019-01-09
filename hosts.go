package gost

import (
	"bufio"
	"io"
	"net"
	"sync"
	"time"

	"github.com/go-log/log"
)

// Host is a static mapping from hostname to IP.
type Host struct {
	IP       net.IP
	Hostname string
	Aliases  []string
}

// NewHost creates a Host.
func NewHost(ip net.IP, hostname string, aliases ...string) Host {
	return Host{
		IP:       ip,
		Hostname: hostname,
		Aliases:  aliases,
	}
}

// Hosts is a static table lookup for hostnames.
// For each host a single line should be present with the following information:
// IP_address canonical_hostname [aliases...]
// Fields of the entry are separated by any number of blanks and/or tab characters.
// Text from a "#" character until the end of the line is a comment, and is ignored.
type Hosts struct {
	hosts   []Host
	period  time.Duration
	stopped chan struct{}
	mux     sync.RWMutex
}

// NewHosts creates a Hosts with optional list of hosts.
func NewHosts(hosts ...Host) *Hosts {
	return &Hosts{
		hosts:   hosts,
		stopped: make(chan struct{}),
	}
}

// AddHost adds host(s) to the host table.
func (h *Hosts) AddHost(host ...Host) {
	h.mux.Lock()
	defer h.mux.Unlock()

	h.hosts = append(h.hosts, host...)
}

// Lookup searches the IP address corresponds to the given host from the host table.
func (h *Hosts) Lookup(host string) (ip net.IP) {
	if h == nil || host == "" {
		return
	}

	h.mux.RLock()
	defer h.mux.RUnlock()

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

// Reload parses config from r, then live reloads the hosts.
func (h *Hosts) Reload(r io.Reader) error {
	var period time.Duration
	var hosts []Host

	if r == nil || h.Stopped() {
		return nil
	}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		ss := splitLine(line)
		if len(ss) < 2 {
			continue // invalid lines are ignored
		}

		switch ss[0] {
		case "reload": // reload option
			period, _ = time.ParseDuration(ss[1])
		default:
			ip := net.ParseIP(ss[0])
			if ip == nil {
				break // invalid IP addresses are ignored
			}
			host := Host{
				IP:       ip,
				Hostname: ss[1],
			}
			if len(ss) > 2 {
				host.Aliases = ss[2:]
			}
			hosts = append(hosts, host)
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	h.mux.Lock()
	h.period = period
	h.hosts = hosts
	h.mux.Unlock()

	return nil
}

// Period returns the reload period
func (h *Hosts) Period() time.Duration {
	if h.Stopped() {
		return -1
	}

	h.mux.RLock()
	defer h.mux.RUnlock()

	return h.period
}

// Stop stops reloading.
func (h *Hosts) Stop() {
	select {
	case <-h.stopped:
	default:
		close(h.stopped)
	}
}

// Stopped checks whether the reloader is stopped.
func (h *Hosts) Stopped() bool {
	select {
	case <-h.stopped:
		return true
	default:
		return false
	}
}
