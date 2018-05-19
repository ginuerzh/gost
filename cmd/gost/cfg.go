package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ginuerzh/gost"
)

var (
	defaultCertFile = "cert.pem"
	defaultKeyFile  = "key.pem"
)

// Load the certificate from cert and key files, will use the default certificate if the provided info are invalid.
func tlsConfig(certFile, keyFile string) (*tls.Config, error) {
	if certFile == "" {
		certFile = defaultCertFile
	}
	if keyFile == "" {
		keyFile = defaultKeyFile
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
}

func loadCA(caFile string) (cp *x509.CertPool, err error) {
	if caFile == "" {
		return
	}
	cp = x509.NewCertPool()
	data, err := ioutil.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	if !cp.AppendCertsFromPEM(data) {
		return nil, errors.New("AppendCertsFromPEM failed")
	}
	return
}

func loadConfigureFile(configureFile string) error {
	if configureFile == "" {
		return nil
	}
	content, err := ioutil.ReadFile(configureFile)
	if err != nil {
		return err
	}
	var cfg struct {
		route
		Routes []route
	}
	if err := json.Unmarshal(content, &cfg); err != nil {
		return err
	}

	if len(cfg.route.ServeNodes) > 0 {
		routes = append(routes, cfg.route)
	}
	for _, route := range cfg.Routes {
		if len(route.ServeNodes) > 0 {
			routes = append(routes, route)
		}
	}
	gost.Debug = cfg.Debug

	return nil
}

type stringList []string

func (l *stringList) String() string {
	return fmt.Sprintf("%s", *l)
}
func (l *stringList) Set(value string) error {
	*l = append(*l, value)
	return nil
}

func parseKCPConfig(configFile string) (*gost.KCPConfig, error) {
	if configFile == "" {
		return nil, nil
	}
	file, err := os.Open(configFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	config := &gost.KCPConfig{}
	if err = json.NewDecoder(file).Decode(config); err != nil {
		return nil, err
	}
	return config, nil
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

func parseIP(s string, port string) (ips []string) {
	if s == "" {
		return
	}
	if port == "" {
		port = "8080" // default port
	}

	file, err := os.Open(s)
	if err != nil {
		ss := strings.Split(s, ",")
		for _, s := range ss {
			s = strings.TrimSpace(s)
			if s != "" {
				if !strings.Contains(s, ":") {
					s = s + ":" + port
				}
				ips = append(ips, s)
			}

		}
		return
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.Contains(line, ":") {
			line = line + ":" + port
		}
		ips = append(ips, line)
	}
	return
}

type peerConfig struct {
	Strategy    string   `json:"strategy"`
	Filters     []string `json:"filters"`
	MaxFails    int      `json:"max_fails"`
	FailTimeout int      `json:"fail_timeout"`
	Nodes       []string `json:"nodes"`
	Bypass      *bypass  `json:"bypass"` // global bypass
}

type bypass struct {
	Reverse  bool     `json:"reverse"`
	Patterns []string `json:"patterns"`
}

func loadPeerConfig(peer string) (config peerConfig, err error) {
	if peer == "" {
		return
	}
	content, err := ioutil.ReadFile(peer)
	if err != nil {
		return
	}
	err = json.Unmarshal(content, &config)
	return
}

func (cfg *peerConfig) Validate() {
	if cfg.MaxFails <= 0 {
		cfg.MaxFails = 1
	}
	if cfg.FailTimeout <= 0 {
		cfg.FailTimeout = 30 // seconds
	}
}

func parseStrategy(s string) gost.Strategy {
	switch s {
	case "random":
		return &gost.RandomStrategy{}
	case "fifo":
		return &gost.FIFOStrategy{}
	case "round":
		fallthrough
	default:
		return &gost.RoundStrategy{}

	}
}

func parseBypass(s string) *gost.Bypass {
	if s == "" {
		return nil
	}
	var matchers []gost.Matcher
	var reversed bool
	if strings.HasPrefix(s, "~") {
		reversed = true
		s = strings.TrimLeft(s, "~")
	}

	f, err := os.Open(s)
	if err != nil {
		for _, s := range strings.Split(s, ",") {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			matchers = append(matchers, gost.NewMatcher(s))
		}
		return gost.NewBypass(matchers, reversed)
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if n := strings.IndexByte(line, '#'); n >= 0 {
			line = line[:n]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		matchers = append(matchers, gost.NewMatcher(line))
	}
	return gost.NewBypass(matchers, reversed)
}

func parseResolver(cfg string) gost.Resolver {
	if cfg == "" {
		return nil
	}
	f, err := os.Open(cfg)
	if err != nil {
		for _, s := range strings.Split(cfg, ",") {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
		}
		// return gost.NewBypass(matchers, reversed)
	}

	timeout := 30 * time.Second

	var nss []gost.NameServer
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if n := strings.IndexByte(line, '#'); n >= 0 {
			line = line[:n]
		}
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

		if len(ss) == 0 {
			continue
		}

		if ss[0] == "timeout" {
			if len(ss) >= 2 {
				if n, _ := strconv.Atoi(ss[1]); n > 0 {
					timeout = time.Second * time.Duration(n)
				}
			}
			continue
		}

		var ns gost.NameServer
		if len(ss) == 1 {
			ns.Addr = ss[0]
		}
		if len(ss) == 2 {
			ns.Addr = ss[0]
			ns.Protocol = ss[1]
		}
		if len(ss) == 3 {
			ns.Addr = ss[0]
			ns.Protocol = ss[1]
			ns.Hostname = ss[2]
		}
		nss = append(nss, ns)
	}
	return gost.NewResolver(nss, timeout)
}
