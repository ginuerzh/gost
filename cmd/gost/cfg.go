package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/url"
	"os"
	"strings"

	"github.com/ginuerzh/gost"
)

var (
	routers []router
)

type baseConfig struct {
	route
	Routes []route
	Debug  bool
}

func parseBaseConfig(s string) (*baseConfig, error) {
	file, err := os.Open(s)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	if err := json.NewDecoder(file).Decode(baseCfg); err != nil {
		return nil, err
	}

	return baseCfg, nil
}

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

func parseAuthenticator(s string) (gost.Authenticator, error) {
	if s == "" {
		return nil, nil
	}
	f, err := os.Open(s)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	au := gost.NewLocalAuthenticator(nil)
	au.Reload(f)

	go gost.PeriodReload(au, s)

	return au, nil
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
		return gost.NewBypass(reversed, matchers...)
	}
	defer f.Close()

	bp := gost.NewBypass(reversed)
	bp.Reload(f)
	go gost.PeriodReload(bp, s)

	return bp
}

func parseResolver(cfg string) gost.Resolver {
	if cfg == "" {
		return nil
	}
	var nss []gost.NameServer

	f, err := os.Open(cfg)
	if err != nil {
		for _, s := range strings.Split(cfg, ",") {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			if strings.HasPrefix(s, "https") {
				ns := gost.NameServer{
					Addr:     s,
					Protocol: "https",
				}
				if err := ns.Init(); err == nil {
					nss = append(nss, ns)
				}
				continue
			}

			ss := strings.Split(s, "/")
			if len(ss) == 1 {
				ns := gost.NameServer{
					Addr: ss[0],
				}
				if err := ns.Init(); err == nil {
					nss = append(nss, ns)
				}
			}
			if len(ss) == 2 {
				ns := gost.NameServer{
					Addr:     ss[0],
					Protocol: ss[1],
				}
				if err := ns.Init(); err == nil {
					nss = append(nss, ns)
				}
			}
		}
		return gost.NewResolver(0, nss...)
	}
	defer f.Close()

	resolver := gost.NewResolver(0)
	resolver.Reload(f)

	go gost.PeriodReload(resolver, cfg)

	return resolver
}

func parseHosts(s string) *gost.Hosts {
	f, err := os.Open(s)
	if err != nil {
		return nil
	}
	defer f.Close()

	hosts := gost.NewHosts()
	hosts.Reload(f)

	go gost.PeriodReload(hosts, s)

	return hosts
}
