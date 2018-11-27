package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"io/ioutil"
	"strconv"
	"strings"
	"time"

	"github.com/ginuerzh/gost"
)

const (
	defaultMaxFails    = 1
	defaultFailTimeout = 30 * time.Second
)

type peerConfig struct {
	Strategy    string        `json:"strategy"`
	MaxFails    int           `json:"max_fails"`
	FailTimeout time.Duration `json:"fail_timeout"`
	period      time.Duration // the period for live reloading
	Nodes       []string      `json:"nodes"`
	group       *gost.NodeGroup
	baseNodes   []gost.Node
}

type bypass struct {
	Reverse  bool     `json:"reverse"`
	Patterns []string `json:"patterns"`
}

func parsePeerConfig(cfg string, group *gost.NodeGroup, baseNodes []gost.Node) *peerConfig {
	pc := &peerConfig{
		group:     group,
		baseNodes: baseNodes,
	}
	go gost.PeriodReload(pc, cfg)
	return pc
}

func (cfg *peerConfig) Validate() {
	if cfg.MaxFails <= 0 {
		cfg.MaxFails = defaultMaxFails
	}
	if cfg.FailTimeout <= 0 {
		cfg.FailTimeout = defaultFailTimeout // seconds
	}
}

func (cfg *peerConfig) Reload(r io.Reader) error {
	if err := cfg.parse(r); err != nil {
		return err
	}
	cfg.Validate()

	group := cfg.group
	/*
		strategy := cfg.Strategy
		if len(cfg.baseNodes) > 0 {
			// overwrite the strategry in the peer config if `strategy` param exists.
			if s := cfg.baseNodes[0].Get("strategy"); s != "" {
				strategy = s
			}
		}
	*/
	group.SetSelector(
		nil,
		gost.WithFilter(&gost.FailFilter{
			MaxFails:    cfg.MaxFails,
			FailTimeout: cfg.FailTimeout,
		}),
		gost.WithStrategy(parseStrategy(cfg.Strategy)),
	)

	gNodes := cfg.baseNodes
	nid := len(gNodes) + 1
	for _, s := range cfg.Nodes {
		nodes, err := parseChainNode(s)
		if err != nil {
			return err
		}

		for i := range nodes {
			nodes[i].ID = nid
			nid++
		}

		gNodes = append(gNodes, nodes...)
	}

	group.SetNodes(gNodes...)

	return nil
}

func (cfg *peerConfig) parse(r io.Reader) error {
	data, err := ioutil.ReadAll(r)
	if err != nil {
		return err
	}

	// compatible with JSON format
	if err := json.NewDecoder(bytes.NewReader(data)).Decode(cfg); err == nil {
		return nil
	}

	split := func(line string) []string {
		if line == "" {
			return nil
		}
		if n := strings.IndexByte(line, '#'); n >= 0 {
			line = line[:n]
		}
		line = strings.Replace(line, "\t", " ", -1)
		line = strings.TrimSpace(line)

		var ss []string
		for _, s := range strings.Split(line, " ") {
			if s = strings.TrimSpace(s); s != "" {
				ss = append(ss, s)
			}
		}
		return ss
	}

	cfg.Nodes = nil
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		ss := split(line)
		if len(ss) < 2 {
			continue
		}

		switch ss[0] {
		case "strategy":
			cfg.Strategy = ss[1]
		case "max_fails":
			cfg.MaxFails, _ = strconv.Atoi(ss[1])
		case "fail_timeout":
			cfg.FailTimeout, _ = time.ParseDuration(ss[1])
		case "reload":
			cfg.period, _ = time.ParseDuration(ss[1])
		case "peer":
			cfg.Nodes = append(cfg.Nodes, ss[1])
		}
	}

	return scanner.Err()
}

func (cfg *peerConfig) Period() time.Duration {
	return cfg.period
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
