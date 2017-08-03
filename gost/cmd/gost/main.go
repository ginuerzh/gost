package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"runtime"

	"github.com/ginuerzh/gost/gost"
	"github.com/go-log/log"
)

var (
	options struct {
		chainNodes, serveNodes stringList
		debugMode              bool
	}
)

func init() {
	var (
		configureFile string
		printVersion  bool
	)

	flag.Var(&options.chainNodes, "F", "forward address, can make a forward chain")
	flag.Var(&options.serveNodes, "L", "listen address, can listen on multiple ports")
	flag.StringVar(&configureFile, "C", "", "configure file")
	flag.BoolVar(&options.debugMode, "D", false, "enable debug log")
	flag.BoolVar(&printVersion, "V", false, "print version")
	flag.Parse()

	if err := loadConfigureFile(configureFile); err != nil {
		log.Log(err)
		os.Exit(1)
	}

	if flag.NFlag() == 0 {
		flag.PrintDefaults()
		os.Exit(0)
	}

	if printVersion {
		fmt.Fprintf(os.Stderr, "gost %s (%s)\n", gost.Version, runtime.Version())
		os.Exit(0)
	}

	gost.Debug = options.debugMode
}

func main() {

}

func buildChain() (*gost.Chain, error) {
	chain := gost.NewChain()
	for _, ns := range options.chainNodes {
		node, err := gost.ParseNode(ns)
		if err != nil {
			return nil, err
		}

		var tr gost.Transporter
		switch node.Transport {
		case "tls":
			tr = gost.TLSTransporter()
		case "ws":
			tr = gost.WSTransporter(nil)
		case "wss":
			tr = gost.WSSTransporter(nil)
		case "kcp":
			if !chain.IsEmpty() {
				log.Log("KCP must be the first node in the proxy chain")
				return nil, err
			}
			tr = gost.KCPTransporter(nil)
		case "ssh":
			if node.Protocol == "direct" || node.Protocol == "remote" {
				tr = gost.SSHForwardTransporter()
			} else {
				tr = gost.SSHTunnelTransporter()
			}
		case "quic":
			if !chain.IsEmpty() {
				log.Log("QUIC must be the first node in the proxy chain")
				return nil, err
			}
			tr = gost.QUICTransporter(nil)
		case "http2":
			tr = gost.HTTP2Transporter(nil)
		case "h2":
			tr = gost.H2Transporter(nil)
		case "h2c":
			tr = gost.H2CTransporter()
		default:
			tr = gost.TCPTransporter()
		}

		var connector gost.Connector
		switch node.Protocol {
		case "http2":
			connector = gost.HTTP2Connector(nil)
		case "socks", "socks5":
			connector = gost.SOCKS5Connector(nil)
		case "socks4":
			connector = gost.SOCKS4Connector()
		case "socks4a":
			connector = gost.SOCKS4AConnector()
		case "ss":
			connector = gost.ShadowConnector(nil)
		case "http":
			fallthrough
		default:
			node.Protocol = "http" // default protocol is HTTP
			connector = gost.HTTPConnector(nil)
		}

		node.Client = &gost.Client{
			Connector:   connector,
			Transporter: tr,
		}
		chain.AddNode(node)
	}

	return chain, nil
}

func loadConfigureFile(configureFile string) error {
	if configureFile == "" {
		return nil
	}
	content, err := ioutil.ReadFile(configureFile)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(content, &options); err != nil {
		return err
	}
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
