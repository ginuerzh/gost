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
}

func main() {

}

func buildChain() (*gost.Chain, error) {
	chain := gost.NewChain()
	for _, cn := range options.chainNodes {
		node, err := parseNode(cn)
		if err != nil {
			return nil, err
		}

		var tr gost.Transporter
		switch node.Transport {
		case "tls":
			tr = gost.TLSTransporter()
		case "ws":
			tr = gost.WSTransporter(nil)
		}

		var connector gost.Connector
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
