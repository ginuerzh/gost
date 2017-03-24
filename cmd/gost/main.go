package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"runtime"
	"sync"

	"github.com/ginuerzh/gost"
	"github.com/golang/glog"
	"golang.org/x/net/http2"
)

var (
	options struct {
		ChainNodes, ServeNodes flagStringList
	}
)

func init() {
	var (
		configureFile string
		printVersion  bool
	)

	flag.StringVar(&configureFile, "C", "", "configure file")
	flag.Var(&options.ChainNodes, "F", "forward address, can make a forward chain")
	flag.Var(&options.ServeNodes, "L", "listen address, can listen on multiple ports")
	flag.BoolVar(&printVersion, "V", false, "print version")
	flag.Parse()

	if err := loadConfigureFile(configureFile); err != nil {
		glog.Fatal(err)
	}

	if glog.V(5) {
		http2.VerboseLogs = true
	}

	if flag.NFlag() == 0 {
		flag.PrintDefaults()
		return
	}

	if printVersion {
		fmt.Fprintf(os.Stderr, "gost %s (%s)\n", gost.Version, runtime.Version())
		return
	}
}

func main() {
	chain := gost.NewProxyChain()
	if err := chain.AddProxyNodeString(options.ChainNodes...); err != nil {
		glog.Fatal(err)
	}
	chain.Init()

	var wg sync.WaitGroup
	for _, ns := range options.ServeNodes {
		serverNode, err := gost.ParseProxyNode(ns)
		if err != nil {
			glog.Fatal(err)
		}

		wg.Add(1)
		go func(node gost.ProxyNode) {
			defer wg.Done()
			server := gost.NewProxyServer(node, chain)
			glog.Fatal(server.Serve())
		}(serverNode)
	}
	wg.Wait()
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

type flagStringList []string

func (this *flagStringList) String() string {
	return fmt.Sprintf("%s", *this)
}
func (this *flagStringList) Set(value string) error {
	*this = append(*this, value)
	return nil
}
