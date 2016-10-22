package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"github.com/ginuerzh/gost"
	"github.com/golang/glog"
	"golang.org/x/net/http2"
	"os"
	"runtime"
	"sync"
)

var (
	chainNodes  stringlist
	serverNodes stringlist
	pv          bool
)

func init() {
	flag.Var(&serverNodes, "L", "listen address, can listen on multiple ports")
	flag.Var(&chainNodes, "F", "forward address, can make a forward chain")
	flag.BoolVar(&pv, "V", false, "print version")
	flag.Parse()

	if glog.V(5) {
		http2.VerboseLogs = true
	}
}

func main() {
	if flag.NFlag() == 0 {
		flag.PrintDefaults()
		return
	}
	if pv {
		fmt.Fprintf(os.Stderr, "gost %s (%s)\n", gost.Version, runtime.Version())
		return
	}

	chain := gost.NewProxyChain()
	if err := chain.AddProxyNodeString(chainNodes...); err != nil {
		glog.Fatal(err)
	}
	chain.Init()

	var wg sync.WaitGroup
	for _, ns := range serverNodes {
		serverNode, err := gost.ParseProxyNode(ns)
		if err != nil {
			glog.Fatal(err)
		}

		wg.Add(1)
		go func(node gost.ProxyNode) {
			defer wg.Done()
			certFile, keyFile := node.Get("cert"), node.Get("key")
			if certFile == "" {
				certFile = gost.DefaultCertFile
			}
			if keyFile == "" {
				keyFile = gost.DefaultKeyFile
			}
			cert, err := gost.LoadCertificate(certFile, keyFile)
			if err != nil {
				glog.Fatal(err)
			}
			server := gost.NewProxyServer(node, chain, &tls.Config{Certificates: []tls.Certificate{cert}})
			glog.Fatal(server.Serve())
		}(serverNode)
	}
	wg.Wait()
}

type stringlist []string

func (list *stringlist) String() string {
	return fmt.Sprintf("%s", *list)
}
func (list *stringlist) Set(value string) error {
	*list = append(*list, value)
	return nil
}
