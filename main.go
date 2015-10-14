// main
package main

import (
	"flag"
	"github.com/golang/glog"
	"sync"
)

const (
	LFATAL = iota
	LERROR
	LWARNING
	LINFO
	LDEBUG
)

var (
	listenAddr, forwardAddr strSlice
	pv                      bool // print version

	listenArgs  []Args
	forwardArgs []Args
)

func init() {
	flag.Var(&listenAddr, "L", "listen address")
	flag.Var(&forwardAddr, "F", "forward address, can make a forward chain")
	flag.BoolVar(&pv, "V", false, "print version")
	flag.Parse()
}

func main() {
	defer glog.Flush()

	if flag.NFlag() == 0 {
		flag.PrintDefaults()
		return
	}
	if pv {
		printVersion()
		return
	}

	listenArgs = parseArgs(listenAddr)
	forwardArgs = parseArgs(forwardAddr)

	if len(listenArgs) == 0 {
		glog.Fatalln("no listen addr")
	}

	var wg sync.WaitGroup
	for _, args := range listenArgs {
		wg.Add(1)
		go func(arg Args) {
			defer wg.Done()
			listenAndServe(arg)
		}(args)
	}
	wg.Wait()
}
