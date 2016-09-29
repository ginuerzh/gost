// main
package main

import (
	"flag"
	"fmt"
	"github.com/golang/glog"
	"golang.org/x/net/http2"
	"os"
	"runtime"
	"sync"
)

const (
	LFATAL = iota
	LERROR
	LWARNING
	LINFO
	LDEBUG
	LVDEBUG // verbose debug
)

const (
	Version = "2.2-dev-http2"
)

var (
	listenAddr, forwardAddr strSlice
	pv                      bool // print version

	listenArgs  []Args
	forwardArgs []Args
)

func init() {
	flag.Var(&listenAddr, "L", "listen address, can listen on multiple ports")
	flag.Var(&forwardAddr, "F", "forward address, can make a forward chain")
	flag.BoolVar(&pv, "V", false, "print version")
	flag.Parse()

	if glog.V(LVDEBUG) {
		http2.VerboseLogs = true
	}
}

func main() {
	defer glog.Flush()

	if flag.NFlag() == 0 {
		flag.PrintDefaults()
		return
	}
	if pv {
		fmt.Fprintf(os.Stderr, "gost %s (%s)\n", Version, runtime.Version())
		return
	}

	listenArgs = parseArgs(listenAddr)
	if len(listenArgs) == 0 {
		fmt.Fprintln(os.Stderr, "no listen address, please specify at least one -L parameter")
		return
	}

	forwardArgs = parseArgs(forwardAddr)
	processForwardChain(forwardArgs...)

	var wg sync.WaitGroup
	for _, args := range listenArgs {
		wg.Add(1)
		go func(arg Args) {
			defer wg.Done()
			glog.V(LERROR).Infoln(listenAndServe(arg))
		}(args)
	}
	wg.Wait()
}
