// +build !windows

package gost

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/go-log/log"
	"gopkg.in/xtaci/kcp-go.v4"
)

func kcpSigHandler() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGUSR1)

	for {
		switch <-ch {
		case syscall.SIGUSR1:
			log.Logf("[kcp] SNMP: %+v", kcp.DefaultSnmp.Copy())
		}
	}
}
