// +build !windows

package gost

import (
	"github.com/golang/glog"
	"gopkg.in/xtaci/kcp-go.v2"
	"os"
	"os/signal"
	"syscall"
)

func kcpSigHandler() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGUSR1)

	for {
		switch <-ch {
		case syscall.SIGUSR1:
			glog.V(LINFO).Infof("[kcp] SNMP: %+v", kcp.DefaultSnmp.Copy())
		}
	}
}
