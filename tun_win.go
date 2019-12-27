// +build windows

package gost

import (
	"errors"
	"net"
)

func createTun(cfg TunConfig) (conn net.Conn, ipNet *net.IPNet, err error) {
	err = errors.New("tun is not supported on Windows")
	return
}
