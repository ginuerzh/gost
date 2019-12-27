// +build windows

package gost

import (
	"errors"
	"net"
)

//TODO: wintun for Windows: https://www.wintun.net/
// https://godoc.org/golang.zx2c4.com/wireguard/tun/wintun
func createTun(cfg TunConfig) (conn net.Conn, ipNet *net.IPNet, err error) {
	err = errors.New("tun is not supported on Windows")
	return
}
