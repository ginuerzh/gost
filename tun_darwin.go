// +build darwin

package gost

import (
	"net"
	"os/exec"
	"strconv"

	"github.com/songgao/water"
)

func createTun(cfg TunConfig) (conn net.Conn, ipNet *net.IPNet, err error) {
	ip, ipNet, err := net.ParseCIDR(cfg.Addr)
	if err != nil {
		return
	}

	ifce, err := water.New(water.Config{
		DeviceType: water.TUN,
	})
	if err != nil {
		return
	}

	mtu := cfg.MTU
	if mtu <= 0 {
		mtu = DefaultMTU
	}

	if err = exec.Command(
		"ifconfig", ifce.Name(),
		"inet", cfg.Addr,
		"mtu", strconv.Itoa(mtu),
		"up").Run(); err != nil {
		return
	}

	conn = &tunConn{
		ifce: ifce,
		addr: &net.IPAddr{IP: ip},
	}
	return
}
