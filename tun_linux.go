// +build linux

package gost

import (
	"net"

	"github.com/milosgajdos83/tenus"
	"github.com/songgao/water"
)

func createTun(cfg TunConfig) (conn net.Conn, ipNet *net.IPNet, err error) {
	ip, ipNet, err := net.ParseCIDR(cfg.Addr)
	if err != nil {
		return
	}

	ifce, err := water.New(water.Config{
		DeviceType: water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{
			Name: cfg.Name,
		},
	})
	if err != nil {
		return
	}

	link, err := tenus.NewLinkFrom(ifce.Name())
	if err != nil {
		return
	}

	mtu := cfg.MTU
	if mtu <= 0 {
		mtu = DefaultMTU
	}
	if err = link.SetLinkMTU(mtu); err != nil {
		return
	}
	if err = link.SetLinkIp(ip, ipNet); err != nil {
		return
	}
	if err = link.SetLinkUp(); err != nil {
		return
	}

	conn = &tunConn{
		ifce: ifce,
		addr: &net.IPAddr{IP: ip},
	}
	return
}
