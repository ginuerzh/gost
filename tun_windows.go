package gost

import (
	"fmt"
	"net"
	"os/exec"

	"github.com/go-log/log"
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
			ComponentID:   "tap0901",
			InterfaceName: cfg.Name,
			Network:       cfg.Addr,
		},
	})
	if err != nil {
		return
	}

	cmd := fmt.Sprintf("netsh interface ip set address name=%s "+
		"source=static addr=%s mask=%s gateway=none",
		ifce.Name(), ip.String(), ipMask(ipNet.Mask))
	log.Log("[tun]", cmd)
	if er := exec.Command("netsh",
		"interface", "ip", "set", "address",
		"name="+ifce.Name(), "source=static",
		"addr="+ip.String(), "mask="+ipMask(ipNet.Mask), "gateway=none").Run(); er != nil {
		err = fmt.Errorf("%s: %v", cmd, er)
		return
	}

	conn = &tunConn{
		ifce: ifce,
		addr: &net.IPAddr{IP: ip},
	}
	return
}

func ipMask(mask net.IPMask) string {
	return fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])
}
