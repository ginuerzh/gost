package gost

import (
	"fmt"
	"net"
	"os/exec"
	"strings"

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
	args := strings.Split(cmd, " ")
	if er := exec.Command(args[0], args[1:]...).Run(); er != nil {
		err = fmt.Errorf("%s: %v", cmd, er)
		return
	}

	if err = addRoutes(ip.String(), cfg.Routes...); err != nil {
		return
	}

	conn = &tunConn{
		ifce: ifce,
		addr: &net.IPAddr{IP: ip},
	}
	return
}

func addRoutes(ifIP string, routes ...string) error {
	for _, route := range routes {
		if route == "" {
			continue
		}
		_, inet, err := net.ParseCIDR(route)
		if err != nil {
			return err
		}

		cmd := fmt.Sprintf("route ADD %s MASK %s %s",
			inet.IP, ipMask(inet.Mask), ifIP)
		log.Log("[tun]", cmd)
		args := strings.Split(cmd, " ")
		if er := exec.Command(args[0], args[1:]...).Run(); er != nil {
			return fmt.Errorf("%s: %v", cmd, er)
		}
	}
	return nil
}

func ipMask(mask net.IPMask) string {
	return fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])
}
