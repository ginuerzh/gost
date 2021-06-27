package gost

import (
	"fmt"
	"net"
	"os/exec"
	"strings"

	"github.com/go-log/log"
	"github.com/songgao/water"
)

func createTun(cfg TunConfig) (conn net.Conn, itf *net.Interface, err error) {
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

	cmd := fmt.Sprintf("netsh interface ip set address name=\"%s\" "+
		"source=static addr=%s mask=%s gateway=none",
		ifce.Name(), ip.String(), ipMask(ipNet.Mask))
	log.Log("[tun]", cmd)
	args := strings.Split(cmd, " ")
	if er := exec.Command(args[0], args[1:]...).Run(); er != nil {
		err = fmt.Errorf("%s: %v", cmd, er)
		return
	}

	if err = addTunRoutes(ifce.Name(), cfg.Gateway, cfg.Routes...); err != nil {
		return
	}

	itf, err = net.InterfaceByName(ifce.Name())
	if err != nil {
		return
	}

	conn = &tunTapConn{
		ifce: ifce,
		addr: &net.IPAddr{IP: ip},
	}
	return
}

func createTap(cfg TapConfig) (conn net.Conn, itf *net.Interface, err error) {
	ip, ipNet, _ := net.ParseCIDR(cfg.Addr)

	ifce, err := water.New(water.Config{
		DeviceType: water.TAP,
		PlatformSpecificParams: water.PlatformSpecificParams{
			ComponentID:   "tap0901",
			InterfaceName: cfg.Name,
			Network:       cfg.Addr,
		},
	})
	if err != nil {
		return
	}

	if ip != nil && ipNet != nil {
		cmd := fmt.Sprintf("netsh interface ip set address name=\"%s\" "+
			"source=static addr=%s mask=%s gateway=none",
			ifce.Name(), ip.String(), ipMask(ipNet.Mask))
		log.Log("[tap]", cmd)
		args := strings.Split(cmd, " ")
		if er := exec.Command(args[0], args[1:]...).Run(); er != nil {
			err = fmt.Errorf("%s: %v", cmd, er)
			return
		}
	}

	if err = addTapRoutes(ifce.Name(), cfg.Gateway, cfg.Routes...); err != nil {
		return
	}

	itf, err = net.InterfaceByName(ifce.Name())
	if err != nil {
		return
	}

	conn = &tunTapConn{
		ifce: ifce,
		addr: &net.IPAddr{IP: ip},
	}
	return
}

func addTunRoutes(ifName string, gw string, routes ...IPRoute) error {
	for _, route := range routes {
		if route.Dest == nil {
			continue
		}

		deleteRoute(ifName, route.Dest.String())

		cmd := fmt.Sprintf("netsh interface ip add route prefix=%s interface=\"%s\" store=active",
			route.Dest.String(), ifName)
		if gw != "" {
			cmd += " nexthop=" + gw
		}
		log.Logf("[tun] %s", cmd)
		args := strings.Split(cmd, " ")
		if er := exec.Command(args[0], args[1:]...).Run(); er != nil {
			return fmt.Errorf("%s: %v", cmd, er)
		}
	}
	return nil
}

func addTapRoutes(ifName string, gw string, routes ...string) error {
	for _, route := range routes {
		if route == "" {
			continue
		}

		deleteRoute(ifName, route)

		cmd := fmt.Sprintf("netsh interface ip add route prefix=%s interface=\"%s\" store=active",
			route, ifName)
		if gw != "" {
			cmd += " nexthop=" + gw
		}
		log.Logf("[tap] %s", cmd)
		args := strings.Split(cmd, " ")
		if er := exec.Command(args[0], args[1:]...).Run(); er != nil {
			return fmt.Errorf("%s: %v", cmd, er)
		}
	}
	return nil
}

func deleteRoute(ifName string, route string) error {
	cmd := fmt.Sprintf("netsh interface ip delete route prefix=%s interface=\"%s\" store=active",
		route, ifName)
	args := strings.Split(cmd, " ")
	return exec.Command(args[0], args[1:]...).Run()
}

func ipMask(mask net.IPMask) string {
	return fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])
}
