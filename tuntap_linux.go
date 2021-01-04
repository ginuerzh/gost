package gost

import (
	"fmt"
	"net"

	"github.com/docker/libcontainer/netlink"
	"github.com/go-log/log"
	"github.com/milosgajdos/tenus"
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

	cmd := fmt.Sprintf("ip link set dev %s mtu %d", ifce.Name(), mtu)
	log.Log("[tun]", cmd)
	if er := link.SetLinkMTU(mtu); er != nil {
		err = fmt.Errorf("%s: %v", cmd, er)
		return
	}

	cmd = fmt.Sprintf("ip address add %s dev %s", cfg.Addr, ifce.Name())
	log.Log("[tun]", cmd)
	if er := link.SetLinkIp(ip, ipNet); er != nil {
		err = fmt.Errorf("%s: %v", cmd, er)
		return
	}

	cmd = fmt.Sprintf("ip link set dev %s up", ifce.Name())
	log.Log("[tun]", cmd)
	if er := link.SetLinkUp(); er != nil {
		err = fmt.Errorf("%s: %v", cmd, er)
		return
	}

	if err = addTunRoutes(ifce.Name(), cfg.Routes...); err != nil {
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
	var ip net.IP
	var ipNet *net.IPNet
	if cfg.Addr != "" {
		ip, ipNet, err = net.ParseCIDR(cfg.Addr)
		if err != nil {
			return
		}
	}

	ifce, err := water.New(water.Config{
		DeviceType: water.TAP,
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

	cmd := fmt.Sprintf("ip link set dev %s mtu %d", ifce.Name(), mtu)
	log.Log("[tap]", cmd)
	if er := link.SetLinkMTU(mtu); er != nil {
		err = fmt.Errorf("%s: %v", cmd, er)
		return
	}

	if cfg.Addr != "" {
		cmd = fmt.Sprintf("ip address add %s dev %s", cfg.Addr, ifce.Name())
		log.Log("[tap]", cmd)
		if er := link.SetLinkIp(ip, ipNet); er != nil {
			err = fmt.Errorf("%s: %v", cmd, er)
			return
		}
	}

	cmd = fmt.Sprintf("ip link set dev %s up", ifce.Name())
	log.Log("[tap]", cmd)
	if er := link.SetLinkUp(); er != nil {
		err = fmt.Errorf("%s: %v", cmd, er)
		return
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

func addTunRoutes(ifName string, routes ...IPRoute) error {
	for _, route := range routes {
		if route.Dest == nil {
			continue
		}
		cmd := fmt.Sprintf("ip route add %s dev %s", route.Dest.String(), ifName)
		log.Logf("[tun] %s", cmd)
		if err := netlink.AddRoute(route.Dest.String(), "", "", ifName); err != nil {
			return fmt.Errorf("%s: %v", cmd, err)
		}
	}
	return nil
}

func addTapRoutes(ifName string, gw string, routes ...string) error {
	for _, route := range routes {
		if route == "" {
			continue
		}
		cmd := fmt.Sprintf("ip route add %s via %s dev %s", route, gw, ifName)
		log.Logf("[tap] %s", cmd)
		if err := netlink.AddRoute(route, "", gw, ifName); err != nil {
			return fmt.Errorf("%s: %v", cmd, err)
		}
	}
	return nil
}
