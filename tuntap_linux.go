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
	ip, _, err := net.ParseCIDR(cfg.Addr)
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

	mtu := cfg.MTU
	if mtu <= 0 {
		mtu = DefaultMTU
	}

	if err = exeCmd(fmt.Sprintf("ip link set dev %s mtu %d", ifce.Name(), mtu)); err != nil {
		log.Log(err)
	}

	if err = exeCmd(fmt.Sprintf("ip address add %s dev %s", cfg.Addr, ifce.Name())); err != nil {
		log.Log(err)
	}

	if err = exeCmd(fmt.Sprintf("ip link set dev %s up", ifce.Name())); err != nil {
		log.Log(err)
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
	if cfg.Addr != "" {
		ip, _, err = net.ParseCIDR(cfg.Addr)
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

	mtu := cfg.MTU
	if mtu <= 0 {
		mtu = DefaultMTU
	}

	if err = exeCmd(fmt.Sprintf("ip link set dev %s mtu %d", ifce.Name(), mtu)); err != nil {
		log.Log(err)
	}

	if cfg.Addr != "" {
		if err = exeCmd(fmt.Sprintf("ip address add %s dev %s", cfg.Addr, ifce.Name())); err != nil {
			log.Log(err)
		}
	}

	if err = exeCmd(fmt.Sprintf("ip link set dev %s up", ifce.Name())); err != nil {
		log.Log(err)
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

		args := strings.Split(cmd, " ")
		if er := exec.Command(args[0], args[1:]...).Run(); er != nil {
			log.Logf("[tun] %s: %v", cmd, er)
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

		args := strings.Split(cmd, " ")
		if er := exec.Command(args[0], args[1:]...).Run(); er != nil {
			log.Logf("[tap] %s: %v", cmd, er)
		}
	}
	return nil
}

func exeCmd(cmd string) error {
	log.Log(cmd)

	args := strings.Split(cmd, " ")
	if err := exec.Command(args[0], args[1:]...).Run(); err != nil {
		return fmt.Errorf("%s: %v", cmd, err)
	}

	return nil
}
