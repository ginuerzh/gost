package tenus

import (
	"github.com/docker/libcontainer/netlink"
)

type NetworkOptions struct {
	IpAddr string
	Gw     string
	Routes []netlink.Route
}
