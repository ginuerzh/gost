package tenus

import (
	"fmt"
	"net"
	"os"
	"syscall"

	"github.com/docker/libcontainer/netlink"
	"github.com/docker/libcontainer/system"
)

// LinkOptions allows you to specify network link options.
type LinkOptions struct {
	// MAC address
	MacAddr string
	// Maximum Transmission Unit
	MTU int
	// Link network flags i.e. FlagUp, FlagLoopback, FlagMulticast
	Flags net.Flags
	// Network namespace in which the network link should be created
	Ns int
}

// Linker is a generic Linux network link
type Linker interface {
	// NetInterface returns the link's logical network interface
	NetInterface() *net.Interface
	// DeleteLink deletes the link from Linux host
	DeleteLink() error
	// SetLinkMTU sets the link's MTU.
	SetLinkMTU(int) error
	// SetLinkMacAddress sets the link's MAC address.
	SetLinkMacAddress(string) error
	// SetLinkUp brings the link up
	SetLinkUp() error
	// SetLinkDown brings the link down
	SetLinkDown() error
	// SetLinkIp configures the link's IP address
	SetLinkIp(net.IP, *net.IPNet) error
	// UnsetLinkIp remove and IP address from the link
	UnsetLinkIp(net.IP, *net.IPNet) error
	// SetLinkDefaultGw configures the link's default gateway
	SetLinkDefaultGw(*net.IP) error
	// SetLinkNetNsPid moves the link to network namespace specified by PID
	SetLinkNetNsPid(int) error
	// SetLinkNetInNs configures network settings of the link in network namespace
	SetLinkNetInNs(int, net.IP, *net.IPNet, *net.IP) error
}

// Link has a logical network interface
type Link struct {
	ifc *net.Interface
}

// NewLink creates new network link on Linux host.
//
// It is equivalent of running: ip link add name ${ifcName} type dummy
// NewLink returns Linker which is initialized to a pointer of type Link if the
// link was created successfully on the Linux host.
// It returns error if the network link could not be created on Linux host.
func NewLink(ifcName string) (Linker, error) {
	if ok, err := NetInterfaceNameValid(ifcName); !ok {
		return nil, err
	}

	if _, err := net.InterfaceByName(ifcName); err == nil {
		return nil, fmt.Errorf("Interface name %s already assigned on the host", ifcName)
	}

	if err := netlink.NetworkLinkAdd(ifcName, "dummy"); err != nil {
		return nil, fmt.Errorf("Could not create new link %s: %s", ifcName, err)
	}

	newIfc, err := net.InterfaceByName(ifcName)
	if err != nil {
		return nil, fmt.Errorf("Could not find the new interface: %s", err)
	}

	return &Link{
		ifc: newIfc,
	}, nil
}

// NewLinkFrom creates new tenus link on Linux host from an existing interface of given name
func NewLinkFrom(ifcName string) (Linker, error) {
	if ok, err := NetInterfaceNameValid(ifcName); !ok {
		return nil, err
	}

	newIfc, err := net.InterfaceByName(ifcName)
	if err != nil {
		return nil, fmt.Errorf("Could not find the new interface: %s", err)
	}

	return &Link{
		ifc: newIfc,
	}, nil
}

// NewLinkWithOptions creates new network link on Linux host and sets some of its network
// parameters passed in as LinkOptions
//
// Calling NewLinkWithOptions is equivalent of running following commands one after another if
// particular option is passed in as a parameter:
// 		ip link add name ${ifcName} type dummy
// 		ip link set dev ${ifcName} address ${MAC address}
//		ip link set dev ${ifcName} mtu ${MTU value}
//		ip link set dev ${ifcName} up
// NewLinkWithOptions returns Linker which is initialized to a pointer of type Link if the network
// link with given LinkOptions was created successfully on the Linux host.
// It attempts to delete the link if any of the LinkOptions are incorrect or if setting the options
// failed and returns error.
func NewLinkWithOptions(ifcName string, opts LinkOptions) (Linker, error) {
	if ok, err := NetInterfaceNameValid(ifcName); !ok {
		return nil, err
	}

	if _, err := net.InterfaceByName(ifcName); err == nil {
		return nil, fmt.Errorf("Interface name %s already assigned on the host", ifcName)
	}

	if err := netlink.NetworkLinkAdd(ifcName, "dummy"); err != nil {
		return nil, fmt.Errorf("Could not create new link %s: %s", ifcName, err)
	}

	newIfc, err := net.InterfaceByName(ifcName)
	if err != nil {
		return nil, fmt.Errorf("Could not find the new interface: %s", err)
	}

	if (opts != LinkOptions{}) {
		errOpts := setLinkOptions(newIfc, opts)
		if errOpts != nil {
			if errDel := DeleteLink(newIfc.Name); err != nil {
				return nil, fmt.Errorf("Incorrect options specified: %s. Attempt to delete the link failed: %s",
					errOpts, errDel)
			}
			return nil, fmt.Errorf("Could not set link options: %s", errOpts)
		}
	}

	return &Link{
		ifc: newIfc,
	}, nil
}

// DeleteLink deletes netowrk link from Linux Host
// It is equivalent of running: ip link delete dev ${name}
func DeleteLink(name string) error {
	return netlink.NetworkLinkDel(name)
}

// NetInterface returns link's logical network interface.
func (l *Link) NetInterface() *net.Interface {
	return l.ifc
}

// DeleteLink deletes link interface on Linux host.
// It is equivalent of running: ip link delete dev ${interface name}
func (l *Link) DeleteLink() error {
	return netlink.NetworkLinkDel(l.NetInterface().Name)
}

// SetLinkMTU sets link's MTU.
// It is equivalent of running: ip link set dev ${interface name} mtu ${MTU value}
func (l *Link) SetLinkMTU(mtu int) error {
	return netlink.NetworkSetMTU(l.NetInterface(), mtu)
}

// SetLinkMacAddress sets link's MAC address.
// It is equivalent of running: ip link set dev ${interface name} address ${address}
func (l *Link) SetLinkMacAddress(macaddr string) error {
	return netlink.NetworkSetMacAddress(l.NetInterface(), macaddr)
}

// SetLinkUp brings the link up.
// It is equivalent of running: ip link set dev ${interface name} up
func (l *Link) SetLinkUp() error {
	return netlink.NetworkLinkUp(l.NetInterface())
}

// SetLinkDown brings the link down.
// It is equivalent of running: ip link set dev ${interface name} down
func (l *Link) SetLinkDown() error {
	return netlink.NetworkLinkDown(l.NetInterface())
}

// SetLinkIp configures the link's IP address.
// It is equivalent of running: ip address add ${address}/${mask} dev ${interface name}
func (l *Link) SetLinkIp(ip net.IP, network *net.IPNet) error {
	return netlink.NetworkLinkAddIp(l.NetInterface(), ip, network)
}

// UnsetLinkIp configures the link's IP address.
// It is equivalent of running: ip address del ${address}/${mask} dev ${interface name}
func (l *Link) UnsetLinkIp(ip net.IP, network *net.IPNet) error {
	return netlink.NetworkLinkDelIp(l.NetInterface(), ip, network)
}

// SetLinkDefaultGw configures the link's default Gateway.
// It is equivalent of running: ip route add default via ${ip address}
func (l *Link) SetLinkDefaultGw(gw *net.IP) error {
	return netlink.AddDefaultGw(gw.String(), l.NetInterface().Name)
}

// SetLinkNetNsPid moves the link to Network namespace specified by PID.
func (l *Link) SetLinkNetNsPid(nspid int) error {
	return netlink.NetworkSetNsPid(l.NetInterface(), nspid)
}

// SetLinkNetInNs configures network settings of the link in network namespace specified by PID.
func (l *Link) SetLinkNetInNs(nspid int, ip net.IP, network *net.IPNet, gw *net.IP) error {
	origNs, _ := NetNsHandle(os.Getpid())
	defer syscall.Close(int(origNs))
	defer system.Setns(origNs, syscall.CLONE_NEWNET)

	if err := SetNetNsToPid(nspid); err != nil {
		return fmt.Errorf("Setting network namespace failed: %s", err)
	}

	if err := netlink.NetworkLinkAddIp(l.NetInterface(), ip, network); err != nil {
		return fmt.Errorf("Unable to set IP: %s in pid: %d network namespace", ip.String(), nspid)
	}

	if err := netlink.NetworkLinkUp(l.ifc); err != nil {
		return fmt.Errorf("Unable to bring %s interface UP: %s", l.ifc.Name, nspid)
	}

	if gw != nil {
		if err := netlink.AddDefaultGw(gw.String(), l.NetInterface().Name); err != nil {
			return fmt.Errorf("Unable to set Default gateway: %s in pid: %d network namespace", gw.String(), nspid)
		}
	}

	return nil
}

// SetLinkNsFd sets the link's Linux namespace to the one specified by filesystem path.
func (l *Link) SetLinkNsFd(nspath string) error {
	fd, err := syscall.Open(nspath, syscall.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("Could not attach to Network namespace: %s", err)
	}

	return netlink.NetworkSetNsFd(l.NetInterface(), fd)
}

// SetLinkNsToDocker sets the link's Linux namespace to a running Docker one specified by Docker name.
func (l *Link) SetLinkNsToDocker(name string, dockerHost string) error {
	pid, err := DockerPidByName(name, dockerHost)
	if err != nil {
		return fmt.Errorf("Failed to find docker %s :  %s", name, err)
	}

	return l.SetLinkNetNsPid(pid)
}

// RenameInterfaceByName renames an interface of given name.
func RenameInterfaceByName(old string, newName string) error {
	iface, err := net.InterfaceByName(old)
	if err != nil {
		return err
	}
	return netlink.NetworkChangeName(iface, newName)
}

// setLinkOptions validates and sets link's various options passed in as LinkOptions.
func setLinkOptions(ifc *net.Interface, opts LinkOptions) error {
	macaddr, mtu, flags, ns := opts.MacAddr, opts.MTU, opts.Flags, opts.Ns

	// if MTU is passed in LinkOptions
	if mtu != 0 {
		if err := validMtu(mtu); err != nil {
			return err
		}

		if err := netlink.NetworkSetMTU(ifc, mtu); err != nil {
			return fmt.Errorf("Unable to set MTU: %s", err)
		}
	}

	// if MacAddress is passed in LinkOptions
	if macaddr != "" {
		if err := validMacAddress(macaddr); err != nil {
			return err
		}

		if err := netlink.NetworkSetMacAddress(ifc, macaddr); err != nil {
			return fmt.Errorf("Unable to set MAC Address: %s", err)
		}
	}

	// if ns is passed in LinkOptions
	if ns != 0 {
		if err := validNs(ns); err != nil {
			return err
		}

		if err := netlink.NetworkSetNsPid(ifc, ns); err != nil {
			return fmt.Errorf("Unable to set Network namespace: %s", err)
		}
	}

	// if flags is passed in LinkOptions
	if flags != 0 {
		if err := validFlags(flags); err != nil {
			return err
		}

		if ns != 0 && (ns != 1 || ns != os.Getpid()) {
			if (flags & syscall.IFF_UP) == syscall.IFF_UP {
				origNs, _ := NetNsHandle(os.Getpid())
				defer syscall.Close(int(origNs))
				defer system.Setns(origNs, syscall.CLONE_NEWNET)

				if err := SetNetNsToPid(ns); err != nil {
					return fmt.Errorf("Switching to %d network namespace failed: %s", ns, err)
				}

				if err := netlink.NetworkLinkUp(ifc); err != nil {
					return fmt.Errorf("Unable to bring %s interface UP: %s", ifc.Name, ns)
				}
			}
		} else {
			if err := netlink.NetworkLinkUp(ifc); err != nil {
				return fmt.Errorf("Could not bring up network link %s: %s", ifc.Name, err)
			}
		}
	}

	return nil
}
