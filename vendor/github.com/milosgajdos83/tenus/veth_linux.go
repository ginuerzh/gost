package tenus

import (
	"fmt"
	"net"
	"os"
	"syscall"

	"github.com/docker/libcontainer/netlink"
	"github.com/docker/libcontainer/system"
)

// VethOptions allows you to specify options for veth link.
type VethOptions struct {
	// Veth pair's peer interface name
	PeerName string
	// TX queue length
	TxQueueLen int
}

// Vether embeds Linker interface and adds few more functions mostly to handle peer link interface
type Vether interface {
	// Linker interface
	Linker
	// PeerNetInterface returns peer network interface
	PeerNetInterface() *net.Interface
	// SetPeerLinkUp sets peer link up - which also brings up the other peer in VethPair
	SetPeerLinkUp() error
	// DeletePeerLink deletes peer link - this also deletes the other peer in VethPair
	DeletePeerLink() error
	// SetPeerLinkIp configures peer link's IP address
	SetPeerLinkIp(net.IP, *net.IPNet) error
	// SetPeerLinkNsToDocker sends peer link into Docker
	SetPeerLinkNsToDocker(string, string) error
	// SetPeerLinkNsPid sends peer link into container specified by PID
	SetPeerLinkNsPid(int) error
	// SetPeerLinkNsFd sends peer link into container specified by path
	SetPeerLinkNsFd(string) error
	// SetPeerLinkNetInNs configures peer link's IP network in network namespace specified by PID
	SetPeerLinkNetInNs(int, net.IP, *net.IPNet, *net.IP) error
}

// VethPair is a Link. Veth links are created in pairs called peers.
type VethPair struct {
	Link
	// Peer network interface
	peerIfc *net.Interface
}

// NewVethPair creates a pair of veth network links.
//
// It is equivalent of running:
// 		ip link add name veth${RANDOM STRING} type veth peer name veth${RANDOM STRING}.
// NewVethPair returns Vether which is initialized to a pointer of type VethPair if the
// veth link was successfully created on Linux host. Newly created pair of veth links
// are assigned random names starting with "veth".
// NewVethPair returns error if the veth pair could not be created.
func NewVethPair() (Vether, error) {
	ifcName := makeNetInterfaceName("veth")
	peerName := makeNetInterfaceName("veth")

	if err := netlink.NetworkCreateVethPair(ifcName, peerName, 0); err != nil {
		return nil, err
	}

	newIfc, err := net.InterfaceByName(ifcName)
	if err != nil {
		return nil, fmt.Errorf("Could not find the new interface: %s", err)
	}

	peerIfc, err := net.InterfaceByName(peerName)
	if err != nil {
		return nil, fmt.Errorf("Could not find the new interface: %s", err)
	}

	return &VethPair{
		Link: Link{
			ifc: newIfc,
		},
		peerIfc: peerIfc,
	}, nil
}

// NewVethPairWithOptions creates a pair of veth network links.
//
// It is equivalent of running:
// 		ip link add name ${first device name} type veth peer name ${second device name}
// NewVethPairWithOptions returns Vether which is initialized to a pointer of type VethPair if the
// veth link was successfully created on the Linux host. It accepts VethOptions which allow you to set
// peer interface name. It returns error if the veth pair could not be created.
func NewVethPairWithOptions(ifcName string, opts VethOptions) (Vether, error) {
	peerName := opts.PeerName
	txQLen := opts.TxQueueLen

	if ok, err := NetInterfaceNameValid(ifcName); !ok {
		return nil, err
	}

	if _, err := net.InterfaceByName(ifcName); err == nil {
		return nil, fmt.Errorf("Interface name %s already assigned on the host", ifcName)
	}

	if peerName != "" {
		if ok, err := NetInterfaceNameValid(peerName); !ok {
			return nil, err
		}

		if _, err := net.InterfaceByName(peerName); err == nil {
			return nil, fmt.Errorf("Interface name %s already assigned on the host", peerName)
		}
	} else {
		peerName = makeNetInterfaceName("veth")
	}

	if txQLen < 0 {
		return nil, fmt.Errorf("TX queue length must be a positive integer: %d", txQLen)
	}

	if err := netlink.NetworkCreateVethPair(ifcName, peerName, txQLen); err != nil {
		return nil, err
	}

	newIfc, err := net.InterfaceByName(ifcName)
	if err != nil {
		return nil, fmt.Errorf("Could not find the new interface: %s", err)
	}

	peerIfc, err := net.InterfaceByName(peerName)
	if err != nil {
		return nil, fmt.Errorf("Could not find the new interface: %s", err)
	}

	return &VethPair{
		Link: Link{
			ifc: newIfc,
		},
		peerIfc: peerIfc,
	}, nil
}

// NetInterface returns veth link's primary network interface
func (veth *VethPair) NetInterface() *net.Interface {
	return veth.ifc
}

// NetInterface returns veth link's peer network interface
func (veth *VethPair) PeerNetInterface() *net.Interface {
	return veth.peerIfc
}

// SetPeerLinkUp sets peer link up
func (veth *VethPair) SetPeerLinkUp() error {
	return netlink.NetworkLinkUp(veth.peerIfc)
}

// DeletePeerLink deletes peer link. It also deletes the other peer interface in VethPair
func (veth *VethPair) DeletePeerLink() error {
	return netlink.NetworkLinkDel(veth.peerIfc.Name)
}

// SetPeerLinkIp configures peer link's IP address
func (veth *VethPair) SetPeerLinkIp(ip net.IP, nw *net.IPNet) error {
	return netlink.NetworkLinkAddIp(veth.peerIfc, ip, nw)
}

// SetPeerLinkNsToDocker sends peer link into Docker
func (veth *VethPair) SetPeerLinkNsToDocker(name string, dockerHost string) error {
	pid, err := DockerPidByName(name, dockerHost)
	if err != nil {
		return fmt.Errorf("Failed to find docker %s :  %s", name, err)
	}

	return netlink.NetworkSetNsPid(veth.peerIfc, pid)
}

// SetPeerLinkNsPid sends peer link into container specified by PID
func (veth *VethPair) SetPeerLinkNsPid(nspid int) error {
	return netlink.NetworkSetNsPid(veth.peerIfc, nspid)
}

// SetPeerLinkNsFd sends peer link into container specified by path
func (veth *VethPair) SetPeerLinkNsFd(nspath string) error {
	fd, err := syscall.Open(nspath, syscall.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("Could not attach to Network namespace: %s", err)
	}

	return netlink.NetworkSetNsFd(veth.peerIfc, fd)
}

// SetPeerLinkNetInNs configures peer link's IP network in network namespace specified by PID
func (veth *VethPair) SetPeerLinkNetInNs(nspid int, ip net.IP, network *net.IPNet, gw *net.IP) error {
	origNs, _ := NetNsHandle(os.Getpid())
	defer syscall.Close(int(origNs))
	defer system.Setns(origNs, syscall.CLONE_NEWNET)

	if err := SetNetNsToPid(nspid); err != nil {
		return fmt.Errorf("Setting network namespace failed: %s", err)
	}

	if err := netlink.NetworkLinkAddIp(veth.peerIfc, ip, network); err != nil {
		return fmt.Errorf("Unable to set IP: %s in pid: %d network namespace", ip.String(), nspid)
	}

	if err := netlink.NetworkLinkUp(veth.peerIfc); err != nil {
		return fmt.Errorf("Unable to bring %s interface UP: %s", veth.peerIfc.Name, nspid)
	}

	if gw != nil {
		if err := netlink.AddDefaultGw(gw.String(), veth.peerIfc.Name); err != nil {
			return fmt.Errorf("Unable to set Default gateway: %s in pid: %d network namespace", gw.String(), nspid)
		}
	}

	return nil
}
