package tenus

import (
	"fmt"
	"net"

	"github.com/docker/libcontainer/netlink"
)

// VlanOptions allows you to specify options for vlan link.
type VlanOptions struct {
	// Name of the vlan device
	Dev string
	// VLAN tag id
	Id uint16
	// MAC address
	MacAddr string
}

// Vlaner is interface which embeds Linker interface and adds few more functions.
type Vlaner interface {
	// Linker interface
	Linker
	// MasterNetInterface returns vlan master network interface
	MasterNetInterface() *net.Interface
	// Id returns VLAN tag
	Id() uint16
}

// VlanLink is a Link which has a master network device.
// Each VlanLink has a VLAN tag id
type VlanLink struct {
	Link
	// Master device logical network interface
	masterIfc *net.Interface
	// VLAN tag
	id uint16
}

// NewVlanLink creates vlan network link.
//
// It is equivalent of running:
//		ip link add name vlan${RANDOM STRING} link ${master interface name} type vlan id ${tag}
// NewVlanLink returns Vlaner which is initialized to a pointer of type VlanLink if the
// vlan link was successfully created on the Linux host. Newly created link is assigned
// a random name starting with "vlan". It returns error if the link can not be created.
func NewVlanLink(masterDev string, id uint16) (Vlaner, error) {
	vlanDev := makeNetInterfaceName("vlan")

	if ok, err := NetInterfaceNameValid(masterDev); !ok {
		return nil, err
	}

	if _, err := net.InterfaceByName(masterDev); err != nil {
		return nil, fmt.Errorf("Master VLAN device %s does not exist on the host", masterDev)
	}

	if id <= 0 {
		return nil, fmt.Errorf("VLAN id must be a postive Integer: %d", id)
	}

	if err := netlink.NetworkLinkAddVlan(masterDev, vlanDev, id); err != nil {
		return nil, err
	}

	vlanIfc, err := net.InterfaceByName(vlanDev)
	if err != nil {
		return nil, fmt.Errorf("Could not find the new interface: %s", err)
	}

	masterIfc, err := net.InterfaceByName(masterDev)
	if err != nil {
		return nil, fmt.Errorf("Could not find the new interface: %s", err)
	}

	return &VlanLink{
		Link: Link{
			ifc: vlanIfc,
		},
		masterIfc: masterIfc,
		id:        id,
	}, nil
}

// NewVlanLinkWithOptions creates vlan network link and sets some of its network parameters
// to values passed in as VlanOptions
//
// It is equivalent of running:
//		ip link add name ${vlan name} link ${master interface} address ${macaddress} type vlan id ${tag}
// NewVlanLinkWithOptions returns Vlaner which is initialized to a pointer of type VlanLink if the
// vlan link was created successfully on the Linux host. It accepts VlanOptions which allow you to set
// link's options. It returns error if the link could not be created.
func NewVlanLinkWithOptions(masterDev string, opts VlanOptions) (Vlaner, error) {
	if ok, err := NetInterfaceNameValid(masterDev); !ok {
		return nil, err
	}

	if _, err := net.InterfaceByName(masterDev); err != nil {
		return nil, fmt.Errorf("Master VLAN device %s does not exist on the host", masterDev)
	}

	if err := validateVlanOptions(&opts); err != nil {
		return nil, err
	}

	if err := netlink.NetworkLinkAddVlan(masterDev, opts.Dev, opts.Id); err != nil {
		return nil, err
	}

	vlanIfc, err := net.InterfaceByName(opts.Dev)
	if err != nil {
		return nil, fmt.Errorf("Could not find the new interface: %s", err)
	}

	if opts.MacAddr != "" {
		if err := netlink.NetworkSetMacAddress(vlanIfc, opts.MacAddr); err != nil {
			if errDel := DeleteLink(vlanIfc.Name); errDel != nil {
				return nil, fmt.Errorf("Incorrect options specified. Attempt to delete the link failed: %s",
					errDel)
			}
		}
	}

	masterIfc, err := net.InterfaceByName(masterDev)
	if err != nil {
		return nil, fmt.Errorf("Could not find the new interface: %s", err)
	}

	return &VlanLink{
		Link: Link{
			ifc: vlanIfc,
		},
		masterIfc: masterIfc,
		id:        opts.Id,
	}, nil
}

// NetInterface returns vlan link's network interface
func (vln *VlanLink) NetInterface() *net.Interface {
	return vln.ifc
}

// MasterNetInterface returns vlan link's master network interface
func (vln *VlanLink) MasterNetInterface() *net.Interface {
	return vln.masterIfc
}

// Id returns vlan link's vlan tag id
func (vln *VlanLink) Id() uint16 {
	return vln.id
}

func validateVlanOptions(opts *VlanOptions) error {
	if opts.Dev != "" {
		if ok, err := NetInterfaceNameValid(opts.Dev); !ok {
			return err
		}

		if _, err := net.InterfaceByName(opts.Dev); err == nil {
			return fmt.Errorf("VLAN device %s already assigned on the host", opts.Dev)
		}
	} else {
		opts.Dev = makeNetInterfaceName("vlan")
	}

	if opts.Id <= 0 {
		return fmt.Errorf("Incorrect VLAN tag specified: %d", opts.Id)
	}

	if _, err := net.ParseMAC(opts.MacAddr); err != nil {
		return fmt.Errorf("Incorrect MacAddress specified: %s", opts.MacAddr)
	}

	return nil
}
