package tenus

import (
	"fmt"
	"net"

	"github.com/docker/libcontainer/netlink"
)

// MacVtaper embeds MacVlaner interface
type MacVtaper interface {
	MacVlaner
}

// MacVtapLink is MacVlanLink. It implements MacVtaper interface
type MacVtapLink struct {
	*MacVlanLink
}

// NewMacVtapLink creates macvtap network link
//
// It is equivalent of running:
//		ip link add name mvt${RANDOM STRING} link ${master interface} type macvtap
// NewMacVtapLink returns MacVtaper which is initialized to a pointer of type MacVtapLink if the
// macvtap link was created successfully on the Linux host. Newly created link is assigned
// a random name starting with "mvt". It sets the macvlan mode to "bridge" which is a default.
// It returns error if the link could not be created.
func NewMacVtapLink(masterDev string) (MacVtaper, error) {
	macVtapDev := makeNetInterfaceName("mvt")

	if ok, err := NetInterfaceNameValid(masterDev); !ok {
		return nil, err
	}

	if _, err := net.InterfaceByName(masterDev); err != nil {
		return nil, fmt.Errorf("Master MAC VTAP device %s does not exist on the host", masterDev)
	}

	if err := netlink.NetworkLinkAddMacVtap(masterDev, macVtapDev, default_mode); err != nil {
		return nil, err
	}

	macVtapIfc, err := net.InterfaceByName(macVtapDev)
	if err != nil {
		return nil, fmt.Errorf("Could not find the new interface: %s", err)
	}

	masterIfc, err := net.InterfaceByName(masterDev)
	if err != nil {
		return nil, fmt.Errorf("Could not find the new interface: %s", err)
	}

	return &MacVtapLink{
		MacVlanLink: &MacVlanLink{
			Link: Link{
				ifc: macVtapIfc,
			},
			masterIfc: masterIfc,
			mode:      default_mode,
		},
	}, nil
}

// NewMacVtapLinkWithOptions creates macvtap network link and can set some of its network parameters
// passed in as MacVlanOptions.
//
// It is equivalent of running:
// 		ip link add name ${macvlan name} link ${master interface} address ${macaddress} type macvtap mode ${mode}
// NewMacVtapLinkWithOptions returns MacVtaper which is initialized to a pointer of type MacVtapLink if the
// macvtap link was created successfully on the Linux host. It returns error if the macvtap link could not be created.
func NewMacVtapLinkWithOptions(masterDev string, opts MacVlanOptions) (MacVtaper, error) {
	if ok, err := NetInterfaceNameValid(masterDev); !ok {
		return nil, err
	}

	if _, err := net.InterfaceByName(masterDev); err != nil {
		return nil, fmt.Errorf("Master MAC VLAN device %s does not exist on the host", masterDev)
	}

	if err := validateMacVlanOptions(&opts); err != nil {
		return nil, err
	}

	if err := netlink.NetworkLinkAddMacVtap(masterDev, opts.Dev, opts.Mode); err != nil {
		return nil, err
	}

	macVtapIfc, err := net.InterfaceByName(opts.Dev)
	if err != nil {
		return nil, fmt.Errorf("Could not find the new interface: %s", err)
	}

	if opts.MacAddr != "" {
		if err := netlink.NetworkSetMacAddress(macVtapIfc, opts.MacAddr); err != nil {
			if errDel := DeleteLink(macVtapIfc.Name); errDel != nil {
				return nil, fmt.Errorf("Incorrect options specified. Attempt to delete the link failed: %s",
					errDel)
			}
		}
	}

	masterIfc, err := net.InterfaceByName(masterDev)
	if err != nil {
		return nil, fmt.Errorf("Could not find the new interface: %s", err)
	}

	return &MacVtapLink{
		MacVlanLink: &MacVlanLink{
			Link: Link{
				ifc: macVtapIfc,
			},
			masterIfc: masterIfc,
			mode:      opts.Mode,
		},
	}, nil
}
