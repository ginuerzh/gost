package tenus

import (
	"fmt"
	"net"

	"github.com/docker/libcontainer/netlink"
)

// Default MacVlan mode
const (
	default_mode = "bridge"
)

// Supported macvlan modes by tenus package
var MacVlanModes = map[string]bool{
	"private": true,
	"vepa":    true,
	"bridge":  true,
}

// MacVlanOptions allows you to specify some options for macvlan link.
type MacVlanOptions struct {
	// macvlan device name
	Dev string
	// macvlan mode
	Mode string
	// MAC address
	MacAddr string
}

// MacVlaner embeds Linker interface and adds few more functions.
type MacVlaner interface {
	// Linker interface
	Linker
	// MasterNetInterface returns macvlan master network device
	MasterNetInterface() *net.Interface
	// Mode returns macvlan link's network mode
	Mode() string
}

// MacVlanLink is Link which has a master network device and operates in
// a given network mode. It implements MacVlaner interface.
type MacVlanLink struct {
	Link
	// Master device logical network interface
	masterIfc *net.Interface
	// macvlan operatio nmode
	mode string
}

// NewMacVlanLink creates macvlan network link
//
// It is equivalent of running:
//		ip link add name mc${RANDOM STRING} link ${master interface} type macvlan
// NewMacVlanLink returns MacVlaner which is initialized to a pointer of type MacVlanLink if the
// macvlan link was created successfully on the Linux host. Newly created link is assigned
// a random name starting with "mc". It sets the macvlan mode to "bridge" mode which is a default.
// It returns error if the link could not be created.
func NewMacVlanLink(masterDev string) (MacVlaner, error) {
	macVlanDev := makeNetInterfaceName("mc")

	if ok, err := NetInterfaceNameValid(masterDev); !ok {
		return nil, err
	}

	if _, err := net.InterfaceByName(masterDev); err != nil {
		return nil, fmt.Errorf("Master MAC VLAN device %s does not exist on the host", masterDev)
	}

	if err := netlink.NetworkLinkAddMacVlan(masterDev, macVlanDev, default_mode); err != nil {
		return nil, err
	}

	macVlanIfc, err := net.InterfaceByName(macVlanDev)
	if err != nil {
		return nil, fmt.Errorf("Could not find the new interface: %s", err)
	}

	masterIfc, err := net.InterfaceByName(masterDev)
	if err != nil {
		return nil, fmt.Errorf("Could not find the new interface: %s", err)
	}

	return &MacVlanLink{
		Link: Link{
			ifc: macVlanIfc,
		},
		masterIfc: masterIfc,
		mode:      default_mode,
	}, nil
}

// NewMacVlanLinkWithOptions creates macvlan network link and sets som of its network parameters
// passed in as MacVlanOptions.
//
// It is equivalent of running:
// 		ip link add name ${macvlan name} link ${master interface} address ${macaddress} type macvlan mode ${mode}
// NewMacVlanLinkWithOptions returns MacVlaner which is initialized to a pointer of type MacVlanLink if the
// macvlan link was created successfully on the Linux host. If particular option is empty, it sets default value if possible.
// It returns error if the macvlan link could not be created or if incorrect options have been passed.
func NewMacVlanLinkWithOptions(masterDev string, opts MacVlanOptions) (MacVlaner, error) {
	if ok, err := NetInterfaceNameValid(masterDev); !ok {
		return nil, err
	}

	if _, err := net.InterfaceByName(masterDev); err != nil {
		return nil, fmt.Errorf("Master MAC VLAN device %s does not exist on the host", masterDev)
	}

	if err := validateMacVlanOptions(&opts); err != nil {
		return nil, err
	}

	if err := netlink.NetworkLinkAddMacVlan(masterDev, opts.Dev, opts.Mode); err != nil {
		return nil, err
	}

	macVlanIfc, err := net.InterfaceByName(opts.Dev)
	if err != nil {
		return nil, fmt.Errorf("Could not find the new interface: %s", err)
	}

	if opts.MacAddr != "" {
		if err := netlink.NetworkSetMacAddress(macVlanIfc, opts.MacAddr); err != nil {
			if errDel := DeleteLink(macVlanIfc.Name); errDel != nil {
				return nil, fmt.Errorf("Incorrect options specified. Attempt to delete the link failed: %s", errDel)
			}
		}
	}

	masterIfc, err := net.InterfaceByName(masterDev)
	if err != nil {
		return nil, fmt.Errorf("Could not find the new interface: %s", err)
	}

	return &MacVlanLink{
		Link: Link{
			ifc: macVlanIfc,
		},
		masterIfc: masterIfc,
		mode:      opts.Mode,
	}, nil
}

// NetInterface returns macvlan link's network interface
func (macvln *MacVlanLink) NetInterface() *net.Interface {
	return macvln.ifc
}

// MasterNetInterface returns macvlan link's master network interface
func (macvln *MacVlanLink) MasterNetInterface() *net.Interface {
	return macvln.masterIfc
}

// Mode returns macvlan link's network operation mode
func (macvln *MacVlanLink) Mode() string {
	return macvln.mode
}

func validateMacVlanOptions(opts *MacVlanOptions) error {
	if opts.Dev != "" {
		if ok, err := NetInterfaceNameValid(opts.Dev); !ok {
			return err
		}

		if _, err := net.InterfaceByName(opts.Dev); err == nil {
			return fmt.Errorf("MAC VLAN device %s already assigned on the host", opts.Dev)
		}
	} else {
		opts.Dev = makeNetInterfaceName("mc")
	}

	if opts.Mode != "" {
		if _, ok := MacVlanModes[opts.Mode]; !ok {
			return fmt.Errorf("Unsupported MacVlan mode specified: %s", opts.Mode)
		}
	} else {
		opts.Mode = default_mode
	}

	if opts.MacAddr != "" {
		if _, err := net.ParseMAC(opts.MacAddr); err != nil {
			return fmt.Errorf("Incorrect MAC ADDRESS specified: %s", opts.MacAddr)
		}
	}

	return nil
}
