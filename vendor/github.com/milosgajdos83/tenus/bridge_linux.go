package tenus

import (
	"bytes"
	"fmt"
	"net"

	"github.com/docker/libcontainer/netlink"
)

// Bridger embeds Linker interface and adds one extra function.
type Bridger interface {
	// Linker interface
	Linker
	// AddSlaveIfc adds network interface to the network bridge
	AddSlaveIfc(*net.Interface) error
	//RemoveSlaveIfc removes network interface from the network bridge
	RemoveSlaveIfc(*net.Interface) error
}

// Bridge is Link which has zero or more slave network interfaces.
// Bridge implements Bridger interface.
type Bridge struct {
	Link
	slaveIfcs []net.Interface
}

// NewBridge creates new network bridge on Linux host.
//
// It is equivalent of running: ip link add name br${RANDOM STRING} type bridge
// NewBridge returns Bridger which is initialized to a pointer of type Bridge if the
// bridge was created successfully on the Linux host. Newly created bridge is assigned
// a random name starting with "br".
// It returns error if the bridge could not be created.
func NewBridge() (Bridger, error) {
	brDev := makeNetInterfaceName("br")

	if ok, err := NetInterfaceNameValid(brDev); !ok {
		return nil, err
	}

	if _, err := net.InterfaceByName(brDev); err == nil {
		return nil, fmt.Errorf("Interface name %s already assigned on the host", brDev)
	}

	if err := netlink.NetworkLinkAdd(brDev, "bridge"); err != nil {
		return nil, err
	}

	newIfc, err := net.InterfaceByName(brDev)
	if err != nil {
		return nil, fmt.Errorf("Could not find the new interface: %s", err)
	}

	return &Bridge{
		Link: Link{
			ifc: newIfc,
		},
	}, nil
}

// NewBridge creates new network bridge on Linux host with the name passed as a parameter.
// It is equivalent of running: ip link add name ${ifcName} type bridge
// It returns error if the bridge can not be created.
func NewBridgeWithName(ifcName string) (Bridger, error) {
	if ok, err := NetInterfaceNameValid(ifcName); !ok {
		return nil, err
	}

	if _, err := net.InterfaceByName(ifcName); err == nil {
		return nil, fmt.Errorf("Interface name %s already assigned on the host", ifcName)
	}

	if err := netlink.NetworkLinkAdd(ifcName, "bridge"); err != nil {
		return nil, err
	}

	newIfc, err := net.InterfaceByName(ifcName)
	if err != nil {
		return nil, fmt.Errorf("Could not find the new interface: %s", err)
	}

	return &Bridge{
		Link: Link{
			ifc: newIfc,
		},
	}, nil
}

// BridgeFromName returns a tenus network bridge from an existing bridge of given name on the Linux host.
// It returns error if the bridge of the given name cannot be found.
func BridgeFromName(ifcName string) (Bridger, error) {
	if ok, err := NetInterfaceNameValid(ifcName); !ok {
		return nil, err
	}

	newIfc, err := net.InterfaceByName(ifcName)
	if err != nil {
		return nil, fmt.Errorf("Could not find the new interface: %s", err)
	}

	return &Bridge{
		Link: Link{
			ifc: newIfc,
		},
	}, nil
}

// AddToBridge adds network interfaces to network bridge.
// It is equivalent of running: ip link set ${netIfc name} master ${netBridge name}
// It returns error when it fails to add the network interface to bridge.
func AddToBridge(netIfc, netBridge *net.Interface) error {
	return netlink.NetworkSetMaster(netIfc, netBridge)
}

// AddToBridge adds network interfaces to network bridge.
// It is equivalent of running: ip link set dev ${netIfc name} nomaster
// It returns error when it fails to remove the network interface from the bridge.
func RemoveFromBridge(netIfc *net.Interface) error {
	return netlink.NetworkSetNoMaster(netIfc)
}

// AddSlaveIfc adds network interface to network bridge.
// It is equivalent of running: ip link set ${ifc name} master ${bridge name}
// It returns error if the network interface could not be added to the bridge.
func (br *Bridge) AddSlaveIfc(ifc *net.Interface) error {
	if err := netlink.NetworkSetMaster(ifc, br.ifc); err != nil {
		return err
	}

	br.slaveIfcs = append(br.slaveIfcs, *ifc)

	return nil
}

// RemoveSlaveIfc removes network interface from the network bridge.
// It is equivalent of running: ip link set dev ${netIfc name} nomaster
// It returns error if the network interface is not in the bridge or
// it could not be removed from the bridge.
func (br *Bridge) RemoveSlaveIfc(ifc *net.Interface) error {
	if err := netlink.NetworkSetNoMaster(ifc); err != nil {
		return err
	}

	for index, i := range br.slaveIfcs {
		// I could reflect.DeepEqual(), but there is not point to import reflect for one operation
		if i.Name == ifc.Name && bytes.Equal(i.HardwareAddr, ifc.HardwareAddr) {
			br.slaveIfcs = append(br.slaveIfcs[:index], br.slaveIfcs[index+1:]...)
		}
	}

	return nil
}
