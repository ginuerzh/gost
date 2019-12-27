// Package tenus allows to configure and manage Linux network devices programmatically.
//
// You can create, configure and manage various advanced Linux network setups directly from your Go code.
// tenus also allows you to configure advanced network setups with Linux containers including Docker.
// It leverages Linux Kernenl's netlink facility and exposes easier to work with programming API than
// the one provided by netlink.
//
// Actual implementations are in:
// link_linux.go, bridge_linux.go, veth_linux.go, vlan_linux.go and macvlan_linux.go
package tenus
