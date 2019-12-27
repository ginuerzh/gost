package tenus

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
	"unicode"

	"github.com/docker/libcontainer/netlink"
	"github.com/docker/libcontainer/system"
)

// generates random string for makeNetInterfaceName()
func randomString(size int) string {
	alphanum := "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	bytes := make([]byte, size)
	rand.Read(bytes)

	for i, b := range bytes {
		bytes[i] = alphanum[b%byte(len(alphanum))]
	}

	return string(bytes)
}

func MakeNetInterfaceName(base string) string {
	return makeNetInterfaceName(base)
}

// generates new unused network interfaces name with given prefix
func makeNetInterfaceName(base string) string {
	for {
		name := base + randomString(6)
		if _, err := net.InterfaceByName(name); err == nil {
			continue
		}

		return name
	}
}

// validates MTU LinkOption
func validMtu(mtu int) error {
	if mtu < 0 {
		return errors.New("MTU must be a positive integer!")
	}

	return nil
}

// validates MacAddress LinkOption
func validMacAddress(macaddr string) error {
	if _, err := net.ParseMAC(macaddr); err != nil {
		return fmt.Errorf("Can not parse MAC address: %s", err)
	}

	if _, err := FindInterfaceByMacAddress(macaddr); err == nil {
		return fmt.Errorf("MAC Address already assigned on the host: %s", macaddr)
	}

	return nil
}

// validates MacAddress LinkOption
func validNs(ns int) error {
	if ns < 0 {
		return fmt.Errorf("Incorrect Network Namespace PID specified: %d", ns)
	}

	return nil
}

// validates Flags LinkOption
func validFlags(flags net.Flags) error {
	if (flags & syscall.IFF_UP) != syscall.IFF_UP {
		return fmt.Errorf("Unsupported network flags specified: %v", flags)
	}

	return nil
}

// NetInterfaceNameValid checks if the network interface name is valid.
// It accepts interface name as a string. It returns error if invalid interface name is supplied.
func NetInterfaceNameValid(name string) (bool, error) {
	if name == "" {
		return false, errors.New("Interface name can not be empty")
	}

	if len(name) == 1 {
		return false, fmt.Errorf("Interface name too short: %s", name)
	}

	if len(name) > netlink.IFNAMSIZ {
		return false, fmt.Errorf("Interface name too long: %s", name)
	}

	for _, char := range name {
		if unicode.IsSpace(char) || char > 0x7F {
			return false, fmt.Errorf("Invalid characters in interface name: %s", name)
		}
	}

	return true, nil
}

// FindInterfaceByMacAddress returns *net.Interface which has a given MAC address assigned.
// It returns nil and error if invalid MAC address is supplied or if there is no network interface
// with the given MAC address assigned on Linux host.
func FindInterfaceByMacAddress(macaddr string) (*net.Interface, error) {
	if macaddr == "" {
		return nil, errors.New("Empty MAC address specified!")
	}

	ifcs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	hwaddr, err := net.ParseMAC(macaddr)
	if err != nil {
		return nil, err
	}

	for _, ifc := range ifcs {
		if bytes.Equal(hwaddr, ifc.HardwareAddr) {
			return &ifc, nil
		}
	}

	return nil, fmt.Errorf("Could not find interface with MAC address on the host: %s", macaddr)
}

// DockerPidByName returns PID of the running docker container.
// It accepts Docker container name and Docker host as parameters and queries Docker API via HTTP.
// Docker host passed as an argument can be either full path to Docker UNIX socket or HOST:PORT address string.
// It returns error if Docker container can not be found or if an error occurs when querying Docker API.
func DockerPidByName(name string, dockerHost string) (int, error) {
	var network string

	if name == "" {
		return 0, errors.New("Docker name can not be empty!")
	}

	if dockerHost == "" {
		return 0, errors.New("Docker host can not be empty!")
	}

	if filepath.IsAbs(dockerHost) {
		network = "unix"
	} else {
		network = "tcp"
	}

	req, err := http.NewRequest("GET", "http://docker.socket/containers/"+name+"/json", nil)
	if err != nil {
		return 0, fmt.Errorf("Fail to create http request: %s", err)
	}

	timeout := time.Duration(2 * time.Second)
	httpTransport := &http.Transport{
		Dial: func(proto string, addr string) (net.Conn, error) {
			return net.DialTimeout(network, dockerHost, timeout)
		},
	}

	dockerClient := http.Client{Transport: httpTransport}

	resp, err := dockerClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("Failed to create http client: %s", err)
	}

	switch resp.StatusCode {
	case http.StatusNotFound:
		return 0, fmt.Errorf("Docker container \"%s\" does not seem to exist!", name)
	case http.StatusInternalServerError:
		return 0, fmt.Errorf("Could not retrieve Docker %s pid due to Docker server error", name)
	}

	data := struct {
		State struct {
			Pid float64
		}
	}{}

	err = json.NewDecoder(resp.Body).Decode(&data)
	if err != nil {
		return 0, fmt.Errorf("Unable to decode json response: %s", err)
	}

	return int(data.State.Pid), nil
}

// NetNsHandle returns a file descriptor handle for network namespace specified by PID.
// It returns error if network namespace could not be found or if network namespace path could not be opened.
func NetNsHandle(nspid int) (uintptr, error) {
	if nspid <= 0 || nspid == 1 {
		return 0, fmt.Errorf("Incorred PID specified: %d", nspid)
	}

	nsPath := path.Join("/", "proc", strconv.Itoa(nspid), "ns/net")
	if nsPath == "" {
		return 0, fmt.Errorf("Could not find Network namespace for pid: %d", nspid)
	}

	file, err := os.Open(nsPath)
	if err != nil {
		return 0, fmt.Errorf("Could not open Network Namespace: %s", err)
	}

	return file.Fd(), nil
}

// SetNetNsToPid sets network namespace to the one specied by PID.
// It returns error if the network namespace could not be set.
func SetNetNsToPid(nspid int) error {
	if nspid <= 0 || nspid == 1 {
		return fmt.Errorf("Incorred PID specified: %d", nspid)
	}

	nsFd, err := NetNsHandle(nspid)
	defer syscall.Close(int(nsFd))
	if err != nil {
		return fmt.Errorf("Could not get network namespace handle: %s", err)
	}

	if err := system.Setns(nsFd, syscall.CLONE_NEWNET); err != nil {
		return fmt.Errorf("Unable to set the network namespace: %v", err)
	}

	return nil
}
