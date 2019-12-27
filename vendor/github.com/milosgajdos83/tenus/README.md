# Linux networking in Golang

[![GoDoc](https://godoc.org/github.com/milosgajdos83/tenus?status.svg)](https://godoc.org/github.com/milosgajdos83/tenus)
[![License](https://img.shields.io/:license-apache-blue.svg)](https://opensource.org/licenses/Apache-2.0)

**tenus** is a [Golang](http://golang.org/) package which allows you to configure and manage Linux network devices programmatically. It communicates with Linux Kernel via [netlink](http://man7.org/linux/man-pages/man7/netlink.7.html) to facilitate creation and configuration of network devices on the Linux host. The package also allows for more advanced network setups with Linux containers including [Docker](https://github.com/dotcloud/docker/).

**tenus** uses [runc](https://github.com/opencontainers/runc)'s implementation of **netlink** protocol. The package only works with newer Linux Kernels (3.10+) which are shipping reasonably new `netlink` protocol implementation, so **if you are running older kernel this package won't be of much use to you** I'm afraid. I have developed this package on Ubuntu [Trusty Tahr](http://releases.ubuntu.com/14.04/) which ships with 3.13+ and verified its functionality on [Precise Pangolin](http://releases.ubuntu.com/12.04/) with upgraded kernel to version 3.10. I could worked around the `netlink` issues by using `ioctl` syscalls, but I decided to prefer "pure netlink" implementation, so suck it old Kernels.

At the moment only functional tests are available, but the interface design should hopefully allow for easy (ish) unit testing in the future. I do appreciate that the package's **test coverage is not great at the moment**, but the core functionality should be covered. I would massively welcome PRs.

## Get started

There is a ```Vagrantfile``` available in the repo so using [vagrant](https://github.com/mitchellh/vagrant) is the easiest way to get started:

```bash
milosgajdos@bimbonet ~ $ git clone https://github.com/milosgajdos83/tenus.git
milosgajdos@bimbonet ~ $ vagrant up

```

**Note** using the provided ```Vagrantfile``` will take quite a long time to spin the VM as vagrant will setup Ubuntu Trusty VM with all the prerequisities:

* it will install golang and docker onto the VM
* it will export ```GOPATH``` and ```go get``` the **tenus** package onto the VM
* it will also "**pull**" Docker ubuntu image so that you can run the tests once the VM is set up

At the moment running the tests require Docker to be installed, but in the future I'd love to separate tests per interface so that you can run only chosen test sets.

Once the VM is running, ```cd``` into particular repo directory and you can run the tests:

```bash
milosgajdos@bimbonet ~ $ cd $GOPATH/src/github.com/milosgajdos83/tenus
milosgajdos@bimbonet ~ $ sudo go test
```

If you don't want to use the provided ```Vagrantfile```, you can simply run your own Linux VM (with 3.10+ kernel) and follow the regular golang development flow:

```bash
milosgajdos@bimbonet ~ $ go get github.com/milosgajdos83/tenus
milosgajdos@bimbonet ~ $ cd $GOPATH/src/github.com/milosgajdos83/tenus
milosgajdos@bimbonet ~ $ sudo go test
```

Once you've got the package and ran the tests (you don't need to run the tests!), you can start hacking. Below you can find simple code samples to get started with the package.

## Examples

Below you can find a few code snippets which can help you get started writing your own programs.

### New network bridge, add dummy link into it

The example below shows a simple program example which creates a new network bridge, a new dummy network link and adds it into the bridge.

```go
package main

import (
	"fmt"
	"log"

	"github.com/milosgajdos83/tenus"
)

func main() {
	// Create a new network bridge
	br, err := tenus.NewBridgeWithName("mybridge")
	if err != nil {
		log.Fatal(err)
	}

	// Bring the bridge up
	if err = br.SetLinkUp(); err != nil {
		fmt.Println(err)
	}

	// Create a dummy link
	dl, err := tenus.NewLink("mydummylink")
	if err != nil {
		log.Fatal(err)
	}

	// Add the dummy link into bridge
	if err = br.AddSlaveIfc(dl.NetInterface()); err != nil {
		log.Fatal(err)
	}

	// Bring the dummy link up
	if err = dl.SetLinkUp(); err != nil {
		fmt.Println(err)
	}
}
```

### New network bridge, veth pair, one peer in Docker

The example below shows how you can create a new network bride, configure its IP address, add a new veth pair and send one of the veth peers into Docker with a given name.

**!! You must make sure that particular Docker is runnig if you want the code sample below to work properly !!** So before you compile and run the program below you should create a particular docker with the below used name:

```bash
milosgajdos@bimbonet ~ $ docker run -i -t --rm --privileged -h vethdckr --name vethdckr ubuntu:14.04 /bin/bash
```

```go
package main

import (
	"fmt"
	"log"
	"net"

	"github.com/milosgajdos83/tenus"
)

func main() {
	// CREATE BRIDGE AND BRING IT UP
	br, err := tenus.NewBridgeWithName("vethbridge")
	if err != nil {
		log.Fatal(err)
	}

	brIp, brIpNet, err := net.ParseCIDR("10.0.41.1/16")
	if err != nil {
		log.Fatal(err)
	}

	if err := br.SetLinkIp(brIp, brIpNet); err != nil {
		fmt.Println(err)
	}

	if err = br.SetLinkUp(); err != nil {
		fmt.Println(err)
	}

	// CREATE VETH PAIR
	veth, err := tenus.NewVethPairWithOptions("myveth01", tenus.VethOptions{PeerName: "myveth02"})
	if err != nil {
		log.Fatal(err)
	}

	// ASSIGN IP ADDRESS TO THE HOST VETH INTERFACE
	vethHostIp, vethHostIpNet, err := net.ParseCIDR("10.0.41.2/16")
	if err != nil {
		log.Fatal(err)
	}

	if err := veth.SetLinkIp(vethHostIp, vethHostIpNet); err != nil {
		fmt.Println(err)
	}

	// ADD MYVETH01 INTERFACE TO THE MYBRIDGE BRIDGE
	myveth01, err := net.InterfaceByName("myveth01")
	if err != nil {
		log.Fatal(err)
	}

	if err = br.AddSlaveIfc(myveth01); err != nil {
		fmt.Println(err)
	}

	if err = veth.SetLinkUp(); err != nil {
		fmt.Println(err)
	}

	// PASS VETH PEER INTERFACE TO A RUNNING DOCKER BY PID
	pid, err := tenus.DockerPidByName("vethdckr", "/var/run/docker.sock")
	if err != nil {
		fmt.Println(err)
	}

	if err := veth.SetPeerLinkNsPid(pid); err != nil {
		log.Fatal(err)
	}

	// ALLOCATE AND SET IP FOR THE NEW DOCKER INTERFACE
	vethGuestIp, vethGuestIpNet, err := net.ParseCIDR("10.0.41.5/16")
	if err != nil {
		log.Fatal(err)
	}

	if err := veth.SetPeerLinkNetInNs(pid, vethGuestIp, vethGuestIpNet, nil); err != nil {
		log.Fatal(err)
	}
}
```

### Working with existing bridges and interfaces

The following examples show how to retrieve exisiting interfaces as a tenus link and bridge

```go
package main

import (
	"fmt"
	"log"
	"net"

	"github.com/milosgajdos83/tenus"
)

func main() {
	// RETRIEVE EXISTING BRIDGE
	br, err := tenus.BridgeFromName("bridge0")
	if err != nil {
		log.Fatal(err)
	}

	// REMOVING AN IP FROM A BRIDGE INTERFACE (BEFORE RECONFIGURATION)
	brIp, brIpNet, err := net.ParseCIDR("10.0.41.1/16")
	if err != nil {
		log.Fatal(err)
	}
	if err := br.UnsetLinkIp(brIp, brIpNet); err != nil {
		log.Fatal(err)
	}

	// RETRIEVE EXISTING INTERFACE
	dl, err := tenus.NewLinkFrom("eth0")
	if err != nil {
		log.Fatal(err)
	}

	// RENAMING AN INTERFACE BY NAME
	if err := tenus.RenameInterfaceByName("vethPSQSEl", "vethNEWNAME"); err != nil {
		log.Fatal(err)
	}

}
```

### VLAN and MAC VLAN interfaces

You can check out [VLAN](https://gist.github.com/milosgajdos83/9f68b1818dca886e9ae8) and [Mac VLAN](https://gist.github.com/milosgajdos83/296fb90d076f259a5b0a) examples, too.

### More examples

Repo contains few more code sample in ```examples``` folder so make sure to check them out if you're interested.

## TODO

This is just a rough beginning of the project which I put together over couple of weeks in my free time. I'd like to integrate this into my own Docker fork and test the advanced netowrking functionality with the core of Docker as oppose to configuring network interfaces from a separate golang program, because advanced networking in Docker was the main motivation for writing this package.

## Documentation

More in depth package documentation is available via [godoc](http://godoc.org/github.com/milosgajdos83/tenus)
