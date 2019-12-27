// +build linux,go1.11

package water

import (
	"os"
	"syscall"
)

func openDev(config Config) (ifce *Interface, err error) {
	var fdInt int
	if fdInt, err = syscall.Open(
		"/dev/net/tun", os.O_RDWR|syscall.O_NONBLOCK, 0); err != nil {
		return nil, err
	}

	name, err := setupFd(config, uintptr(fdInt))
	if err != nil {
		return nil, err
	}

	return &Interface{
		isTAP:           config.DeviceType == TAP,
		ReadWriteCloser: os.NewFile(uintptr(fdInt), "tun"),
		name:            name,
	}, nil
}
