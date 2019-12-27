// +build linux,!go1.11

package water

import (
	"os"
)

func openDev(config Config) (ifce *Interface, err error) {
	var file *os.File
	if file, err = os.OpenFile(
		"/dev/net/tun", os.O_RDWR, 0); err != nil {
		return nil, err
	}

	name, err := setupFd(config, file.Fd())
	if err != nil {
		return nil, err
	}

	return &Interface{
		isTAP:           config.DeviceType == TAP,
		ReadWriteCloser: file,
		name:            name,
	}, nil
}
