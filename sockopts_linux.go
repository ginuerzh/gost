package gost

import "syscall"

func setSocketMark(fd int, value int) (e error) {
	return syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_MARK, value)
}
