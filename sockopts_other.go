//go:build !linux

package gost

func setSocketMark(fd int, value int) (e error) {
	return nil
}

func setSocketInterface(fd int, value string) (e error) {
	return nil
}