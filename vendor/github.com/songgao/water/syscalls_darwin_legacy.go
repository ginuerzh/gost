// +build darwin,!go1.11

package water

func setNonBlock(fd int) error {
	// There's a but pre-go1.11 that causes 'resource temporarily unavailable'
	// error in non-blocking mode. So just skip it here. Close() won't be able
	// to unblock a pending read, but that's better than being broken.
	return nil
}
