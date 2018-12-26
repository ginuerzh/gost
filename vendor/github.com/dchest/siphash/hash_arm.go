// +build arm

package siphash

// NB: ARM implementation of forgoes extra speed for Hash()
// and Hash128() by simply reusing the same blocks() implementation
// in assembly used by the streaming hash.

func Hash(k0, k1 uint64, p []byte) uint64 {
	var d digest
	d.size = Size
	d.k0 = k0
	d.k1 = k1
	d.Reset()
	d.Write(p)
	return d.Sum64()
}

func Hash128(k0, k1 uint64, p []byte) (uint64, uint64) {
	var d digest
	d.size = Size128
	d.k0 = k0
	d.k1 = k1
	d.Reset()
	d.Write(p)
	return d.sum128()
}
