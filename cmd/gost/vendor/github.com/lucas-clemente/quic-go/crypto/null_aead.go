package crypto

import (
	"encoding/binary"
	"errors"

	"github.com/lucas-clemente/fnv128a"
	"github.com/lucas-clemente/quic-go/protocol"
)

// NullAEAD handles not-yet encrypted packets
type NullAEAD struct{}

var _ AEAD = &NullAEAD{}

// Open and verify the ciphertext
func (NullAEAD) Open(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) ([]byte, error) {
	if len(src) < 12 {
		return nil, errors.New("NullAEAD: ciphertext cannot be less than 12 bytes long")
	}

	hash := fnv128a.New()
	hash.Write(associatedData)
	hash.Write(src[12:])
	testHigh, testLow := hash.Sum128()

	low := binary.LittleEndian.Uint64(src)
	high := binary.LittleEndian.Uint32(src[8:])

	if uint32(testHigh&0xffffffff) != high || testLow != low {
		return nil, errors.New("NullAEAD: failed to authenticate received data")
	}
	return src[12:], nil
}

// Seal writes hash and ciphertext to the buffer
func (NullAEAD) Seal(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) []byte {
	if cap(dst) < 12+len(src) {
		dst = make([]byte, 12+len(src))
	} else {
		dst = dst[:12+len(src)]
	}

	hash := fnv128a.New()
	hash.Write(associatedData)
	hash.Write(src)
	high, low := hash.Sum128()

	copy(dst[12:], src)
	binary.LittleEndian.PutUint64(dst, low)
	binary.LittleEndian.PutUint32(dst[8:], uint32(high))
	return dst
}
