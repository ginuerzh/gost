// chacha20.go - A ChaCha stream cipher implementation.
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to chacha20, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package chacha20

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"math"
	"runtime"
)

const (
	// KeySize is the ChaCha20 key size in bytes.
	KeySize = 32

	// NonceSize is the ChaCha20 nonce size in bytes.
	NonceSize = 8

	// INonceSize is the IETF ChaCha20 nonce size in bytes.
	INonceSize = 12

	// XNonceSize is the XChaCha20 nonce size in bytes.
	XNonceSize = 24

	// HNonceSize is the HChaCha20 nonce size in bytes.
	HNonceSize = 16

	// BlockSize is the ChaCha20 block size in bytes.
	BlockSize = 64

	stateSize    = 16
	chachaRounds = 20

	// The constant "expand 32-byte k" as little endian uint32s.
	sigma0 = uint32(0x61707865)
	sigma1 = uint32(0x3320646e)
	sigma2 = uint32(0x79622d32)
	sigma3 = uint32(0x6b206574)
)

var (
	// ErrInvalidKey is the error returned when the key is invalid.
	ErrInvalidKey = errors.New("key length must be KeySize bytes")

	// ErrInvalidNonce is the error returned when the nonce is invalid.
	ErrInvalidNonce = errors.New("nonce length must be NonceSize/INonceSize/XNonceSize bytes")

	// ErrInvalidCounter is the error returned when the counter is invalid.
	ErrInvalidCounter = errors.New("block counter is invalid (out of range)")

	useUnsafe    = false
	usingVectors = false
	blocksFn     = blocksRef
)

// A Cipher is an instance of ChaCha20/XChaCha20 using a particular key and
// nonce.
type Cipher struct {
	state [stateSize]uint32

	buf  [BlockSize]byte
	off  int
	ietf bool
}

// Reset zeros the key data so that it will no longer appear in the process's
// memory.
func (c *Cipher) Reset() {
	for i := range c.state {
		c.state[i] = 0
	}
	for i := range c.buf {
		c.buf[i] = 0
	}
}

// XORKeyStream sets dst to the result of XORing src with the key stream.  Dst
// and src may be the same slice but otherwise should not overlap.
func (c *Cipher) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		src = src[:len(dst)]
	}

	for remaining := len(src); remaining > 0; {
		// Process multiple blocks at once.
		if c.off == BlockSize {
			nrBlocks := remaining / BlockSize
			directBytes := nrBlocks * BlockSize
			if nrBlocks > 0 {
				blocksFn(&c.state, src, dst, nrBlocks, c.ietf)
				remaining -= directBytes
				if remaining == 0 {
					return
				}
				dst = dst[directBytes:]
				src = src[directBytes:]
			}

			// If there's a partial block, generate 1 block of keystream into
			// the internal buffer.
			blocksFn(&c.state, nil, c.buf[:], 1, c.ietf)
			c.off = 0
		}

		// Process partial blocks from the buffered keystream.
		toXor := BlockSize - c.off
		if remaining < toXor {
			toXor = remaining
		}
		if toXor > 0 {
			for i, v := range src[:toXor] {
				dst[i] = v ^ c.buf[c.off+i]
			}
			dst = dst[toXor:]
			src = src[toXor:]

			remaining -= toXor
			c.off += toXor
		}
	}
}

// KeyStream sets dst to the raw keystream.
func (c *Cipher) KeyStream(dst []byte) {
	for remaining := len(dst); remaining > 0; {
		// Process multiple blocks at once.
		if c.off == BlockSize {
			nrBlocks := remaining / BlockSize
			directBytes := nrBlocks * BlockSize
			if nrBlocks > 0 {
				blocksFn(&c.state, nil, dst, nrBlocks, c.ietf)
				remaining -= directBytes
				if remaining == 0 {
					return
				}
				dst = dst[directBytes:]
			}

			// If there's a partial block, generate 1 block of keystream into
			// the internal buffer.
			blocksFn(&c.state, nil, c.buf[:], 1, c.ietf)
			c.off = 0
		}

		// Process partial blocks from the buffered keystream.
		toCopy := BlockSize - c.off
		if remaining < toCopy {
			toCopy = remaining
		}
		if toCopy > 0 {
			copy(dst[:toCopy], c.buf[c.off:c.off+toCopy])
			dst = dst[toCopy:]
			remaining -= toCopy
			c.off += toCopy
		}
	}
}

// ReKey reinitializes the ChaCha20/XChaCha20 instance with the provided key
// and nonce.
func (c *Cipher) ReKey(key, nonce []byte) error {
	if len(key) != KeySize {
		return ErrInvalidKey
	}

	switch len(nonce) {
	case NonceSize:
	case INonceSize:
	case XNonceSize:
		var subkey [KeySize]byte
		var subnonce [HNonceSize]byte
		copy(subnonce[:], nonce[0:16])
		HChaCha(key, &subnonce, &subkey)
		key = subkey[:]
		nonce = nonce[16:24]
		defer func() {
			for i := range subkey {
				subkey[i] = 0
			}
		}()
	default:
		return ErrInvalidNonce
	}

	c.Reset()
	c.state[0] = sigma0
	c.state[1] = sigma1
	c.state[2] = sigma2
	c.state[3] = sigma3
	c.state[4] = binary.LittleEndian.Uint32(key[0:4])
	c.state[5] = binary.LittleEndian.Uint32(key[4:8])
	c.state[6] = binary.LittleEndian.Uint32(key[8:12])
	c.state[7] = binary.LittleEndian.Uint32(key[12:16])
	c.state[8] = binary.LittleEndian.Uint32(key[16:20])
	c.state[9] = binary.LittleEndian.Uint32(key[20:24])
	c.state[10] = binary.LittleEndian.Uint32(key[24:28])
	c.state[11] = binary.LittleEndian.Uint32(key[28:32])
	c.state[12] = 0
	if len(nonce) == INonceSize {
		c.state[13] = binary.LittleEndian.Uint32(nonce[0:4])
		c.state[14] = binary.LittleEndian.Uint32(nonce[4:8])
		c.state[15] = binary.LittleEndian.Uint32(nonce[8:12])
		c.ietf = true
	} else {
		c.state[13] = 0
		c.state[14] = binary.LittleEndian.Uint32(nonce[0:4])
		c.state[15] = binary.LittleEndian.Uint32(nonce[4:8])
		c.ietf = false
	}
	c.off = BlockSize
	return nil

}

// Seek sets the block counter to a given offset.
func (c *Cipher) Seek(blockCounter uint64) error {
	if c.ietf {
		if blockCounter > math.MaxUint32 {
			return ErrInvalidCounter
		}
		c.state[12] = uint32(blockCounter)
	} else {
		c.state[12] = uint32(blockCounter)
		c.state[13] = uint32(blockCounter >> 32)
	}
	c.off = BlockSize
	return nil
}

// NewCipher returns a new ChaCha20/XChaCha20 instance.
func NewCipher(key, nonce []byte) (*Cipher, error) {
	c := new(Cipher)
	if err := c.ReKey(key, nonce); err != nil {
		return nil, err
	}
	return c, nil
}

// HChaCha is the HChaCha20 hash function used to make XChaCha.
func HChaCha(key []byte, nonce *[HNonceSize]byte, out *[32]byte) {
	var x [stateSize]uint32 // Last 4 slots unused, sigma hardcoded.
	x[0] = binary.LittleEndian.Uint32(key[0:4])
	x[1] = binary.LittleEndian.Uint32(key[4:8])
	x[2] = binary.LittleEndian.Uint32(key[8:12])
	x[3] = binary.LittleEndian.Uint32(key[12:16])
	x[4] = binary.LittleEndian.Uint32(key[16:20])
	x[5] = binary.LittleEndian.Uint32(key[20:24])
	x[6] = binary.LittleEndian.Uint32(key[24:28])
	x[7] = binary.LittleEndian.Uint32(key[28:32])
	x[8] = binary.LittleEndian.Uint32(nonce[0:4])
	x[9] = binary.LittleEndian.Uint32(nonce[4:8])
	x[10] = binary.LittleEndian.Uint32(nonce[8:12])
	x[11] = binary.LittleEndian.Uint32(nonce[12:16])
	hChaChaRef(&x, out)
}

func init() {
	switch runtime.GOARCH {
	case "386", "amd64":
		// Abuse unsafe to skip calling binary.LittleEndian.PutUint32
		// in the critical path.  This is a big boost on systems that are
		// little endian and not overly picky about alignment.
		useUnsafe = true
	}
}

var _ cipher.Stream = (*Cipher)(nil)
