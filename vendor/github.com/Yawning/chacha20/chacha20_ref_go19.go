// chacha20_ref.go - Reference ChaCha20.
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to chacha20, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

// +build go1.9

package chacha20

import (
	"encoding/binary"
	"math"
	"math/bits"
	"unsafe"
)

func blocksRef(x *[stateSize]uint32, in []byte, out []byte, nrBlocks int, isIetf bool) {
	if isIetf {
		var totalBlocks uint64
		totalBlocks = uint64(x[12]) + uint64(nrBlocks)
		if totalBlocks > math.MaxUint32 {
			panic("chacha20: Exceeded keystream per nonce limit")
		}
	}

	// This routine ignores x[0]...x[4] in favor the const values since it's
	// ever so slightly faster.

	for n := 0; n < nrBlocks; n++ {
		x0, x1, x2, x3 := sigma0, sigma1, sigma2, sigma3
		x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15 := x[4], x[5], x[6], x[7], x[8], x[9], x[10], x[11], x[12], x[13], x[14], x[15]

		for i := chachaRounds; i > 0; i -= 2 {
			// quarterround(x, 0, 4, 8, 12)
			x0 += x4
			x12 ^= x0
			x12 = bits.RotateLeft32(x12, 16)
			x8 += x12
			x4 ^= x8
			x4 = bits.RotateLeft32(x4, 12)
			x0 += x4
			x12 ^= x0
			x12 = bits.RotateLeft32(x12, 8)
			x8 += x12
			x4 ^= x8
			x4 = bits.RotateLeft32(x4, 7)

			// quarterround(x, 1, 5, 9, 13)
			x1 += x5
			x13 ^= x1
			x13 = bits.RotateLeft32(x13, 16)
			x9 += x13
			x5 ^= x9
			x5 = bits.RotateLeft32(x5, 12)
			x1 += x5
			x13 ^= x1
			x13 = bits.RotateLeft32(x13, 8)
			x9 += x13
			x5 ^= x9
			x5 = bits.RotateLeft32(x5, 7)

			// quarterround(x, 2, 6, 10, 14)
			x2 += x6
			x14 ^= x2
			x14 = bits.RotateLeft32(x14, 16)
			x10 += x14
			x6 ^= x10
			x6 = bits.RotateLeft32(x6, 12)
			x2 += x6
			x14 ^= x2
			x14 = bits.RotateLeft32(x14, 8)
			x10 += x14
			x6 ^= x10
			x6 = bits.RotateLeft32(x6, 7)

			// quarterround(x, 3, 7, 11, 15)
			x3 += x7
			x15 ^= x3
			x15 = bits.RotateLeft32(x15, 16)
			x11 += x15
			x7 ^= x11
			x7 = bits.RotateLeft32(x7, 12)
			x3 += x7
			x15 ^= x3
			x15 = bits.RotateLeft32(x15, 8)
			x11 += x15
			x7 ^= x11
			x7 = bits.RotateLeft32(x7, 7)

			// quarterround(x, 0, 5, 10, 15)
			x0 += x5
			x15 ^= x0
			x15 = bits.RotateLeft32(x15, 16)
			x10 += x15
			x5 ^= x10
			x5 = bits.RotateLeft32(x5, 12)
			x0 += x5
			x15 ^= x0
			x15 = bits.RotateLeft32(x15, 8)
			x10 += x15
			x5 ^= x10
			x5 = bits.RotateLeft32(x5, 7)

			// quarterround(x, 1, 6, 11, 12)
			x1 += x6
			x12 ^= x1
			x12 = bits.RotateLeft32(x12, 16)
			x11 += x12
			x6 ^= x11
			x6 = bits.RotateLeft32(x6, 12)
			x1 += x6
			x12 ^= x1
			x12 = bits.RotateLeft32(x12, 8)
			x11 += x12
			x6 ^= x11
			x6 = bits.RotateLeft32(x6, 7)

			// quarterround(x, 2, 7, 8, 13)
			x2 += x7
			x13 ^= x2
			x13 = bits.RotateLeft32(x13, 16)
			x8 += x13
			x7 ^= x8
			x7 = bits.RotateLeft32(x7, 12)
			x2 += x7
			x13 ^= x2
			x13 = bits.RotateLeft32(x13, 8)
			x8 += x13
			x7 ^= x8
			x7 = bits.RotateLeft32(x7, 7)

			// quarterround(x, 3, 4, 9, 14)
			x3 += x4
			x14 ^= x3
			x14 = bits.RotateLeft32(x14, 16)
			x9 += x14
			x4 ^= x9
			x4 = bits.RotateLeft32(x4, 12)
			x3 += x4
			x14 ^= x3
			x14 = bits.RotateLeft32(x14, 8)
			x9 += x14
			x4 ^= x9
			x4 = bits.RotateLeft32(x4, 7)
		}

		// On amd64 at least, this is a rather big boost.
		if useUnsafe {
			if in != nil {
				inArr := (*[16]uint32)(unsafe.Pointer(&in[n*BlockSize]))
				outArr := (*[16]uint32)(unsafe.Pointer(&out[n*BlockSize]))
				outArr[0] = inArr[0] ^ (x0 + sigma0)
				outArr[1] = inArr[1] ^ (x1 + sigma1)
				outArr[2] = inArr[2] ^ (x2 + sigma2)
				outArr[3] = inArr[3] ^ (x3 + sigma3)
				outArr[4] = inArr[4] ^ (x4 + x[4])
				outArr[5] = inArr[5] ^ (x5 + x[5])
				outArr[6] = inArr[6] ^ (x6 + x[6])
				outArr[7] = inArr[7] ^ (x7 + x[7])
				outArr[8] = inArr[8] ^ (x8 + x[8])
				outArr[9] = inArr[9] ^ (x9 + x[9])
				outArr[10] = inArr[10] ^ (x10 + x[10])
				outArr[11] = inArr[11] ^ (x11 + x[11])
				outArr[12] = inArr[12] ^ (x12 + x[12])
				outArr[13] = inArr[13] ^ (x13 + x[13])
				outArr[14] = inArr[14] ^ (x14 + x[14])
				outArr[15] = inArr[15] ^ (x15 + x[15])
			} else {
				outArr := (*[16]uint32)(unsafe.Pointer(&out[n*BlockSize]))
				outArr[0] = x0 + sigma0
				outArr[1] = x1 + sigma1
				outArr[2] = x2 + sigma2
				outArr[3] = x3 + sigma3
				outArr[4] = x4 + x[4]
				outArr[5] = x5 + x[5]
				outArr[6] = x6 + x[6]
				outArr[7] = x7 + x[7]
				outArr[8] = x8 + x[8]
				outArr[9] = x9 + x[9]
				outArr[10] = x10 + x[10]
				outArr[11] = x11 + x[11]
				outArr[12] = x12 + x[12]
				outArr[13] = x13 + x[13]
				outArr[14] = x14 + x[14]
				outArr[15] = x15 + x[15]
			}
		} else {
			// Slow path, either the architecture cares about alignment, or is not little endian.
			x0 += sigma0
			x1 += sigma1
			x2 += sigma2
			x3 += sigma3
			x4 += x[4]
			x5 += x[5]
			x6 += x[6]
			x7 += x[7]
			x8 += x[8]
			x9 += x[9]
			x10 += x[10]
			x11 += x[11]
			x12 += x[12]
			x13 += x[13]
			x14 += x[14]
			x15 += x[15]
			if in != nil {
				binary.LittleEndian.PutUint32(out[0:4], binary.LittleEndian.Uint32(in[0:4])^x0)
				binary.LittleEndian.PutUint32(out[4:8], binary.LittleEndian.Uint32(in[4:8])^x1)
				binary.LittleEndian.PutUint32(out[8:12], binary.LittleEndian.Uint32(in[8:12])^x2)
				binary.LittleEndian.PutUint32(out[12:16], binary.LittleEndian.Uint32(in[12:16])^x3)
				binary.LittleEndian.PutUint32(out[16:20], binary.LittleEndian.Uint32(in[16:20])^x4)
				binary.LittleEndian.PutUint32(out[20:24], binary.LittleEndian.Uint32(in[20:24])^x5)
				binary.LittleEndian.PutUint32(out[24:28], binary.LittleEndian.Uint32(in[24:28])^x6)
				binary.LittleEndian.PutUint32(out[28:32], binary.LittleEndian.Uint32(in[28:32])^x7)
				binary.LittleEndian.PutUint32(out[32:36], binary.LittleEndian.Uint32(in[32:36])^x8)
				binary.LittleEndian.PutUint32(out[36:40], binary.LittleEndian.Uint32(in[36:40])^x9)
				binary.LittleEndian.PutUint32(out[40:44], binary.LittleEndian.Uint32(in[40:44])^x10)
				binary.LittleEndian.PutUint32(out[44:48], binary.LittleEndian.Uint32(in[44:48])^x11)
				binary.LittleEndian.PutUint32(out[48:52], binary.LittleEndian.Uint32(in[48:52])^x12)
				binary.LittleEndian.PutUint32(out[52:56], binary.LittleEndian.Uint32(in[52:56])^x13)
				binary.LittleEndian.PutUint32(out[56:60], binary.LittleEndian.Uint32(in[56:60])^x14)
				binary.LittleEndian.PutUint32(out[60:64], binary.LittleEndian.Uint32(in[60:64])^x15)
				in = in[BlockSize:]
			} else {
				binary.LittleEndian.PutUint32(out[0:4], x0)
				binary.LittleEndian.PutUint32(out[4:8], x1)
				binary.LittleEndian.PutUint32(out[8:12], x2)
				binary.LittleEndian.PutUint32(out[12:16], x3)
				binary.LittleEndian.PutUint32(out[16:20], x4)
				binary.LittleEndian.PutUint32(out[20:24], x5)
				binary.LittleEndian.PutUint32(out[24:28], x6)
				binary.LittleEndian.PutUint32(out[28:32], x7)
				binary.LittleEndian.PutUint32(out[32:36], x8)
				binary.LittleEndian.PutUint32(out[36:40], x9)
				binary.LittleEndian.PutUint32(out[40:44], x10)
				binary.LittleEndian.PutUint32(out[44:48], x11)
				binary.LittleEndian.PutUint32(out[48:52], x12)
				binary.LittleEndian.PutUint32(out[52:56], x13)
				binary.LittleEndian.PutUint32(out[56:60], x14)
				binary.LittleEndian.PutUint32(out[60:64], x15)
			}
			out = out[BlockSize:]
		}

		// Stoping at 2^70 bytes per nonce is the user's responsibility.
		ctr := uint64(x[13])<<32 | uint64(x[12])
		ctr++
		x[12] = uint32(ctr)
		x[13] = uint32(ctr >> 32)
	}
}

func hChaChaRef(x *[stateSize]uint32, out *[32]byte) {
	x0, x1, x2, x3 := sigma0, sigma1, sigma2, sigma3
	x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15 := x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7], x[8], x[9], x[10], x[11]

	for i := chachaRounds; i > 0; i -= 2 {
		// quarterround(x, 0, 4, 8, 12)
		x0 += x4
		x12 ^= x0
		x12 = bits.RotateLeft32(x12, 16)
		x8 += x12
		x4 ^= x8
		x4 = bits.RotateLeft32(x4, 12)
		x0 += x4
		x12 ^= x0
		x12 = bits.RotateLeft32(x12, 8)
		x8 += x12
		x4 ^= x8
		x4 = bits.RotateLeft32(x4, 7)

		// quarterround(x, 1, 5, 9, 13)
		x1 += x5
		x13 ^= x1
		x13 = bits.RotateLeft32(x13, 16)
		x9 += x13
		x5 ^= x9
		x5 = bits.RotateLeft32(x5, 12)
		x1 += x5
		x13 ^= x1
		x13 = bits.RotateLeft32(x13, 8)
		x9 += x13
		x5 ^= x9
		x5 = bits.RotateLeft32(x5, 7)

		// quarterround(x, 2, 6, 10, 14)
		x2 += x6
		x14 ^= x2
		x14 = bits.RotateLeft32(x14, 16)
		x10 += x14
		x6 ^= x10
		x6 = bits.RotateLeft32(x6, 12)
		x2 += x6
		x14 ^= x2
		x14 = bits.RotateLeft32(x14, 8)
		x10 += x14
		x6 ^= x10
		x6 = bits.RotateLeft32(x6, 7)

		// quarterround(x, 3, 7, 11, 15)
		x3 += x7
		x15 ^= x3
		x15 = bits.RotateLeft32(x15, 16)
		x11 += x15
		x7 ^= x11
		x7 = bits.RotateLeft32(x7, 12)
		x3 += x7
		x15 ^= x3
		x15 = bits.RotateLeft32(x15, 8)
		x11 += x15
		x7 ^= x11
		x7 = bits.RotateLeft32(x7, 7)

		// quarterround(x, 0, 5, 10, 15)
		x0 += x5
		x15 ^= x0
		x15 = bits.RotateLeft32(x15, 16)
		x10 += x15
		x5 ^= x10
		x5 = bits.RotateLeft32(x5, 12)
		x0 += x5
		x15 ^= x0
		x15 = bits.RotateLeft32(x15, 8)
		x10 += x15
		x5 ^= x10
		x5 = bits.RotateLeft32(x5, 7)

		// quarterround(x, 1, 6, 11, 12)
		x1 += x6
		x12 ^= x1
		x12 = bits.RotateLeft32(x12, 16)
		x11 += x12
		x6 ^= x11
		x6 = bits.RotateLeft32(x6, 12)
		x1 += x6
		x12 ^= x1
		x12 = bits.RotateLeft32(x12, 8)
		x11 += x12
		x6 ^= x11
		x6 = bits.RotateLeft32(x6, 7)

		// quarterround(x, 2, 7, 8, 13)
		x2 += x7
		x13 ^= x2
		x13 = bits.RotateLeft32(x13, 16)
		x8 += x13
		x7 ^= x8
		x7 = bits.RotateLeft32(x7, 12)
		x2 += x7
		x13 ^= x2
		x13 = bits.RotateLeft32(x13, 8)
		x8 += x13
		x7 ^= x8
		x7 = bits.RotateLeft32(x7, 7)

		// quarterround(x, 3, 4, 9, 14)
		x3 += x4
		x14 ^= x3
		x14 = bits.RotateLeft32(x14, 16)
		x9 += x14
		x4 ^= x9
		x4 = bits.RotateLeft32(x4, 12)
		x3 += x4
		x14 ^= x3
		x14 = bits.RotateLeft32(x14, 8)
		x9 += x14
		x4 ^= x9
		x4 = bits.RotateLeft32(x4, 7)
	}

	// HChaCha returns x0...x3 | x12...x15, which corresponds to the
	// indexes of the ChaCha constant and the indexes of the IV.
	if useUnsafe {
		outArr := (*[16]uint32)(unsafe.Pointer(&out[0]))
		outArr[0] = x0
		outArr[1] = x1
		outArr[2] = x2
		outArr[3] = x3
		outArr[4] = x12
		outArr[5] = x13
		outArr[6] = x14
		outArr[7] = x15
	} else {
		binary.LittleEndian.PutUint32(out[0:4], x0)
		binary.LittleEndian.PutUint32(out[4:8], x1)
		binary.LittleEndian.PutUint32(out[8:12], x2)
		binary.LittleEndian.PutUint32(out[12:16], x3)
		binary.LittleEndian.PutUint32(out[16:20], x12)
		binary.LittleEndian.PutUint32(out[20:24], x13)
		binary.LittleEndian.PutUint32(out[24:28], x14)
		binary.LittleEndian.PutUint32(out[28:32], x15)
	}
	return
}
