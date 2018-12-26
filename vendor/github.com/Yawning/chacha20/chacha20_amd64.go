// chacha20_amd64.go - AMD64 optimized chacha20.
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to chacha20, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

// +build amd64,!gccgo,!appengine

package chacha20

import (
	"math"
)

var usingAVX2 = false

func blocksAmd64SSE2(x *uint32, inp, outp *byte, nrBlocks uint)

func blocksAmd64AVX2(x *uint32, inp, outp *byte, nrBlocks uint)

func cpuidAmd64(cpuidParams *uint32)

func xgetbv0Amd64(xcrVec *uint32)

func blocksAmd64(x *[stateSize]uint32, in []byte, out []byte, nrBlocks int, isIetf bool) {
	// Probably unneeded, but stating this explicitly simplifies the assembly.
	if nrBlocks == 0 {
		return
	}

	if isIetf {
		var totalBlocks uint64
		totalBlocks = uint64(x[12]) + uint64(nrBlocks)
		if totalBlocks > math.MaxUint32 {
			panic("chacha20: Exceeded keystream per nonce limit")
		}
	}

	if in == nil {
		for i := range out {
			out[i] = 0
		}
		in = out
	}

	// Pointless to call the AVX2 code for just a single block, since half of
	// the output gets discarded...
	if usingAVX2 && nrBlocks > 1 {
		blocksAmd64AVX2(&x[0], &in[0], &out[0], uint(nrBlocks))
	} else {
		blocksAmd64SSE2(&x[0], &in[0], &out[0], uint(nrBlocks))
	}
}

func supportsAVX2() bool {
	// https://software.intel.com/en-us/articles/how-to-detect-new-instruction-support-in-the-4th-generation-intel-core-processor-family
	const (
		osXsaveBit = 1 << 27
		avx2Bit    = 1 << 5
	)

	// Check to see if CPUID actually supports the leaf that indicates AVX2.
	// CPUID.(EAX=0H, ECX=0H) >= 7
	regs := [4]uint32{0x00}
	cpuidAmd64(&regs[0])
	if regs[0] < 7 {
		return false
	}

	// Check to see if the OS knows how to save/restore XMM/YMM state.
	// CPUID.(EAX=01H, ECX=0H):ECX.OSXSAVE[bit 27]==1
	regs = [4]uint32{0x01}
	cpuidAmd64(&regs[0])
	if regs[2]&osXsaveBit == 0 {
		return false
	}
	xcrRegs := [2]uint32{}
	xgetbv0Amd64(&xcrRegs[0])
	if xcrRegs[0]&6 != 6 {
		return false
	}

	// Check for AVX2 support.
	// CPUID.(EAX=07H, ECX=0H):EBX.AVX2[bit 5]==1
	regs = [4]uint32{0x07}
	cpuidAmd64(&regs[0])
	return regs[1]&avx2Bit != 0
}

func init() {
	blocksFn = blocksAmd64
	usingVectors = true
	usingAVX2 = supportsAVX2()
}
