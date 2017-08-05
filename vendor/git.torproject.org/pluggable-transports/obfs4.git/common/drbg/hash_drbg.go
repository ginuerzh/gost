/*
 * Copyright (c) 2014, Yawning Angel <yawning at torproject dot org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  * Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 *  * Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

// Package drbg implements a minimalistic DRBG based off SipHash-2-4 in OFB
// mode.
package drbg

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"

	"github.com/dchest/siphash"

	"git.torproject.org/pluggable-transports/obfs4.git/common/csrand"
)

// Size is the length of the HashDrbg output.
const Size = siphash.Size

// SeedLength is the length of the HashDrbg seed.
const SeedLength = 16 + Size

// Seed is the initial state for a HashDrbg.  It consists of a SipHash-2-4
// key, and 8 bytes of initial data.
type Seed [SeedLength]byte

// Bytes returns a pointer to the raw HashDrbg seed.
func (seed *Seed) Bytes() *[SeedLength]byte {
	return (*[SeedLength]byte)(seed)
}

// Hex returns the hexdecimal representation of the seed.
func (seed *Seed) Hex() string {
	return hex.EncodeToString(seed.Bytes()[:])
}

// NewSeed returns a Seed initialized with the runtime CSPRNG.
func NewSeed() (seed *Seed, err error) {
	seed = new(Seed)
	if err = csrand.Bytes(seed.Bytes()[:]); err != nil {
		return nil, err
	}

	return
}

// SeedFromBytes creates a Seed from the raw bytes, truncating to SeedLength as
// appropriate.
func SeedFromBytes(src []byte) (seed *Seed, err error) {
	if len(src) < SeedLength {
		return nil, InvalidSeedLengthError(len(src))
	}

	seed = new(Seed)
	copy(seed.Bytes()[:], src)

	return
}

// SeedFromHex creates a Seed from the hexdecimal representation, truncating to
// SeedLength as appropriate.
func SeedFromHex(encoded string) (seed *Seed, err error) {
	var raw []byte
	if raw, err = hex.DecodeString(encoded); err != nil {
		return nil, err
	}

	return SeedFromBytes(raw)
}

// InvalidSeedLengthError is the error returned when the seed provided to the
// DRBG is an invalid length.
type InvalidSeedLengthError int

func (e InvalidSeedLengthError) Error() string {
	return fmt.Sprintf("invalid seed length: %d", int(e))
}

// HashDrbg is a CSDRBG based off of SipHash-2-4 in OFB mode.
type HashDrbg struct {
	sip hash.Hash64
	ofb [Size]byte
}

// NewHashDrbg makes a HashDrbg instance based off an optional seed.  The seed
// is truncated to SeedLength.
func NewHashDrbg(seed *Seed) (*HashDrbg, error) {
	drbg := new(HashDrbg)
	if seed == nil {
		var err error
		if seed, err = NewSeed(); err != nil {
			return nil, err
		}
	}
	drbg.sip = siphash.New(seed.Bytes()[:16])
	copy(drbg.ofb[:], seed.Bytes()[16:])

	return drbg, nil
}

// Int63 returns a uniformly distributed random integer [0, 1 << 63).
func (drbg *HashDrbg) Int63() int64 {
	block := drbg.NextBlock()
	ret := binary.BigEndian.Uint64(block)
	ret &= (1<<63 - 1)

	return int64(ret)
}

// Seed does nothing, call NewHashDrbg if you want to reseed.
func (drbg *HashDrbg) Seed(seed int64) {
	// No-op.
}

// NextBlock returns the next 8 byte DRBG block.
func (drbg *HashDrbg) NextBlock() []byte {
	drbg.sip.Write(drbg.ofb[:])
	copy(drbg.ofb[:], drbg.sip.Sum(nil))

	ret := make([]byte, Size)
	copy(ret, drbg.ofb[:])
	return ret
}
