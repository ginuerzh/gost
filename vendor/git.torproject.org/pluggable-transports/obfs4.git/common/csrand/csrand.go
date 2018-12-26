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

// Package csrand implements the math/rand interface over crypto/rand, along
// with some utility functions for common random number/byte related tasks.
//
// Not all of the convinience routines are replicated, only those that are
// immediately useful.  The Rand variable provides access to the full math/rand
// API.
package csrand

import (
	cryptRand "crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
)

var (
	csRandSourceInstance csRandSource

	// Rand is a math/rand instance backed by crypto/rand CSPRNG.
	Rand = rand.New(csRandSourceInstance)
)

type csRandSource struct {
	// This does not keep any state as it is backed by crypto/rand.
}

func (r csRandSource) Int63() int64 {
	var src [8]byte
	if err := Bytes(src[:]); err != nil {
		panic(err)
	}
	val := binary.BigEndian.Uint64(src[:])
	val &= (1<<63 - 1)

	return int64(val)
}

func (r csRandSource) Seed(seed int64) {
	// No-op.
}

// Intn returns, as a int, a pseudo random number in [0, n).
func Intn(n int) int {
	return Rand.Intn(n)
}

// Float64 returns, as a float64, a pesudo random number in [0.0,1.0).
func Float64() float64 {
	return Rand.Float64()
}

// IntRange returns a uniformly distributed int [min, max].
func IntRange(min, max int) int {
	if max < min {
		panic(fmt.Sprintf("IntRange: min > max (%d, %d)", min, max))
	}

	r := (max + 1) - min
	ret := Rand.Intn(r)
	return ret + min
}

// Bytes fills the slice with random data.
func Bytes(buf []byte) error {
	if _, err := io.ReadFull(cryptRand.Reader, buf); err != nil {
		return err
	}

	return nil
}

// Reader is a alias of rand.Reader.
var Reader = cryptRand.Reader
