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

// Package replayfilter implements a generic replay detection filter with a
// caller specifiable time-to-live.  It only detects if a given byte sequence
// has been seen before based on the SipHash-2-4 digest of the sequence.
// Collisions are treated as positive matches, though the probability of this
// happening is negligible.
package replayfilter

import (
	"container/list"
	"encoding/binary"
	"sync"
	"time"

	"github.com/dchest/siphash"

	"git.torproject.org/pluggable-transports/obfs4.git/common/csrand"
)

// maxFilterSize is the maximum capacity of a replay filter.  This value is
// more as a safeguard to prevent runaway filter growth, and is sized to be
// serveral orders of magnitude greater than the number of connections a busy
// bridge sees in one day, so in practice should never be reached.
const maxFilterSize = 100 * 1024

type entry struct {
	digest    uint64
	firstSeen time.Time
	element   *list.Element
}

// ReplayFilter is a simple filter designed only to detect if a given byte
// sequence has been seen before.
type ReplayFilter struct {
	sync.Mutex

	filter map[uint64]*entry
	fifo   *list.List

	key [2]uint64
	ttl time.Duration
}

// New creates a new ReplayFilter instance.
func New(ttl time.Duration) (filter *ReplayFilter, err error) {
	// Initialize the SipHash-2-4 instance with a random key.
	var key [16]byte
	if err = csrand.Bytes(key[:]); err != nil {
		return
	}

	filter = new(ReplayFilter)
	filter.filter = make(map[uint64]*entry)
	filter.fifo = list.New()
	filter.key[0] = binary.BigEndian.Uint64(key[0:8])
	filter.key[1] = binary.BigEndian.Uint64(key[8:16])
	filter.ttl = ttl

	return
}

// TestAndSet queries the filter for a given byte sequence, inserts the
// sequence, and returns if it was present before the insertion operation.
func (f *ReplayFilter) TestAndSet(now time.Time, buf []byte) bool {
	digest := siphash.Hash(f.key[0], f.key[1], buf)

	f.Lock()
	defer f.Unlock()

	f.compactFilter(now)

	if e := f.filter[digest]; e != nil {
		// Hit.  Just return.
		return true
	}

	// Miss.  Add a new entry.
	e := new(entry)
	e.digest = digest
	e.firstSeen = now
	e.element = f.fifo.PushBack(e)
	f.filter[digest] = e

	return false
}

func (f *ReplayFilter) compactFilter(now time.Time) {
	e := f.fifo.Front()
	for e != nil {
		ent, _ := e.Value.(*entry)

		// If the filter is not full, only purge entries that exceed the TTL,
		// otherwise purge at least one entry, then revert to TTL based
		// compaction.
		if f.fifo.Len() < maxFilterSize && f.ttl > 0 {
			deltaT := now.Sub(ent.firstSeen)
			if deltaT < 0 {
				// Aeeeeeee, the system time jumped backwards, potentially by
				// a lot.  This will eventually self-correct, but "eventually"
				// could be a long time.  As much as this sucks, jettison the
				// entire filter.
				f.reset()
				return
			} else if deltaT < f.ttl {
				return
			}
		}

		// Remove the eldest entry.
		eNext := e.Next()
		delete(f.filter, ent.digest)
		f.fifo.Remove(ent.element)
		ent.element = nil
		e = eNext
	}
}

func (f *ReplayFilter) reset() {
	f.filter = make(map[uint64]*entry)
	f.fifo = list.New()
}
