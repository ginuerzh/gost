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

//
// Package framing implements the obfs4 link framing and cryptography.
//
// The Encoder/Decoder shared secret format is:
//    uint8_t[32] NaCl secretbox key
//    uint8_t[16] NaCl Nonce prefix
//    uint8_t[16] SipHash-2-4 key (used to obfsucate length)
//    uint8_t[8]  SipHash-2-4 IV
//
// The frame format is:
//   uint16_t length (obfsucated, big endian)
//   NaCl secretbox (Poly1305/XSalsa20) containing:
//     uint8_t[16] tag (Part of the secretbox construct)
//     uint8_t[]   payload
//
// The length field is length of the NaCl secretbox XORed with the truncated
// SipHash-2-4 digest ran in OFB mode.
//
//     Initialize K, IV[0] with values from the shared secret.
//     On each packet, IV[n] = H(K, IV[n - 1])
//     mask[n] = IV[n][0:2]
//     obfsLen = length ^ mask[n]
//
// The NaCl secretbox (Poly1305/XSalsa20) nonce format is:
//     uint8_t[24] prefix (Fixed)
//     uint64_t    counter (Big endian)
//
// The counter is initialized to 1, and is incremented on each frame.  Since
// the protocol is designed to be used over a reliable medium, the nonce is not
// transmitted over the wire as both sides of the conversation know the prefix
// and the initial counter value.  It is imperative that the counter does not
// wrap, and sessions MUST terminate before 2^64 frames are sent.
//
package framing

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/nacl/secretbox"

	"git.torproject.org/pluggable-transports/obfs4.git/common/csrand"
	"git.torproject.org/pluggable-transports/obfs4.git/common/drbg"
)

const (
	// MaximumSegmentLength is the length of the largest possible segment
	// including overhead.
	MaximumSegmentLength = 1500 - (40 + 12)

	// FrameOverhead is the length of the framing overhead.
	FrameOverhead = lengthLength + secretbox.Overhead

	// MaximumFramePayloadLength is the length of the maximum allowed payload
	// per frame.
	MaximumFramePayloadLength = MaximumSegmentLength - FrameOverhead

	// KeyLength is the length of the Encoder/Decoder secret key.
	KeyLength = keyLength + noncePrefixLength + drbg.SeedLength

	maxFrameLength = MaximumSegmentLength - lengthLength
	minFrameLength = FrameOverhead - lengthLength

	keyLength = 32

	noncePrefixLength  = 16
	nonceCounterLength = 8
	nonceLength        = noncePrefixLength + nonceCounterLength

	lengthLength = 2
)

// Error returned when Decoder.Decode() requires more data to continue.
var ErrAgain = errors.New("framing: More data needed to decode")

// Error returned when Decoder.Decode() failes to authenticate a frame.
var ErrTagMismatch = errors.New("framing: Poly1305 tag mismatch")

// Error returned when the NaCl secretbox nonce's counter wraps (FATAL).
var ErrNonceCounterWrapped = errors.New("framing: Nonce counter wrapped")

// InvalidPayloadLengthError is the error returned when Encoder.Encode()
// rejects the payload length.
type InvalidPayloadLengthError int

func (e InvalidPayloadLengthError) Error() string {
	return fmt.Sprintf("framing: Invalid payload length: %d", int(e))
}

type boxNonce struct {
	prefix  [noncePrefixLength]byte
	counter uint64
}

func (nonce *boxNonce) init(prefix []byte) {
	if noncePrefixLength != len(prefix) {
		panic(fmt.Sprintf("BUG: Nonce prefix length invalid: %d", len(prefix)))
	}

	copy(nonce.prefix[:], prefix)
	nonce.counter = 1
}

func (nonce boxNonce) bytes(out *[nonceLength]byte) error {
	// The security guarantee of Poly1305 is broken if a nonce is ever reused
	// for a given key.  Detect this by checking for counter wraparound since
	// we start each counter at 1.  If it ever happens that more than 2^64 - 1
	// frames are transmitted over a given connection, support for rekeying
	// will be neccecary, but that's unlikely to happen.
	if nonce.counter == 0 {
		return ErrNonceCounterWrapped
	}

	copy(out[:], nonce.prefix[:])
	binary.BigEndian.PutUint64(out[noncePrefixLength:], nonce.counter)

	return nil
}

// Encoder is a frame encoder instance.
type Encoder struct {
	key   [keyLength]byte
	nonce boxNonce
	drbg  *drbg.HashDrbg
}

// NewEncoder creates a new Encoder instance.  It must be supplied a slice
// containing exactly KeyLength bytes of keying material.
func NewEncoder(key []byte) *Encoder {
	if len(key) != KeyLength {
		panic(fmt.Sprintf("BUG: Invalid encoder key length: %d", len(key)))
	}

	encoder := new(Encoder)
	copy(encoder.key[:], key[0:keyLength])
	encoder.nonce.init(key[keyLength : keyLength+noncePrefixLength])
	seed, err := drbg.SeedFromBytes(key[keyLength+noncePrefixLength:])
	if err != nil {
		panic(fmt.Sprintf("BUG: Failed to initialize DRBG: %s", err))
	}
	encoder.drbg, _ = drbg.NewHashDrbg(seed)

	return encoder
}

// Encode encodes a single frame worth of payload and returns the encoded
// length.  InvalidPayloadLengthError is recoverable, all other errors MUST be
// treated as fatal and the session aborted.
func (encoder *Encoder) Encode(frame, payload []byte) (n int, err error) {
	payloadLen := len(payload)
	if MaximumFramePayloadLength < payloadLen {
		return 0, InvalidPayloadLengthError(payloadLen)
	}
	if len(frame) < payloadLen+FrameOverhead {
		return 0, io.ErrShortBuffer
	}

	// Generate a new nonce.
	var nonce [nonceLength]byte
	if err = encoder.nonce.bytes(&nonce); err != nil {
		return 0, err
	}
	encoder.nonce.counter++

	// Encrypt and MAC payload.
	box := secretbox.Seal(frame[:lengthLength], payload, &nonce, &encoder.key)

	// Obfuscate the length.
	length := uint16(len(box) - lengthLength)
	lengthMask := encoder.drbg.NextBlock()
	length ^= binary.BigEndian.Uint16(lengthMask)
	binary.BigEndian.PutUint16(frame[:2], length)

	// Return the frame.
	return len(box), nil
}

// Decoder is a frame decoder instance.
type Decoder struct {
	key   [keyLength]byte
	nonce boxNonce
	drbg  *drbg.HashDrbg

	nextNonce         [nonceLength]byte
	nextLength        uint16
	nextLengthInvalid bool
}

// NewDecoder creates a new Decoder instance.  It must be supplied a slice
// containing exactly KeyLength bytes of keying material.
func NewDecoder(key []byte) *Decoder {
	if len(key) != KeyLength {
		panic(fmt.Sprintf("BUG: Invalid decoder key length: %d", len(key)))
	}

	decoder := new(Decoder)
	copy(decoder.key[:], key[0:keyLength])
	decoder.nonce.init(key[keyLength : keyLength+noncePrefixLength])
	seed, err := drbg.SeedFromBytes(key[keyLength+noncePrefixLength:])
	if err != nil {
		panic(fmt.Sprintf("BUG: Failed to initialize DRBG: %s", err))
	}
	decoder.drbg, _ = drbg.NewHashDrbg(seed)

	return decoder
}

// Decode decodes a stream of data and returns the length if any.  ErrAgain is
// a temporary failure, all other errors MUST be treated as fatal and the
// session aborted.
func (decoder *Decoder) Decode(data []byte, frames *bytes.Buffer) (int, error) {
	// A length of 0 indicates that we do not know how big the next frame is
	// going to be.
	if decoder.nextLength == 0 {
		// Attempt to pull out the next frame length.
		if lengthLength > frames.Len() {
			return 0, ErrAgain
		}

		// Remove the length field from the buffer.
		var obfsLen [lengthLength]byte
		_, err := io.ReadFull(frames, obfsLen[:])
		if err != nil {
			return 0, err
		}

		// Derive the nonce the peer used.
		if err = decoder.nonce.bytes(&decoder.nextNonce); err != nil {
			return 0, err
		}

		// Deobfuscate the length field.
		length := binary.BigEndian.Uint16(obfsLen[:])
		lengthMask := decoder.drbg.NextBlock()
		length ^= binary.BigEndian.Uint16(lengthMask)
		if maxFrameLength < length || minFrameLength > length {
			// Per "Plaintext Recovery Attacks Against SSH" by
			// Martin R. Albrecht, Kenneth G. Paterson and Gaven J. Watson,
			// there are a class of attacks againt protocols that use similar
			// sorts of framing schemes.
			//
			// While obfs4 should not allow plaintext recovery (CBC mode is
			// not used), attempt to mitigate out of bound frame length errors
			// by pretending that the length was a random valid range as per
			// the countermeasure suggested by Denis Bider in section 6 of the
			// paper.

			decoder.nextLengthInvalid = true
			length = uint16(csrand.IntRange(minFrameLength, maxFrameLength))
		}
		decoder.nextLength = length
	}

	if int(decoder.nextLength) > frames.Len() {
		return 0, ErrAgain
	}

	// Unseal the frame.
	var box [maxFrameLength]byte
	n, err := io.ReadFull(frames, box[:decoder.nextLength])
	if err != nil {
		return 0, err
	}
	out, ok := secretbox.Open(data[:0], box[:n], &decoder.nextNonce, &decoder.key)
	if !ok || decoder.nextLengthInvalid {
		// When a random length is used (on length error) the tag should always
		// mismatch, but be paranoid.
		return 0, ErrTagMismatch
	}

	// Clean up and prepare for the next frame.
	decoder.nextLength = 0
	decoder.nonce.counter++

	return len(out), nil
}
