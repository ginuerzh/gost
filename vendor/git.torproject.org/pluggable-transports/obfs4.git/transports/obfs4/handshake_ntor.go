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

package obfs4

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"strconv"
	"time"

	"git.torproject.org/pluggable-transports/obfs4.git/common/csrand"
	"git.torproject.org/pluggable-transports/obfs4.git/common/ntor"
	"git.torproject.org/pluggable-transports/obfs4.git/common/replayfilter"
	"git.torproject.org/pluggable-transports/obfs4.git/transports/obfs4/framing"
)

const (
	maxHandshakeLength = 8192

	clientMinPadLength = (serverMinHandshakeLength + inlineSeedFrameLength) -
		clientMinHandshakeLength
	clientMaxPadLength       = maxHandshakeLength - clientMinHandshakeLength
	clientMinHandshakeLength = ntor.RepresentativeLength + markLength + macLength

	serverMinPadLength = 0
	serverMaxPadLength = maxHandshakeLength - (serverMinHandshakeLength +
		inlineSeedFrameLength)
	serverMinHandshakeLength = ntor.RepresentativeLength + ntor.AuthLength +
		markLength + macLength

	markLength = sha256.Size / 2
	macLength  = sha256.Size / 2

	inlineSeedFrameLength = framing.FrameOverhead + packetOverhead + seedPacketPayloadLength
)

// ErrMarkNotFoundYet is the error returned when the obfs4 handshake is
// incomplete and requires more data to continue.  This error is non-fatal and
// is the equivalent to EAGAIN/EWOULDBLOCK.
var ErrMarkNotFoundYet = errors.New("handshake: M_[C,S] not found yet")

// ErrInvalidHandshake is the error returned when the obfs4 handshake fails due
// to the peer not sending the correct mark.  This error is fatal and the
// connection MUST be dropped.
var ErrInvalidHandshake = errors.New("handshake: Failed to find M_[C,S]")

// ErrReplayedHandshake is the error returned when the obfs4 handshake fails
// due it being replayed.  This error is fatal and the connection MUST be
// dropped.
var ErrReplayedHandshake = errors.New("handshake: Replay detected")

// ErrNtorFailed is the error returned when the ntor handshake fails.  This
// error is fatal and the connection MUST be dropped.
var ErrNtorFailed = errors.New("handshake: ntor handshake failure")

// InvalidMacError is the error returned when the handshake MACs do not match.
// This error is fatal and the connection MUST be dropped.
type InvalidMacError struct {
	Derived  []byte
	Received []byte
}

func (e *InvalidMacError) Error() string {
	return fmt.Sprintf("handshake: MAC mismatch: Dervied: %s Received: %s.",
		hex.EncodeToString(e.Derived), hex.EncodeToString(e.Received))
}

// InvalidAuthError is the error returned when the ntor AUTH tags do not match.
// This error is fatal and the connection MUST be dropped.
type InvalidAuthError struct {
	Derived  *ntor.Auth
	Received *ntor.Auth
}

func (e *InvalidAuthError) Error() string {
	return fmt.Sprintf("handshake: ntor AUTH mismatch: Derived: %s Received:%s.",
		hex.EncodeToString(e.Derived.Bytes()[:]),
		hex.EncodeToString(e.Received.Bytes()[:]))
}

type clientHandshake struct {
	keypair        *ntor.Keypair
	nodeID         *ntor.NodeID
	serverIdentity *ntor.PublicKey
	epochHour      []byte

	padLen int
	mac    hash.Hash

	serverRepresentative *ntor.Representative
	serverAuth           *ntor.Auth
	serverMark           []byte
}

func newClientHandshake(nodeID *ntor.NodeID, serverIdentity *ntor.PublicKey, sessionKey *ntor.Keypair) *clientHandshake {
	hs := new(clientHandshake)
	hs.keypair = sessionKey
	hs.nodeID = nodeID
	hs.serverIdentity = serverIdentity
	hs.padLen = csrand.IntRange(clientMinPadLength, clientMaxPadLength)
	hs.mac = hmac.New(sha256.New, append(hs.serverIdentity.Bytes()[:], hs.nodeID.Bytes()[:]...))

	return hs
}

func (hs *clientHandshake) generateHandshake() ([]byte, error) {
	var buf bytes.Buffer

	hs.mac.Reset()
	hs.mac.Write(hs.keypair.Representative().Bytes()[:])
	mark := hs.mac.Sum(nil)[:markLength]

	// The client handshake is X | P_C | M_C | MAC(X | P_C | M_C | E) where:
	//  * X is the client's ephemeral Curve25519 public key representative.
	//  * P_C is [clientMinPadLength,clientMaxPadLength] bytes of random padding.
	//  * M_C is HMAC-SHA256-128(serverIdentity | NodeID, X)
	//  * MAC is HMAC-SHA256-128(serverIdentity | NodeID, X .... E)
	//  * E is the string representation of the number of hours since the UNIX
	//    epoch.

	// Generate the padding
	pad, err := makePad(hs.padLen)
	if err != nil {
		return nil, err
	}

	// Write X, P_C, M_C.
	buf.Write(hs.keypair.Representative().Bytes()[:])
	buf.Write(pad)
	buf.Write(mark)

	// Calculate and write the MAC.
	hs.mac.Reset()
	hs.mac.Write(buf.Bytes())
	hs.epochHour = []byte(strconv.FormatInt(getEpochHour(), 10))
	hs.mac.Write(hs.epochHour)
	buf.Write(hs.mac.Sum(nil)[:macLength])

	return buf.Bytes(), nil
}

func (hs *clientHandshake) parseServerHandshake(resp []byte) (int, []byte, error) {
	// No point in examining the data unless the miminum plausible response has
	// been received.
	if serverMinHandshakeLength > len(resp) {
		return 0, nil, ErrMarkNotFoundYet
	}

	if hs.serverRepresentative == nil || hs.serverAuth == nil {
		// Pull out the representative/AUTH. (XXX: Add ctors to ntor)
		hs.serverRepresentative = new(ntor.Representative)
		copy(hs.serverRepresentative.Bytes()[:], resp[0:ntor.RepresentativeLength])
		hs.serverAuth = new(ntor.Auth)
		copy(hs.serverAuth.Bytes()[:], resp[ntor.RepresentativeLength:])

		// Derive the mark.
		hs.mac.Reset()
		hs.mac.Write(hs.serverRepresentative.Bytes()[:])
		hs.serverMark = hs.mac.Sum(nil)[:markLength]
	}

	// Attempt to find the mark + MAC.
	pos := findMarkMac(hs.serverMark, resp, ntor.RepresentativeLength+ntor.AuthLength+serverMinPadLength,
		maxHandshakeLength, false)
	if pos == -1 {
		if len(resp) >= maxHandshakeLength {
			return 0, nil, ErrInvalidHandshake
		}
		return 0, nil, ErrMarkNotFoundYet
	}

	// Validate the MAC.
	hs.mac.Reset()
	hs.mac.Write(resp[:pos+markLength])
	hs.mac.Write(hs.epochHour)
	macCmp := hs.mac.Sum(nil)[:macLength]
	macRx := resp[pos+markLength : pos+markLength+macLength]
	if !hmac.Equal(macCmp, macRx) {
		return 0, nil, &InvalidMacError{macCmp, macRx}
	}

	// Complete the handshake.
	serverPublic := hs.serverRepresentative.ToPublic()
	ok, seed, auth := ntor.ClientHandshake(hs.keypair, serverPublic,
		hs.serverIdentity, hs.nodeID)
	if !ok {
		return 0, nil, ErrNtorFailed
	}
	if !ntor.CompareAuth(auth, hs.serverAuth.Bytes()[:]) {
		return 0, nil, &InvalidAuthError{auth, hs.serverAuth}
	}

	return pos + markLength + macLength, seed.Bytes()[:], nil
}

type serverHandshake struct {
	keypair        *ntor.Keypair
	nodeID         *ntor.NodeID
	serverIdentity *ntor.Keypair
	epochHour      []byte
	serverAuth     *ntor.Auth

	padLen int
	mac    hash.Hash

	clientRepresentative *ntor.Representative
	clientMark           []byte
}

func newServerHandshake(nodeID *ntor.NodeID, serverIdentity *ntor.Keypair, sessionKey *ntor.Keypair) *serverHandshake {
	hs := new(serverHandshake)
	hs.keypair = sessionKey
	hs.nodeID = nodeID
	hs.serverIdentity = serverIdentity
	hs.padLen = csrand.IntRange(serverMinPadLength, serverMaxPadLength)
	hs.mac = hmac.New(sha256.New, append(hs.serverIdentity.Public().Bytes()[:], hs.nodeID.Bytes()[:]...))

	return hs
}

func (hs *serverHandshake) parseClientHandshake(filter *replayfilter.ReplayFilter, resp []byte) ([]byte, error) {
	// No point in examining the data unless the miminum plausible response has
	// been received.
	if clientMinHandshakeLength > len(resp) {
		return nil, ErrMarkNotFoundYet
	}

	if hs.clientRepresentative == nil {
		// Pull out the representative/AUTH. (XXX: Add ctors to ntor)
		hs.clientRepresentative = new(ntor.Representative)
		copy(hs.clientRepresentative.Bytes()[:], resp[0:ntor.RepresentativeLength])

		// Derive the mark.
		hs.mac.Reset()
		hs.mac.Write(hs.clientRepresentative.Bytes()[:])
		hs.clientMark = hs.mac.Sum(nil)[:markLength]
	}

	// Attempt to find the mark + MAC.
	pos := findMarkMac(hs.clientMark, resp, ntor.RepresentativeLength+clientMinPadLength,
		maxHandshakeLength, true)
	if pos == -1 {
		if len(resp) >= maxHandshakeLength {
			return nil, ErrInvalidHandshake
		}
		return nil, ErrMarkNotFoundYet
	}

	// Validate the MAC.
	macFound := false
	for _, off := range []int64{0, -1, 1} {
		// Allow epoch to be off by up to a hour in either direction.
		epochHour := []byte(strconv.FormatInt(getEpochHour()+int64(off), 10))
		hs.mac.Reset()
		hs.mac.Write(resp[:pos+markLength])
		hs.mac.Write(epochHour)
		macCmp := hs.mac.Sum(nil)[:macLength]
		macRx := resp[pos+markLength : pos+markLength+macLength]
		if hmac.Equal(macCmp, macRx) {
			// Ensure that this handshake has not been seen previously.
			if filter.TestAndSet(time.Now(), macRx) {
				// The client either happened to generate exactly the same
				// session key and padding, or someone is replaying a previous
				// handshake.  In either case, fuck them.
				return nil, ErrReplayedHandshake
			}

			macFound = true
			hs.epochHour = epochHour

			// We could break out here, but in the name of reducing timing
			// variation, evaluate all 3 MACs.
		}
	}
	if !macFound {
		// This probably should be an InvalidMacError, but conveying the 3 MACS
		// that would be accepted is annoying so just return a generic fatal
		// failure.
		return nil, ErrInvalidHandshake
	}

	// Client should never sent trailing garbage.
	if len(resp) != pos+markLength+macLength {
		return nil, ErrInvalidHandshake
	}

	clientPublic := hs.clientRepresentative.ToPublic()
	ok, seed, auth := ntor.ServerHandshake(clientPublic, hs.keypair,
		hs.serverIdentity, hs.nodeID)
	if !ok {
		return nil, ErrNtorFailed
	}
	hs.serverAuth = auth

	return seed.Bytes()[:], nil
}

func (hs *serverHandshake) generateHandshake() ([]byte, error) {
	var buf bytes.Buffer

	hs.mac.Reset()
	hs.mac.Write(hs.keypair.Representative().Bytes()[:])
	mark := hs.mac.Sum(nil)[:markLength]

	// The server handshake is Y | AUTH | P_S | M_S | MAC(Y | AUTH | P_S | M_S | E) where:
	//  * Y is the server's ephemeral Curve25519 public key representative.
	//  * AUTH is the ntor handshake AUTH value.
	//  * P_S is [serverMinPadLength,serverMaxPadLength] bytes of random padding.
	//  * M_S is HMAC-SHA256-128(serverIdentity | NodeID, Y)
	//  * MAC is HMAC-SHA256-128(serverIdentity | NodeID, Y .... E)
	//  * E is the string representation of the number of hours since the UNIX
	//    epoch.

	// Generate the padding
	pad, err := makePad(hs.padLen)
	if err != nil {
		return nil, err
	}

	// Write Y, AUTH, P_S, M_S.
	buf.Write(hs.keypair.Representative().Bytes()[:])
	buf.Write(hs.serverAuth.Bytes()[:])
	buf.Write(pad)
	buf.Write(mark)

	// Calculate and write the MAC.
	hs.mac.Reset()
	hs.mac.Write(buf.Bytes())
	hs.mac.Write(hs.epochHour) // Set in hs.parseClientHandshake()
	buf.Write(hs.mac.Sum(nil)[:macLength])

	return buf.Bytes(), nil
}

// getEpochHour returns the number of hours since the UNIX epoch.
func getEpochHour() int64 {
	return time.Now().Unix() / 3600
}

func findMarkMac(mark, buf []byte, startPos, maxPos int, fromTail bool) (pos int) {
	if len(mark) != markLength {
		panic(fmt.Sprintf("BUG: Invalid mark length: %d", len(mark)))
	}

	endPos := len(buf)
	if startPos > len(buf) {
		return -1
	}
	if endPos > maxPos {
		endPos = maxPos
	}
	if endPos-startPos < markLength+macLength {
		return -1
	}

	if fromTail {
		// The server can optimize the search process by only examining the
		// tail of the buffer.  The client can't send valid data past M_C |
		// MAC_C as it does not have the server's public key yet.
		pos = endPos - (markLength + macLength)
		if !hmac.Equal(buf[pos:pos+markLength], mark) {
			return -1
		}

		return
	}

	// The client has to actually do a substring search since the server can
	// and will send payload trailing the response.
	//
	// XXX: bytes.Index() uses a naive search, which kind of sucks.
	pos = bytes.Index(buf[startPos:endPos], mark)
	if pos == -1 {
		return -1
	}

	// Ensure that there is enough trailing data for the MAC.
	if startPos+pos+markLength+macLength > endPos {
		return -1
	}

	// Return the index relative to the start of the slice.
	pos += startPos
	return
}

func makePad(padLen int) ([]byte, error) {
	pad := make([]byte, padLen)
	if err := csrand.Bytes(pad); err != nil {
		return nil, err
	}

	return pad, nil
}
