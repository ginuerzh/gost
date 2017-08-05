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

// Package ntor implements the Tor Project's ntor handshake as defined in
// proposal 216 "Improved circuit-creation key exchange".  It also supports
// using Elligator to transform the Curve25519 public keys sent over the wire
// to a form that is indistinguishable from random strings.
//
// Before using this package, it is strongly recommended that the specification
// is read and understood.
package ntor

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"

	"github.com/agl/ed25519/extra25519"

	"git.torproject.org/pluggable-transports/obfs4.git/common/csrand"
)

const (
	// PublicKeyLength is the length of a Curve25519 public key.
	PublicKeyLength = 32

	// RepresentativeLength is the length of an Elligator representative.
	RepresentativeLength = 32

	// PrivateKeyLength is the length of a Curve25519 private key.
	PrivateKeyLength = 32

	// SharedSecretLength is the length of a Curve25519 shared secret.
	SharedSecretLength = 32

	// NodeIDLength is the length of a ntor node identifier.
	NodeIDLength = 20

	// KeySeedLength is the length of the derived KEY_SEED.
	KeySeedLength = sha256.Size

	// AuthLength is the lenght of the derived AUTH.
	AuthLength = sha256.Size
)

var protoID = []byte("ntor-curve25519-sha256-1")
var tMac = append(protoID, []byte(":mac")...)
var tKey = append(protoID, []byte(":key_extract")...)
var tVerify = append(protoID, []byte(":key_verify")...)
var mExpand = append(protoID, []byte(":key_expand")...)

// PublicKeyLengthError is the error returned when the public key being
// imported is an invalid length.
type PublicKeyLengthError int

func (e PublicKeyLengthError) Error() string {
	return fmt.Sprintf("ntor: Invalid Curve25519 public key length: %d",
		int(e))
}

// PrivateKeyLengthError is the error returned when the private key being
// imported is an invalid length.
type PrivateKeyLengthError int

func (e PrivateKeyLengthError) Error() string {
	return fmt.Sprintf("ntor: Invalid Curve25519 private key length: %d",
		int(e))
}

// NodeIDLengthError is the error returned when the node ID being imported is
// an invalid length.
type NodeIDLengthError int

func (e NodeIDLengthError) Error() string {
	return fmt.Sprintf("ntor: Invalid NodeID length: %d", int(e))
}

// KeySeed is the key material that results from a handshake (KEY_SEED).
type KeySeed [KeySeedLength]byte

// Bytes returns a pointer to the raw key material.
func (key_seed *KeySeed) Bytes() *[KeySeedLength]byte {
	return (*[KeySeedLength]byte)(key_seed)
}

// Auth is the verifier that results from a handshake (AUTH).
type Auth [AuthLength]byte

// Bytes returns a pointer to the raw auth.
func (auth *Auth) Bytes() *[AuthLength]byte {
	return (*[AuthLength]byte)(auth)
}

// NodeID is a ntor node identifier.
type NodeID [NodeIDLength]byte

// NewNodeID creates a NodeID from the raw bytes.
func NewNodeID(raw []byte) (*NodeID, error) {
	if len(raw) != NodeIDLength {
		return nil, NodeIDLengthError(len(raw))
	}

	nodeID := new(NodeID)
	copy(nodeID[:], raw)

	return nodeID, nil
}

// NodeIDFromHex creates a new NodeID from the hexdecimal representation.
func NodeIDFromHex(encoded string) (*NodeID, error) {
	raw, err := hex.DecodeString(encoded)
	if err != nil {
		return nil, err
	}

	return NewNodeID(raw)
}

// Bytes returns a pointer to the raw NodeID.
func (id *NodeID) Bytes() *[NodeIDLength]byte {
	return (*[NodeIDLength]byte)(id)
}

// Hex returns the hexdecimal representation of the NodeID.
func (id *NodeID) Hex() string {
	return hex.EncodeToString(id[:])
}

// PublicKey is a Curve25519 public key in little-endian byte order.
type PublicKey [PublicKeyLength]byte

// Bytes returns a pointer to the raw Curve25519 public key.
func (public *PublicKey) Bytes() *[PublicKeyLength]byte {
	return (*[PublicKeyLength]byte)(public)
}

// Hex returns the hexdecimal representation of the Curve25519 public key.
func (public *PublicKey) Hex() string {
	return hex.EncodeToString(public.Bytes()[:])
}

// NewPublicKey creates a PublicKey from the raw bytes.
func NewPublicKey(raw []byte) (*PublicKey, error) {
	if len(raw) != PublicKeyLength {
		return nil, PublicKeyLengthError(len(raw))
	}

	pubKey := new(PublicKey)
	copy(pubKey[:], raw)

	return pubKey, nil
}

// PublicKeyFromHex returns a PublicKey from the hexdecimal representation.
func PublicKeyFromHex(encoded string) (*PublicKey, error) {
	raw, err := hex.DecodeString(encoded)
	if err != nil {
		return nil, err
	}

	return NewPublicKey(raw)
}

// Representative is an Elligator representative of a Curve25519 public key
// in little-endian byte order.
type Representative [RepresentativeLength]byte

// Bytes returns a pointer to the raw Elligator representative.
func (repr *Representative) Bytes() *[RepresentativeLength]byte {
	return (*[RepresentativeLength]byte)(repr)
}

// ToPublic converts a Elligator representative to a Curve25519 public key.
func (repr *Representative) ToPublic() *PublicKey {
	pub := new(PublicKey)

	extra25519.RepresentativeToPublicKey(pub.Bytes(), repr.Bytes())
	return pub
}

// PrivateKey is a Curve25519 private key in little-endian byte order.
type PrivateKey [PrivateKeyLength]byte

// Bytes returns a pointer to the raw Curve25519 private key.
func (private *PrivateKey) Bytes() *[PrivateKeyLength]byte {
	return (*[PrivateKeyLength]byte)(private)
}

// Hex returns the hexdecimal representation of the Curve25519 private key.
func (private *PrivateKey) Hex() string {
	return hex.EncodeToString(private.Bytes()[:])
}

// Keypair is a Curve25519 keypair with an optional Elligator representative.
// As only certain Curve25519 keys can be obfuscated with Elligator, the
// representative must be generated along with the keypair.
type Keypair struct {
	public         *PublicKey
	private        *PrivateKey
	representative *Representative
}

// Public returns the Curve25519 public key belonging to the Keypair.
func (keypair *Keypair) Public() *PublicKey {
	return keypair.public
}

// Private returns the Curve25519 private key belonging to the Keypair.
func (keypair *Keypair) Private() *PrivateKey {
	return keypair.private
}

// Representative returns the Elligator representative of the public key
// belonging to the Keypair.
func (keypair *Keypair) Representative() *Representative {
	return keypair.representative
}

// HasElligator returns true if the Keypair has an Elligator representative.
func (keypair *Keypair) HasElligator() bool {
	return nil != keypair.representative
}

// NewKeypair generates a new Curve25519 keypair, and optionally also generates
// an Elligator representative of the public key.
func NewKeypair(elligator bool) (*Keypair, error) {
	keypair := new(Keypair)
	keypair.private = new(PrivateKey)
	keypair.public = new(PublicKey)
	if elligator {
		keypair.representative = new(Representative)
	}

	for {
		// Generate a Curve25519 private key.  Like everyone who does this,
		// run the CSPRNG output through SHA256 for extra tinfoil hattery.
		priv := keypair.private.Bytes()[:]
		if err := csrand.Bytes(priv); err != nil {
			return nil, err
		}
		digest := sha256.Sum256(priv)
		digest[0] &= 248
		digest[31] &= 127
		digest[31] |= 64
		copy(priv, digest[:])

		if elligator {
			// Apply the Elligator transform.  This fails ~50% of the time.
			if !extra25519.ScalarBaseMult(keypair.public.Bytes(),
				keypair.representative.Bytes(),
				keypair.private.Bytes()) {
				continue
			}
		} else {
			// Generate the corresponding Curve25519 public key.
			curve25519.ScalarBaseMult(keypair.public.Bytes(),
				keypair.private.Bytes())
		}

		return keypair, nil
	}
}

// KeypairFromHex returns a Keypair from the hexdecimal representation of the
// private key.
func KeypairFromHex(encoded string) (*Keypair, error) {
	raw, err := hex.DecodeString(encoded)
	if err != nil {
		return nil, err
	}

	if len(raw) != PrivateKeyLength {
		return nil, PrivateKeyLengthError(len(raw))
	}

	keypair := new(Keypair)
	keypair.private = new(PrivateKey)
	keypair.public = new(PublicKey)

	copy(keypair.private[:], raw)
	curve25519.ScalarBaseMult(keypair.public.Bytes(),
		keypair.private.Bytes())

	return keypair, nil
}

// ServerHandshake does the server side of a ntor handshake and returns status,
// KEY_SEED, and AUTH.  If status is not true, the handshake MUST be aborted.
func ServerHandshake(clientPublic *PublicKey, serverKeypair *Keypair, idKeypair *Keypair, id *NodeID) (ok bool, keySeed *KeySeed, auth *Auth) {
	var notOk int
	var secretInput bytes.Buffer

	// Server side uses EXP(X,y) | EXP(X,b)
	var exp [SharedSecretLength]byte
	curve25519.ScalarMult(&exp, serverKeypair.private.Bytes(),
		clientPublic.Bytes())
	notOk |= constantTimeIsZero(exp[:])
	secretInput.Write(exp[:])

	curve25519.ScalarMult(&exp, idKeypair.private.Bytes(),
		clientPublic.Bytes())
	notOk |= constantTimeIsZero(exp[:])
	secretInput.Write(exp[:])

	keySeed, auth = ntorCommon(secretInput, id, idKeypair.public,
		clientPublic, serverKeypair.public)
	return notOk == 0, keySeed, auth
}

// ClientHandshake does the client side of a ntor handshake and returnes
// status, KEY_SEED, and AUTH.  If status is not true or AUTH does not match
// the value recieved from the server, the handshake MUST be aborted.
func ClientHandshake(clientKeypair *Keypair, serverPublic *PublicKey, idPublic *PublicKey, id *NodeID) (ok bool, keySeed *KeySeed, auth *Auth) {
	var notOk int
	var secretInput bytes.Buffer

	// Client side uses EXP(Y,x) | EXP(B,x)
	var exp [SharedSecretLength]byte
	curve25519.ScalarMult(&exp, clientKeypair.private.Bytes(),
		serverPublic.Bytes())
	notOk |= constantTimeIsZero(exp[:])
	secretInput.Write(exp[:])

	curve25519.ScalarMult(&exp, clientKeypair.private.Bytes(),
		idPublic.Bytes())
	notOk |= constantTimeIsZero(exp[:])
	secretInput.Write(exp[:])

	keySeed, auth = ntorCommon(secretInput, id, idPublic,
		clientKeypair.public, serverPublic)
	return notOk == 0, keySeed, auth
}

// CompareAuth does a constant time compare of a Auth and a byte slice
// (presumably received over a network).
func CompareAuth(auth1 *Auth, auth2 []byte) bool {
	auth1Bytes := auth1.Bytes()
	return hmac.Equal(auth1Bytes[:], auth2)
}

func ntorCommon(secretInput bytes.Buffer, id *NodeID, b *PublicKey, x *PublicKey, y *PublicKey) (*KeySeed, *Auth) {
	keySeed := new(KeySeed)
	auth := new(Auth)

	// secret_input/auth_input use this common bit, build it once.
	suffix := bytes.NewBuffer(b.Bytes()[:])
	suffix.Write(b.Bytes()[:])
	suffix.Write(x.Bytes()[:])
	suffix.Write(y.Bytes()[:])
	suffix.Write(protoID)
	suffix.Write(id[:])

	// At this point secret_input has the 2 exponents, concatenated, append the
	// client/server common suffix.
	secretInput.Write(suffix.Bytes())

	// KEY_SEED = H(secret_input, t_key)
	h := hmac.New(sha256.New, tKey)
	h.Write(secretInput.Bytes())
	tmp := h.Sum(nil)
	copy(keySeed[:], tmp)

	// verify = H(secret_input, t_verify)
	h = hmac.New(sha256.New, tVerify)
	h.Write(secretInput.Bytes())
	verify := h.Sum(nil)

	// auth_input = verify | ID | B | Y | X | PROTOID | "Server"
	authInput := bytes.NewBuffer(verify)
	authInput.Write(suffix.Bytes())
	authInput.Write([]byte("Server"))
	h = hmac.New(sha256.New, tMac)
	h.Write(authInput.Bytes())
	tmp = h.Sum(nil)
	copy(auth[:], tmp)

	return keySeed, auth
}

func constantTimeIsZero(x []byte) int {
	var ret byte
	for _, v := range x {
		ret |= v
	}

	return subtle.ConstantTimeByteEq(ret, 0)
}

// Kdf extracts and expands KEY_SEED via HKDF-SHA256 and returns `okm_len` bytes
// of key material.
func Kdf(keySeed []byte, okmLen int) []byte {
	kdf := hkdf.New(sha256.New, keySeed, tKey, mExpand)
	okm := make([]byte, okmLen)
	n, err := io.ReadFull(kdf, okm)
	if err != nil {
		panic(fmt.Sprintf("BUG: Failed HKDF: %s", err.Error()))
	} else if n != len(okm) {
		panic(fmt.Sprintf("BUG: Got truncated HKDF output: %d", n))
	}

	return okm
}
