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

// Package obfs4 provides an implementation of the Tor Project's obfs4
// obfuscation protocol.
package obfs4

import (
	"bytes"
	"crypto/sha256"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"syscall"
	"time"

	"git.torproject.org/pluggable-transports/goptlib.git"
	"git.torproject.org/pluggable-transports/obfs4.git/common/drbg"
	"git.torproject.org/pluggable-transports/obfs4.git/common/ntor"
	"git.torproject.org/pluggable-transports/obfs4.git/common/probdist"
	"git.torproject.org/pluggable-transports/obfs4.git/common/replayfilter"
	"git.torproject.org/pluggable-transports/obfs4.git/transports/base"
	"git.torproject.org/pluggable-transports/obfs4.git/transports/obfs4/framing"
)

const (
	transportName = "obfs4"

	nodeIDArg     = "node-id"
	publicKeyArg  = "public-key"
	privateKeyArg = "private-key"
	seedArg       = "drbg-seed"
	iatArg        = "iat-mode"
	certArg       = "cert"

	biasCmdArg = "obfs4-distBias"

	seedLength             = drbg.SeedLength
	headerLength           = framing.FrameOverhead + packetOverhead
	clientHandshakeTimeout = time.Duration(60) * time.Second
	serverHandshakeTimeout = time.Duration(30) * time.Second
	replayTTL              = time.Duration(3) * time.Hour

	maxIATDelay        = 100
	maxCloseDelayBytes = maxHandshakeLength
	maxCloseDelay      = 60
)

const (
	iatNone = iota
	iatEnabled
	iatParanoid
)

// biasedDist controls if the probability table will be ScrambleSuit style or
// uniformly distributed.
var biasedDist bool

type obfs4ClientArgs struct {
	nodeID     *ntor.NodeID
	publicKey  *ntor.PublicKey
	sessionKey *ntor.Keypair
	iatMode    int
}

// Transport is the obfs4 implementation of the base.Transport interface.
type Transport struct{}

// Name returns the name of the obfs4 transport protocol.
func (t *Transport) Name() string {
	return transportName
}

// ClientFactory returns a new obfs4ClientFactory instance.
func (t *Transport) ClientFactory(stateDir string) (base.ClientFactory, error) {
	cf := &obfs4ClientFactory{transport: t}
	return cf, nil
}

// ServerFactory returns a new obfs4ServerFactory instance.
func (t *Transport) ServerFactory(stateDir string, args *pt.Args) (base.ServerFactory, error) {
	st, err := serverStateFromArgs(stateDir, args)
	if err != nil {
		return nil, err
	}

	var iatSeed *drbg.Seed
	if st.iatMode != iatNone {
		iatSeedSrc := sha256.Sum256(st.drbgSeed.Bytes()[:])
		var err error
		iatSeed, err = drbg.SeedFromBytes(iatSeedSrc[:])
		if err != nil {
			return nil, err
		}
	}

	// Store the arguments that should appear in our descriptor for the clients.
	ptArgs := pt.Args{}
	ptArgs.Add(certArg, st.cert.String())
	ptArgs.Add(iatArg, strconv.Itoa(st.iatMode))

	// Initialize the replay filter.
	filter, err := replayfilter.New(replayTTL)
	if err != nil {
		return nil, err
	}

	// Initialize the close thresholds for failed connections.
	drbg, err := drbg.NewHashDrbg(st.drbgSeed)
	if err != nil {
		return nil, err
	}
	rng := rand.New(drbg)

	sf := &obfs4ServerFactory{t, &ptArgs, st.nodeID, st.identityKey, st.drbgSeed, iatSeed, st.iatMode, filter, rng.Intn(maxCloseDelayBytes), rng.Intn(maxCloseDelay)}
	return sf, nil
}

type obfs4ClientFactory struct {
	transport base.Transport
}

func (cf *obfs4ClientFactory) Transport() base.Transport {
	return cf.transport
}

func (cf *obfs4ClientFactory) ParseArgs(args *pt.Args) (interface{}, error) {
	var nodeID *ntor.NodeID
	var publicKey *ntor.PublicKey

	// The "new" (version >= 0.0.3) bridge lines use a unified "cert" argument
	// for the Node ID and Public Key.
	certStr, ok := args.Get(certArg)
	if ok {
		cert, err := serverCertFromString(certStr)
		if err != nil {
			return nil, err
		}
		nodeID, publicKey = cert.unpack()
	} else {
		// The "old" style (version <= 0.0.2) bridge lines use separate Node ID
		// and Public Key arguments in Base16 encoding and are a UX disaster.
		nodeIDStr, ok := args.Get(nodeIDArg)
		if !ok {
			return nil, fmt.Errorf("missing argument '%s'", nodeIDArg)
		}
		var err error
		if nodeID, err = ntor.NodeIDFromHex(nodeIDStr); err != nil {
			return nil, err
		}

		publicKeyStr, ok := args.Get(publicKeyArg)
		if !ok {
			return nil, fmt.Errorf("missing argument '%s'", publicKeyArg)
		}
		if publicKey, err = ntor.PublicKeyFromHex(publicKeyStr); err != nil {
			return nil, err
		}
	}

	// IAT config is common across the two bridge line formats.
	iatStr, ok := args.Get(iatArg)
	if !ok {
		return nil, fmt.Errorf("missing argument '%s'", iatArg)
	}
	iatMode, err := strconv.Atoi(iatStr)
	if err != nil || iatMode < iatNone || iatMode > iatParanoid {
		return nil, fmt.Errorf("invalid iat-mode '%d'", iatMode)
	}

	// Generate the session key pair before connectiong to hide the Elligator2
	// rejection sampling from network observers.
	sessionKey, err := ntor.NewKeypair(true)
	if err != nil {
		return nil, err
	}

	return &obfs4ClientArgs{nodeID, publicKey, sessionKey, iatMode}, nil
}

func (cf *obfs4ClientFactory) Dial(network, addr string, dialFn base.DialFunc, args interface{}) (net.Conn, error) {
	// Validate args before bothering to open connection.
	ca, ok := args.(*obfs4ClientArgs)
	if !ok {
		return nil, fmt.Errorf("invalid argument type for args")
	}
	conn, err := dialFn(network, addr)
	if err != nil {
		return nil, err
	}
	dialConn := conn
	if conn, err = newObfs4ClientConn(conn, ca); err != nil {
		dialConn.Close()
		return nil, err
	}
	return conn, nil
}

type obfs4ServerFactory struct {
	transport base.Transport
	args      *pt.Args

	nodeID       *ntor.NodeID
	identityKey  *ntor.Keypair
	lenSeed      *drbg.Seed
	iatSeed      *drbg.Seed
	iatMode      int
	replayFilter *replayfilter.ReplayFilter

	closeDelayBytes int
	closeDelay      int
}

func (sf *obfs4ServerFactory) Transport() base.Transport {
	return sf.transport
}

func (sf *obfs4ServerFactory) Args() *pt.Args {
	return sf.args
}

func (sf *obfs4ServerFactory) WrapConn(conn net.Conn) (net.Conn, error) {
	// Not much point in having a separate newObfs4ServerConn routine when
	// wrapping requires using values from the factory instance.

	// Generate the session keypair *before* consuming data from the peer, to
	// attempt to mask the rejection sampling due to use of Elligator2.  This
	// might be futile, but the timing differential isn't very large on modern
	// hardware, and there are far easier statistical attacks that can be
	// mounted as a distinguisher.
	sessionKey, err := ntor.NewKeypair(true)
	if err != nil {
		return nil, err
	}

	lenDist := probdist.New(sf.lenSeed, 0, framing.MaximumSegmentLength, biasedDist)
	var iatDist *probdist.WeightedDist
	if sf.iatSeed != nil {
		iatDist = probdist.New(sf.iatSeed, 0, maxIATDelay, biasedDist)
	}

	c := &obfs4Conn{conn, true, lenDist, iatDist, sf.iatMode, bytes.NewBuffer(nil), bytes.NewBuffer(nil), make([]byte, consumeReadSize), nil, nil}

	startTime := time.Now()

	if err = c.serverHandshake(sf, sessionKey); err != nil {
		c.closeAfterDelay(sf, startTime)
		return nil, err
	}

	return c, nil
}

type obfs4Conn struct {
	net.Conn

	isServer bool

	lenDist *probdist.WeightedDist
	iatDist *probdist.WeightedDist
	iatMode int

	receiveBuffer        *bytes.Buffer
	receiveDecodedBuffer *bytes.Buffer
	readBuffer           []byte

	encoder *framing.Encoder
	decoder *framing.Decoder
}

func newObfs4ClientConn(conn net.Conn, args *obfs4ClientArgs) (c *obfs4Conn, err error) {
	// Generate the initial protocol polymorphism distribution(s).
	var seed *drbg.Seed
	if seed, err = drbg.NewSeed(); err != nil {
		return
	}
	lenDist := probdist.New(seed, 0, framing.MaximumSegmentLength, biasedDist)
	var iatDist *probdist.WeightedDist
	if args.iatMode != iatNone {
		var iatSeed *drbg.Seed
		iatSeedSrc := sha256.Sum256(seed.Bytes()[:])
		if iatSeed, err = drbg.SeedFromBytes(iatSeedSrc[:]); err != nil {
			return
		}
		iatDist = probdist.New(iatSeed, 0, maxIATDelay, biasedDist)
	}

	// Allocate the client structure.
	c = &obfs4Conn{conn, false, lenDist, iatDist, args.iatMode, bytes.NewBuffer(nil), bytes.NewBuffer(nil), make([]byte, consumeReadSize), nil, nil}

	// Start the handshake timeout.
	deadline := time.Now().Add(clientHandshakeTimeout)
	if err = conn.SetDeadline(deadline); err != nil {
		return nil, err
	}

	if err = c.clientHandshake(args.nodeID, args.publicKey, args.sessionKey); err != nil {
		return nil, err
	}

	// Stop the handshake timeout.
	if err = conn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}

	return
}

func (conn *obfs4Conn) clientHandshake(nodeID *ntor.NodeID, peerIdentityKey *ntor.PublicKey, sessionKey *ntor.Keypair) error {
	if conn.isServer {
		return fmt.Errorf("clientHandshake called on server connection")
	}

	// Generate and send the client handshake.
	hs := newClientHandshake(nodeID, peerIdentityKey, sessionKey)
	blob, err := hs.generateHandshake()
	if err != nil {
		return err
	}
	if _, err = conn.Conn.Write(blob); err != nil {
		return err
	}

	// Consume the server handshake.
	var hsBuf [maxHandshakeLength]byte
	for {
		n, err := conn.Conn.Read(hsBuf[:])
		if err != nil {
			// The Read() could have returned data and an error, but there is
			// no point in continuing on an EOF or whatever.
			return err
		}
		conn.receiveBuffer.Write(hsBuf[:n])

		n, seed, err := hs.parseServerHandshake(conn.receiveBuffer.Bytes())
		if err == ErrMarkNotFoundYet {
			continue
		} else if err != nil {
			return err
		}
		_ = conn.receiveBuffer.Next(n)

		// Use the derived key material to intialize the link crypto.
		okm := ntor.Kdf(seed, framing.KeyLength*2)
		conn.encoder = framing.NewEncoder(okm[:framing.KeyLength])
		conn.decoder = framing.NewDecoder(okm[framing.KeyLength:])

		return nil
	}
}

func (conn *obfs4Conn) serverHandshake(sf *obfs4ServerFactory, sessionKey *ntor.Keypair) error {
	if !conn.isServer {
		return fmt.Errorf("serverHandshake called on client connection")
	}

	// Generate the server handshake, and arm the base timeout.
	hs := newServerHandshake(sf.nodeID, sf.identityKey, sessionKey)
	if err := conn.Conn.SetDeadline(time.Now().Add(serverHandshakeTimeout)); err != nil {
		return err
	}

	// Consume the client handshake.
	var hsBuf [maxHandshakeLength]byte
	for {
		n, err := conn.Conn.Read(hsBuf[:])
		if err != nil {
			// The Read() could have returned data and an error, but there is
			// no point in continuing on an EOF or whatever.
			return err
		}
		conn.receiveBuffer.Write(hsBuf[:n])

		seed, err := hs.parseClientHandshake(sf.replayFilter, conn.receiveBuffer.Bytes())
		if err == ErrMarkNotFoundYet {
			continue
		} else if err != nil {
			return err
		}
		conn.receiveBuffer.Reset()

		if err := conn.Conn.SetDeadline(time.Time{}); err != nil {
			return nil
		}

		// Use the derived key material to intialize the link crypto.
		okm := ntor.Kdf(seed, framing.KeyLength*2)
		conn.encoder = framing.NewEncoder(okm[framing.KeyLength:])
		conn.decoder = framing.NewDecoder(okm[:framing.KeyLength])

		break
	}

	// Since the current and only implementation always sends a PRNG seed for
	// the length obfuscation, this makes the amount of data received from the
	// server inconsistent with the length sent from the client.
	//
	// Rebalance this by tweaking the client mimimum padding/server maximum
	// padding, and sending the PRNG seed unpadded (As in, treat the PRNG seed
	// as part of the server response).  See inlineSeedFrameLength in
	// handshake_ntor.go.

	// Generate/send the response.
	blob, err := hs.generateHandshake()
	if err != nil {
		return err
	}
	var frameBuf bytes.Buffer
	if _, err = frameBuf.Write(blob); err != nil {
		return err
	}

	// Send the PRNG seed as the first packet.
	if err := conn.makePacket(&frameBuf, packetTypePrngSeed, sf.lenSeed.Bytes()[:], 0); err != nil {
		return err
	}
	if _, err = conn.Conn.Write(frameBuf.Bytes()); err != nil {
		return err
	}

	return nil
}

func (conn *obfs4Conn) Read(b []byte) (n int, err error) {
	// If there is no payload from the previous Read() calls, consume data off
	// the network.  Not all data received is guaranteed to be usable payload,
	// so do this in a loop till data is present or an error occurs.
	for conn.receiveDecodedBuffer.Len() == 0 {
		err = conn.readPackets()
		if err == framing.ErrAgain {
			// Don't proagate this back up the call stack if we happen to break
			// out of the loop.
			err = nil
			continue
		} else if err != nil {
			break
		}
	}

	// Even if err is set, attempt to do the read anyway so that all decoded
	// data gets relayed before the connection is torn down.
	if conn.receiveDecodedBuffer.Len() > 0 {
		var berr error
		n, berr = conn.receiveDecodedBuffer.Read(b)
		if err == nil {
			// Only propagate berr if there are not more important (fatal)
			// errors from the network/crypto/packet processing.
			err = berr
		}
	}

	return
}

func (conn *obfs4Conn) Write(b []byte) (n int, err error) {
	chopBuf := bytes.NewBuffer(b)
	var payload [maxPacketPayloadLength]byte
	var frameBuf bytes.Buffer

	// Chop the pending data into payload frames.
	for chopBuf.Len() > 0 {
		// Send maximum sized frames.
		rdLen := 0
		rdLen, err = chopBuf.Read(payload[:])
		if err != nil {
			return 0, err
		} else if rdLen == 0 {
			panic(fmt.Sprintf("BUG: Write(), chopping length was 0"))
		}
		n += rdLen

		err = conn.makePacket(&frameBuf, packetTypePayload, payload[:rdLen], 0)
		if err != nil {
			return 0, err
		}
	}

	if conn.iatMode != iatParanoid {
		// For non-paranoid IAT, pad once per burst.  Paranoid IAT handles
		// things differently.
		if err = conn.padBurst(&frameBuf, conn.lenDist.Sample()); err != nil {
			return 0, err
		}
	}

	// Write the pending data onto the network.  Partial writes are fatal,
	// because the frame encoder state is advanced, and the code doesn't keep
	// frameBuf around.  In theory, write timeouts and whatnot could be
	// supported if this wasn't the case, but that complicates the code.
	if conn.iatMode != iatNone {
		var iatFrame [framing.MaximumSegmentLength]byte
		for frameBuf.Len() > 0 {
			iatWrLen := 0

			switch conn.iatMode {
			case iatEnabled:
				// Standard (ScrambleSuit-style) IAT obfuscation optimizes for
				// bulk transport and will write ~MTU sized frames when
				// possible.
				iatWrLen, err = frameBuf.Read(iatFrame[:])

			case iatParanoid:
				// Paranoid IAT obfuscation throws performance out of the
				// window and will sample the length distribution every time a
				// write is scheduled.
				targetLen := conn.lenDist.Sample()
				if frameBuf.Len() < targetLen {
					// There's not enough data buffered for the target write,
					// so padding must be inserted.
					if err = conn.padBurst(&frameBuf, targetLen); err != nil {
						return 0, err
					}
					if frameBuf.Len() != targetLen {
						// Ugh, padding came out to a value that required more
						// than one frame, this is relatively unlikely so just
						// resample since there's enough data to ensure that
						// the next sample will be written.
						continue
					}
				}
				iatWrLen, err = frameBuf.Read(iatFrame[:targetLen])
			}
			if err != nil {
				return 0, err
			} else if iatWrLen == 0 {
				panic(fmt.Sprintf("BUG: Write(), iat length was 0"))
			}

			// Calculate the delay.  The delay resolution is 100 usec, leading
			// to a maximum delay of 10 msec.
			iatDelta := time.Duration(conn.iatDist.Sample() * 100)

			// Write then sleep.
			_, err = conn.Conn.Write(iatFrame[:iatWrLen])
			if err != nil {
				return 0, err
			}
			time.Sleep(iatDelta * time.Microsecond)
		}
	} else {
		_, err = conn.Conn.Write(frameBuf.Bytes())
	}

	return
}

func (conn *obfs4Conn) SetDeadline(t time.Time) error {
	return syscall.ENOTSUP
}

func (conn *obfs4Conn) SetWriteDeadline(t time.Time) error {
	return syscall.ENOTSUP
}

func (conn *obfs4Conn) closeAfterDelay(sf *obfs4ServerFactory, startTime time.Time) {
	// I-it's not like I w-wanna handshake with you or anything.  B-b-baka!
	defer conn.Conn.Close()

	delay := time.Duration(sf.closeDelay)*time.Second + serverHandshakeTimeout
	deadline := startTime.Add(delay)
	if time.Now().After(deadline) {
		return
	}

	if err := conn.Conn.SetReadDeadline(deadline); err != nil {
		return
	}

	// Consume and discard data on this connection until either the specified
	// interval passes or a certain size has been reached.
	discarded := 0
	var buf [framing.MaximumSegmentLength]byte
	for discarded < int(sf.closeDelayBytes) {
		n, err := conn.Conn.Read(buf[:])
		if err != nil {
			return
		}
		discarded += n
	}
}

func (conn *obfs4Conn) padBurst(burst *bytes.Buffer, toPadTo int) (err error) {
	tailLen := burst.Len() % framing.MaximumSegmentLength

	padLen := 0
	if toPadTo >= tailLen {
		padLen = toPadTo - tailLen
	} else {
		padLen = (framing.MaximumSegmentLength - tailLen) + toPadTo
	}

	if padLen > headerLength {
		err = conn.makePacket(burst, packetTypePayload, []byte{},
			uint16(padLen-headerLength))
		if err != nil {
			return
		}
	} else if padLen > 0 {
		err = conn.makePacket(burst, packetTypePayload, []byte{},
			maxPacketPayloadLength)
		if err != nil {
			return
		}
		err = conn.makePacket(burst, packetTypePayload, []byte{},
			uint16(padLen))
		if err != nil {
			return
		}
	}

	return
}

func init() {
	flag.BoolVar(&biasedDist, biasCmdArg, false, "Enable obfs4 using ScrambleSuit style table generation")
}

var _ base.ClientFactory = (*obfs4ClientFactory)(nil)
var _ base.ServerFactory = (*obfs4ServerFactory)(nil)
var _ base.Transport = (*Transport)(nil)
var _ net.Conn = (*obfs4Conn)(nil)
