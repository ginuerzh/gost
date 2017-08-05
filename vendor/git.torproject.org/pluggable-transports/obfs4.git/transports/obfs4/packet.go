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
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"git.torproject.org/pluggable-transports/obfs4.git/common/drbg"
	"git.torproject.org/pluggable-transports/obfs4.git/transports/obfs4/framing"
)

const (
	packetOverhead          = 2 + 1
	maxPacketPayloadLength  = framing.MaximumFramePayloadLength - packetOverhead
	maxPacketPaddingLength  = maxPacketPayloadLength
	seedPacketPayloadLength = seedLength

	consumeReadSize = framing.MaximumSegmentLength * 16
)

const (
	packetTypePayload = iota
	packetTypePrngSeed
)

// InvalidPacketLengthError is the error returned when decodePacket detects a
// invalid packet length/
type InvalidPacketLengthError int

func (e InvalidPacketLengthError) Error() string {
	return fmt.Sprintf("packet: Invalid packet length: %d", int(e))
}

// InvalidPayloadLengthError is the error returned when decodePacket rejects the
// payload length.
type InvalidPayloadLengthError int

func (e InvalidPayloadLengthError) Error() string {
	return fmt.Sprintf("packet: Invalid payload length: %d", int(e))
}

var zeroPadBytes [maxPacketPaddingLength]byte

func (conn *obfs4Conn) makePacket(w io.Writer, pktType uint8, data []byte, padLen uint16) error {
	var pkt [framing.MaximumFramePayloadLength]byte

	if len(data)+int(padLen) > maxPacketPayloadLength {
		panic(fmt.Sprintf("BUG: makePacket() len(data) + padLen > maxPacketPayloadLength: %d + %d > %d",
			len(data), padLen, maxPacketPayloadLength))
	}

	// Packets are:
	//   uint8_t type      packetTypePayload (0x00)
	//   uint16_t length   Length of the payload (Big Endian).
	//   uint8_t[] payload Data payload.
	//   uint8_t[] padding Padding.
	pkt[0] = pktType
	binary.BigEndian.PutUint16(pkt[1:], uint16(len(data)))
	if len(data) > 0 {
		copy(pkt[3:], data[:])
	}
	copy(pkt[3+len(data):], zeroPadBytes[:padLen])

	pktLen := packetOverhead + len(data) + int(padLen)

	// Encode the packet in an AEAD frame.
	var frame [framing.MaximumSegmentLength]byte
	frameLen, err := conn.encoder.Encode(frame[:], pkt[:pktLen])
	if err != nil {
		// All encoder errors are fatal.
		return err
	}
	wrLen, err := w.Write(frame[:frameLen])
	if err != nil {
		return err
	} else if wrLen < frameLen {
		return io.ErrShortWrite
	}

	return nil
}

func (conn *obfs4Conn) readPackets() (err error) {
	// Attempt to read off the network.
	rdLen, rdErr := conn.Conn.Read(conn.readBuffer)
	conn.receiveBuffer.Write(conn.readBuffer[:rdLen])

	var decoded [framing.MaximumFramePayloadLength]byte
	for conn.receiveBuffer.Len() > 0 {
		// Decrypt an AEAD frame.
		decLen := 0
		decLen, err = conn.decoder.Decode(decoded[:], conn.receiveBuffer)
		if err == framing.ErrAgain {
			break
		} else if err != nil {
			break
		} else if decLen < packetOverhead {
			err = InvalidPacketLengthError(decLen)
			break
		}

		// Decode the packet.
		pkt := decoded[0:decLen]
		pktType := pkt[0]
		payloadLen := binary.BigEndian.Uint16(pkt[1:])
		if int(payloadLen) > len(pkt)-packetOverhead {
			err = InvalidPayloadLengthError(int(payloadLen))
			break
		}
		payload := pkt[3 : 3+payloadLen]

		switch pktType {
		case packetTypePayload:
			if payloadLen > 0 {
				conn.receiveDecodedBuffer.Write(payload)
			}
		case packetTypePrngSeed:
			// Only regenerate the distribution if we are the client.
			if len(payload) == seedPacketPayloadLength && !conn.isServer {
				var seed *drbg.Seed
				seed, err = drbg.SeedFromBytes(payload)
				if err != nil {
					break
				}
				conn.lenDist.Reset(seed)
				if conn.iatDist != nil {
					iatSeedSrc := sha256.Sum256(seed.Bytes()[:])
					iatSeed, err := drbg.SeedFromBytes(iatSeedSrc[:])
					if err != nil {
						break
					}
					conn.iatDist.Reset(iatSeed)
				}
			}
		default:
			// Ignore unknown packet types.
		}
	}

	// Read errors (all fatal) take priority over various frame processing
	// errors.
	if rdErr != nil {
		return rdErr
	}

	return
}
