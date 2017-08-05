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

// Package base provides the common interface that each supported transport
// protocol must implement.
package base

import (
	"net"

	"git.torproject.org/pluggable-transports/goptlib.git"
)

type DialFunc func(string, string) (net.Conn, error)

// ClientFactory is the interface that defines the factory for creating
// pluggable transport protocol client instances.
type ClientFactory interface {
	// Transport returns the Transport instance that this ClientFactory belongs
	// to.
	Transport() Transport

	// ParseArgs parses the supplied arguments into an internal representation
	// for use with WrapConn.  This routine is called before the outgoing
	// TCP/IP connection is created to allow doing things (like keypair
	// generation) to be hidden from third parties.
	ParseArgs(args *pt.Args) (interface{}, error)

	// Dial creates an outbound net.Conn, and does whatever is required
	// (eg: handshaking) to get the connection to the point where it is
	// ready to relay data.
	Dial(network, address string, dialFn DialFunc, args interface{}) (net.Conn, error)
}

// ServerFactory is the interface that defines the factory for creating
// plugable transport protocol server instances.  As the arguments are the
// property of the factory, validation is done at factory creation time.
type ServerFactory interface {
	// Transport returns the Transport instance that this ServerFactory belongs
	// to.
	Transport() Transport

	// Args returns the Args required on the client side to handshake with
	// server connections created by this factory.
	Args() *pt.Args

	// WrapConn wraps the provided net.Conn with a transport protocol
	// implementation, and does whatever is required (eg: handshaking) to get
	// the connection to a point where it is ready to relay data.
	WrapConn(conn net.Conn) (net.Conn, error)
}

// Transport is an interface that defines a pluggable transport protocol.
type Transport interface {
	// Name returns the name of the transport protocol.  It MUST be a valid C
	// identifier.
	Name() string

	// ClientFactory returns a ClientFactory instance for this transport
	// protocol.
	ClientFactory(stateDir string) (ClientFactory, error)

	// ServerFactory returns a ServerFactory instance for this transport
	// protocol.  This can fail if the provided arguments are invalid.
	ServerFactory(stateDir string, args *pt.Args) (ServerFactory, error)
}
