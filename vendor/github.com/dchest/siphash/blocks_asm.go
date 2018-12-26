// +build arm amd64,!appengine,!gccgo

// Written in 2012 by Dmitry Chestnykh.
//
// To the extent possible under law, the author have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// http://creativecommons.org/publicdomain/zero/1.0/

// This file contains a function definition for use with assembly implementations of Hash()

package siphash

//go:noescape
func blocks(d *digest, p []uint8)

//go:noescape
func finalize(d *digest) uint64

//go:noescape
func once(d *digest)
