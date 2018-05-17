// Copyright 2014 Vic Demuzere
//
// Use of this source code is governed by the MIT license.

// +build !go1.2

// Debian Wheezy only ships Go 1.0:
// https://github.com/sorcix/irc/issues/4
//
// This code may be removed when Wheezy is no longer supported.

package internal

// IndexByte implements strings.IndexByte for Go versions < 1.2.
func IndexByte(s string, c byte) int {
	for i := range s {
		if s[i] == c {
			return i
		}
	}
	return -1
}
