// Copyright 2014 Vic Demuzere
//
// Use of this source code is governed by the MIT license.

// +build go1.2

// Documented in strings_legacy.go

package internal

import (
	"strings"
)

// IndexByte is a compatibility function so strings.IndexByte can be used in
// older versions of go.
func IndexByte(s string, c byte) int {
	return strings.IndexByte(s, c)
}
