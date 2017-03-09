// +build !go1.7

package h2quic

import "net/http"

func setUncompressed(res *http.Response) {
	// http.Response.Uncompressed was introduced in go 1.7
}
