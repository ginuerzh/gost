// +build go1.7

package h2quic

import "net/http"

func setUncompressed(res *http.Response) {
	res.Uncompressed = true
}
