package h2quic

import (
	"errors"
	"net/http"
	"net/url"

	"golang.org/x/net/http2/hpack"
)

func requestFromHeaders(headers []hpack.HeaderField) (*http.Request, error) {
	var path, authority, method string
	httpHeaders := http.Header{}

	for _, h := range headers {
		switch h.Name {
		case ":path":
			path = h.Value
		case ":method":
			method = h.Value
		case ":authority":
			authority = h.Value
		default:
			if !h.IsPseudo() {
				httpHeaders.Add(h.Name, h.Value)
			}
		}
	}

	if len(path) == 0 || len(authority) == 0 || len(method) == 0 {
		return nil, errors.New(":path, :authority and :method must not be empty")
	}

	u, err := url.Parse(path)
	if err != nil {
		return nil, err
	}

	return &http.Request{
		Method:     method,
		URL:        u,
		Proto:      "HTTP/2.0",
		ProtoMajor: 2,
		ProtoMinor: 0,
		Header:     httpHeaders,
		Body:       nil,
		// ContentLength: -1,
		Host:       authority,
		RequestURI: path,
	}, nil
}
