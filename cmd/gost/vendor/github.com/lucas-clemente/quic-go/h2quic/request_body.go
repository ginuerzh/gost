package h2quic

import (
	"io"

	"github.com/lucas-clemente/quic-go/utils"
)

type requestBody struct {
	requestRead bool
	dataStream  utils.Stream
}

// make sure the requestBody can be used as a http.Request.Body
var _ io.ReadCloser = &requestBody{}

func newRequestBody(stream utils.Stream) *requestBody {
	return &requestBody{dataStream: stream}
}

func (b *requestBody) Read(p []byte) (int, error) {
	b.requestRead = true
	return b.dataStream.Read(p)
}

func (b *requestBody) Close() error {
	// stream's Close() closes the write side, not the read side
	return nil
}
