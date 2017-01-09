package h2quic

import (
	"bytes"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/utils"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type responseWriter struct {
	dataStreamID protocol.StreamID
	dataStream   utils.Stream

	headerStream      utils.Stream
	headerStreamMutex *sync.Mutex

	header        http.Header
	headerWritten bool
}

func newResponseWriter(headerStream utils.Stream, headerStreamMutex *sync.Mutex, dataStream utils.Stream, dataStreamID protocol.StreamID) *responseWriter {
	return &responseWriter{
		header:            http.Header{},
		headerStream:      headerStream,
		headerStreamMutex: headerStreamMutex,
		dataStream:        dataStream,
		dataStreamID:      dataStreamID,
	}
}

func (w *responseWriter) Header() http.Header {
	return w.header
}

func (w *responseWriter) WriteHeader(status int) {
	if w.headerWritten {
		return
	}
	w.headerWritten = true

	var headers bytes.Buffer
	enc := hpack.NewEncoder(&headers)
	enc.WriteField(hpack.HeaderField{Name: ":status", Value: strconv.Itoa(status)})

	for k, v := range w.header {
		for index := range v {
			enc.WriteField(hpack.HeaderField{Name: strings.ToLower(k), Value: v[index]})
		}
	}

	utils.Infof("Responding with %d", status)
	w.headerStreamMutex.Lock()
	defer w.headerStreamMutex.Unlock()
	h2framer := http2.NewFramer(w.headerStream, nil)
	err := h2framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      uint32(w.dataStreamID),
		EndHeaders:    true,
		BlockFragment: headers.Bytes(),
	})
	if err != nil {
		utils.Errorf("could not write h2 header: %s", err.Error())
	}
}

func (w *responseWriter) Write(p []byte) (int, error) {
	if !w.headerWritten {
		w.WriteHeader(200)
	}
	return w.dataStream.Write(p)
}

func (w *responseWriter) Flush() {}

// test that we implement http.Flusher
var _ http.Flusher = &responseWriter{}
