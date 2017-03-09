package h2quic

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
	"golang.org/x/net/idna"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
	"github.com/lucas-clemente/quic-go/utils"
)

type quicClient interface {
	OpenStream(protocol.StreamID) (utils.Stream, error)
	Close(error) error
	Listen() error
}

// Client is a HTTP2 client doing QUIC requests
type Client struct {
	mutex             sync.RWMutex
	cryptoChangedCond sync.Cond

	t *QuicRoundTripper

	hostname        string
	encryptionLevel protocol.EncryptionLevel

	client              quicClient
	headerStream        utils.Stream
	headerErr           *qerr.QuicError
	highestOpenedStream protocol.StreamID
	requestWriter       *requestWriter

	responses map[protocol.StreamID]chan *http.Response
}

var _ h2quicClient = &Client{}

// NewClient creates a new client
func NewClient(t *QuicRoundTripper, tlsConfig *tls.Config, hostname string) (*Client, error) {
	c := &Client{
		t:                   t,
		hostname:            authorityAddr("https", hostname),
		highestOpenedStream: 3,
		responses:           make(map[protocol.StreamID]chan *http.Response),
	}
	c.cryptoChangedCond = sync.Cond{L: &c.mutex}

	var err error
	c.client, err = quic.NewClient(c.hostname, tlsConfig, c.cryptoChangeCallback, c.versionNegotiateCallback)
	if err != nil {
		return nil, err
	}

	go c.client.Listen()
	return c, nil
}

func (c *Client) handleStreamCb(session *quic.Session, stream utils.Stream) {
	utils.Debugf("Handling stream %d", stream.StreamID())
}

func (c *Client) cryptoChangeCallback(isForwardSecure bool) {
	c.cryptoChangedCond.L.Lock()
	defer c.cryptoChangedCond.L.Unlock()

	if isForwardSecure {
		c.encryptionLevel = protocol.EncryptionForwardSecure
		utils.Debugf("is forward secure")
	} else {
		c.encryptionLevel = protocol.EncryptionSecure
		utils.Debugf("is secure")
	}
	c.cryptoChangedCond.Broadcast()
}

func (c *Client) versionNegotiateCallback() error {
	var err error
	// once the version has been negotiated, open the header stream
	c.headerStream, err = c.client.OpenStream(3)
	if err != nil {
		return err
	}
	c.requestWriter = newRequestWriter(c.headerStream)
	go c.handleHeaderStream()
	return nil
}

func (c *Client) handleHeaderStream() {
	decoder := hpack.NewDecoder(4096, func(hf hpack.HeaderField) {})
	h2framer := http2.NewFramer(nil, c.headerStream)

	var lastStream protocol.StreamID

	for {
		frame, err := h2framer.ReadFrame()
		if err != nil {
			c.headerErr = qerr.Error(qerr.InvalidStreamData, "cannot read frame")
			break
		}
		lastStream = protocol.StreamID(frame.Header().StreamID)
		hframe, ok := frame.(*http2.HeadersFrame)
		if !ok {
			c.headerErr = qerr.Error(qerr.InvalidHeadersStreamData, "not a headers frame")
			break
		}
		mhframe := &http2.MetaHeadersFrame{HeadersFrame: hframe}
		mhframe.Fields, err = decoder.DecodeFull(hframe.HeaderBlockFragment())
		if err != nil {
			c.headerErr = qerr.Error(qerr.InvalidHeadersStreamData, "cannot read header fields")
			break
		}

		c.mutex.RLock()
		headerChan, ok := c.responses[protocol.StreamID(hframe.StreamID)]
		c.mutex.RUnlock()
		if !ok {
			c.headerErr = qerr.Error(qerr.InternalError, fmt.Sprintf("h2client BUG: response channel for stream %d not found", lastStream))
			break
		}

		rsp, err := responseFromHeaders(mhframe)
		if err != nil {
			c.headerErr = qerr.Error(qerr.InternalError, err.Error())
		}
		headerChan <- rsp
	}

	// stop all running request
	utils.Debugf("Error handling header stream %d: %s", lastStream, c.headerErr.Error())
	c.mutex.Lock()
	for _, responseChan := range c.responses {
		responseChan <- nil
	}
	c.mutex.Unlock()
}

// Do executes a request and returns a response
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	// TODO: add port to address, if it doesn't have one
	if req.URL.Scheme != "https" {
		return nil, errors.New("quic http2: unsupported scheme")
	}
	if authorityAddr("https", hostnameFromRequest(req)) != c.hostname {
		utils.Debugf("%s vs %s", req.Host, c.hostname)
		return nil, errors.New("h2quic Client BUG: Do called for the wrong client")
	}

	hasBody := (req.Body != nil)

	c.mutex.Lock()
	c.highestOpenedStream += 2
	dataStreamID := c.highestOpenedStream
	for c.encryptionLevel != protocol.EncryptionForwardSecure {
		c.cryptoChangedCond.Wait()
	}
	hdrChan := make(chan *http.Response)
	c.responses[dataStreamID] = hdrChan
	c.mutex.Unlock()

	// TODO: think about what to do with a TooManyOpenStreams error. Wait and retry?
	dataStream, err := c.client.OpenStream(dataStreamID)
	if err != nil {
		c.Close(err)
		return nil, err
	}

	var requestedGzip bool
	if !c.t.disableCompression() && req.Header.Get("Accept-Encoding") == "" && req.Header.Get("Range") == "" && req.Method != "HEAD" {
		requestedGzip = true
	}
	// TODO: add support for trailers
	endStream := !hasBody
	err = c.requestWriter.WriteRequest(req, dataStreamID, endStream, requestedGzip)
	if err != nil {
		c.Close(err)
		return nil, err
	}

	resc := make(chan error, 1)
	if hasBody {
		go func() {
			resc <- c.writeRequestBody(dataStream, req.Body)
		}()
	}

	var res *http.Response

	var receivedResponse bool
	var bodySent bool

	if !hasBody {
		bodySent = true
	}

	for !(bodySent && receivedResponse) {
		select {
		case res = <-hdrChan:
			receivedResponse = true
			c.mutex.Lock()
			delete(c.responses, dataStreamID)
			c.mutex.Unlock()
			if res == nil { // an error occured on the header stream
				c.Close(c.headerErr)
				return nil, c.headerErr
			}
		case err := <-resc:
			bodySent = true
			if err != nil {
				return nil, err
			}
		}
	}

	// TODO: correctly set this variable
	var streamEnded bool
	isHead := (req.Method == "HEAD")

	res = setLength(res, isHead, streamEnded)

	if streamEnded || isHead {
		res.Body = noBody
	} else {
		res.Body = dataStream
		if requestedGzip && res.Header.Get("Content-Encoding") == "gzip" {
			res.Header.Del("Content-Encoding")
			res.Header.Del("Content-Length")
			res.ContentLength = -1
			res.Body = &gzipReader{body: res.Body}
			setUncompressed(res)
		}
	}

	res.Request = req

	return res, nil
}

func (c *Client) writeRequestBody(dataStream utils.Stream, body io.ReadCloser) (err error) {
	defer func() {
		cerr := body.Close()
		if err == nil {
			// TODO: what to do with dataStream here? Maybe reset it?
			err = cerr
		}
	}()

	_, err = io.Copy(dataStream, body)
	if err != nil {
		// TODO: what to do with dataStream here? Maybe reset it?
		return err
	}
	return dataStream.Close()
}

// Close closes the client
func (c *Client) Close(e error) {
	_ = c.client.Close(e)
}

// copied from net/transport.go

// authorityAddr returns a given authority (a host/IP, or host:port / ip:port)
// and returns a host:port. The port 443 is added if needed.
func authorityAddr(scheme string, authority string) (addr string) {
	host, port, err := net.SplitHostPort(authority)
	if err != nil { // authority didn't have a port
		port = "443"
		if scheme == "http" {
			port = "80"
		}
		host = authority
	}
	if a, err := idna.ToASCII(host); err == nil {
		host = a
	}
	// IPv6 address literal, without a port:
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		return host + ":" + port
	}
	return net.JoinHostPort(host, port)
}
