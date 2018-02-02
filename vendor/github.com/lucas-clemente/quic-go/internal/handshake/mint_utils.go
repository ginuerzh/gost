package handshake

import (
	"bytes"
	gocrypto "crypto"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"time"

	"github.com/bifurcation/mint"
	"github.com/lucas-clemente/quic-go/internal/crypto"
	"github.com/lucas-clemente/quic-go/internal/protocol"
)

func tlsToMintConfig(tlsConf *tls.Config, pers protocol.Perspective) (*mint.Config, error) {
	mconf := &mint.Config{
		NonBlocking: true,
		CipherSuites: []mint.CipherSuite{
			mint.TLS_AES_128_GCM_SHA256,
			mint.TLS_AES_256_GCM_SHA384,
		},
	}
	if tlsConf != nil {
		mconf.Certificates = make([]*mint.Certificate, len(tlsConf.Certificates))
		for i, certChain := range tlsConf.Certificates {
			mconf.Certificates[i] = &mint.Certificate{
				Chain:      make([]*x509.Certificate, len(certChain.Certificate)),
				PrivateKey: certChain.PrivateKey.(gocrypto.Signer),
			}
			for j, cert := range certChain.Certificate {
				c, err := x509.ParseCertificate(cert)
				if err != nil {
					return nil, err
				}
				mconf.Certificates[i].Chain[j] = c
			}
		}
	}
	if err := mconf.Init(pers == protocol.PerspectiveClient); err != nil {
		return nil, err
	}
	return mconf, nil
}

type mintTLS interface {
	// These two methods are the same as the crypto.TLSExporter interface.
	// Cannot use embedding here, because mockgen source mode refuses to generate mocks then.
	GetCipherSuite() mint.CipherSuiteParams
	ComputeExporter(label string, context []byte, keyLength int) ([]byte, error)
	// additional methods
	Handshake() mint.Alert
	State() mint.ConnectionState
}

var _ crypto.TLSExporter = (mintTLS)(nil)

type mintController struct {
	conn *mint.Conn
}

var _ mintTLS = &mintController{}

func (mc *mintController) GetCipherSuite() mint.CipherSuiteParams {
	return mc.conn.State().CipherSuite
}

func (mc *mintController) ComputeExporter(label string, context []byte, keyLength int) ([]byte, error) {
	return mc.conn.ComputeExporter(label, context, keyLength)
}

func (mc *mintController) Handshake() mint.Alert {
	return mc.conn.Handshake()
}

func (mc *mintController) State() mint.ConnectionState {
	return mc.conn.State()
}

// mint expects a net.Conn, but we're doing the handshake on a stream
// so we wrap a stream such that implements a net.Conn
type fakeConn struct {
	stream     io.ReadWriter
	pers       protocol.Perspective
	remoteAddr net.Addr

	blockRead   bool
	writeBuffer bytes.Buffer
}

var _ net.Conn = &fakeConn{}

func (c *fakeConn) Read(b []byte) (int, error) {
	if c.blockRead { // this causes mint.Conn.Handshake() to return a mint.AlertWouldBlock
		return 0, nil
	}
	c.blockRead = true // block the next Read call
	return c.stream.Read(b)
}

func (c *fakeConn) Write(p []byte) (int, error) {
	if c.pers == protocol.PerspectiveClient {
		return c.stream.Write(p)
	}
	// Buffer all writes by the server.
	// Mint transitions to the next state *after* writing, so we need to let all the writes happen, only then we can determine the packet type to use to send out this data.
	return c.writeBuffer.Write(p)
}

func (c *fakeConn) Continue() error {
	c.blockRead = false
	if c.pers == protocol.PerspectiveClient {
		return nil
	}
	// write all contents of the write buffer to the stream.
	_, err := c.stream.Write(c.writeBuffer.Bytes())
	c.writeBuffer.Reset()
	return err
}

func (c *fakeConn) Close() error                     { return nil }
func (c *fakeConn) LocalAddr() net.Addr              { return nil }
func (c *fakeConn) RemoteAddr() net.Addr             { return c.remoteAddr }
func (c *fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakeConn) SetWriteDeadline(time.Time) error { return nil }
func (c *fakeConn) SetDeadline(time.Time) error      { return nil }
