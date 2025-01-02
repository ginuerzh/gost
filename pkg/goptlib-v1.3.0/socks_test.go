package pt

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// testReadWriter is a bytes.Buffer backed io.ReadWriter used for testing.  The
// Read and Write routines are to be used by the component being tested.  Data
// can be written to and read back via the writeHex and readHex routines.
type testReadWriter struct {
	readBuf  bytes.Buffer
	writeBuf bytes.Buffer
}

func (c *testReadWriter) Read(buf []byte) (n int, err error) {
	return c.readBuf.Read(buf)
}

func (c *testReadWriter) Write(buf []byte) (n int, err error) {
	return c.writeBuf.Write(buf)
}

func (c *testReadWriter) writeHex(str string) (n int, err error) {
	var buf []byte
	if buf, err = hex.DecodeString(str); err != nil {
		return
	}
	return c.readBuf.Write(buf)
}

func (c *testReadWriter) readHex() string {
	return hex.EncodeToString(c.writeBuf.Bytes())
}

func (c *testReadWriter) toBufio() *bufio.ReadWriter {
	return bufio.NewReadWriter(bufio.NewReader(c), bufio.NewWriter(c))
}

func (c *testReadWriter) reset() {
	c.readBuf.Reset()
	c.writeBuf.Reset()
}

// TestAuthInvalidVersion tests auth negotiation with an invalid version.
func TestAuthInvalidVersion(t *testing.T) {
	c := new(testReadWriter)

	// VER = 03, NMETHODS = 01, METHODS = [00]
	c.writeHex("030100")
	if _, err := socksNegotiateAuth(c.toBufio()); err == nil {
		t.Error("socksNegotiateAuth(InvalidVersion) succeded")
	}
}

// TestAuthInvalidNMethods tests auth negotiaton with no methods.
func TestAuthInvalidNMethods(t *testing.T) {
	c := new(testReadWriter)
	var err error
	var method byte

	// VER = 05, NMETHODS = 00
	c.writeHex("0500")
	if method, err = socksNegotiateAuth(c.toBufio()); err != nil {
		t.Error("socksNegotiateAuth(No Methods) failed:", err)
	}
	if method != socksAuthNoAcceptableMethods {
		t.Error("socksNegotiateAuth(No Methods) picked unexpected method:", method)
	}
	if msg := c.readHex(); msg != "05ff" {
		t.Error("socksNegotiateAuth(No Methods) invalid response:", msg)
	}
}

// TestAuthNoneRequired tests auth negotiaton with NO AUTHENTICATION REQUIRED.
func TestAuthNoneRequired(t *testing.T) {
	c := new(testReadWriter)
	var err error
	var method byte

	// VER = 05, NMETHODS = 01, METHODS = [00]
	c.writeHex("050100")
	if method, err = socksNegotiateAuth(c.toBufio()); err != nil {
		t.Error("socksNegotiateAuth(None) failed:", err)
	}
	if method != socksAuthNoneRequired {
		t.Error("socksNegotiateAuth(None) unexpected method:", method)
	}
	if msg := c.readHex(); msg != "0500" {
		t.Error("socksNegotiateAuth(None) invalid response:", msg)
	}
}

// TestAuthUsernamePassword tests auth negotiation with USERNAME/PASSWORD.
func TestAuthUsernamePassword(t *testing.T) {
	c := new(testReadWriter)
	var err error
	var method byte

	// VER = 05, NMETHODS = 01, METHODS = [02]
	c.writeHex("050102")
	if method, err = socksNegotiateAuth(c.toBufio()); err != nil {
		t.Error("socksNegotiateAuth(UsernamePassword) failed:", err)
	}
	if method != socksAuthUsernamePassword {
		t.Error("socksNegotiateAuth(UsernamePassword) unexpected method:", method)
	}
	if msg := c.readHex(); msg != "0502" {
		t.Error("socksNegotiateAuth(UsernamePassword) invalid response:", msg)
	}
}

var fakeListenerDistinguishedError = errors.New("distinguished error")

// fakeListener is a fake dummy net.Listener that returns the given net.Conn and
// error the first time Accept is called. After the first call, it returns
// (nil, fakeListenerDistinguishedError).
type fakeListener struct {
	c   net.Conn
	err error
}

func (ln *fakeListener) Accept() (net.Conn, error) {
	c := ln.c
	err := ln.err
	ln.c = nil
	ln.err = fakeListenerDistinguishedError
	return c, err
}

func (ln *fakeListener) Close() error {
	return nil
}

func (ln *fakeListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0, Zone: ""}
}

// A trivial net.Error that lets you control whether it is considered Temporary.
type netError struct {
	errString string
	temporary bool
}

func (e *netError) Error() string {
	return e.errString
}

func (e *netError) Temporary() bool {
	return e.temporary
}

func (e *netError) Timeout() bool {
	return false
}

// The purpose of ignoreDeadlineConn is to wrap net.Pipe so that the deadline
// functions don't return an error ("net.Pipe does not support deadlines").
type ignoreDeadlineConn struct {
	net.Conn
}

func (c *ignoreDeadlineConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *ignoreDeadlineConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *ignoreDeadlineConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func TestAcceptErrors(t *testing.T) {
	// Check that AcceptSocks accurately reflects net.Errors returned by the
	// underlying call to Accept. This is important for the handling of
	// Temporary and non-Temporary errors. The loop iterates over
	// non-net.Error, non-Temporary net.Error, and Temporary net.Error.
	for _, expectedErr := range []error{io.EOF, &netError{"non-temp", false}, &netError{"temp", true}} {
		ln := NewSocksListener(&fakeListener{nil, expectedErr})
		_, err := ln.AcceptSocks()
		if expectedNerr, ok := expectedErr.(net.Error); ok {
			nerr, ok := err.(net.Error)
			if !ok {
				t.Errorf("AcceptSocks returned non-net.Error %v", nerr)
			} else {
				if expectedNerr.Temporary() != expectedNerr.Temporary() {
					t.Errorf("AcceptSocks did not keep Temporary status of net.Error: %v", nerr)
				}
			}
		}
	}

	c1, c2 := net.Pipe()
	go func() {
		// Bogus request: SOCKS 5 then EOF.
		c2.Write([]byte("\x05\x01\x00"))
		c2.Close()
	}()
	ln := NewSocksListener(&fakeListener{c: &ignoreDeadlineConn{c1}, err: nil})
	_, err := ln.AcceptSocks()
	// The error in parsing the SOCKS request must be either silently
	// ignored, or else must be a Temporary net.Error. I.e., it must not be
	// the io.ErrUnexpectedEOF caused by the short request.
	if err == fakeListenerDistinguishedError {
		// Was silently ignored.
	} else if nerr, ok := err.(net.Error); ok {
		if !nerr.Temporary() {
			t.Errorf("AcceptSocks returned non-Temporary net.Error: %v", nerr)
		}
	} else {
		t.Errorf("AcceptSocks returned non-net.Error: %v", err)
	}
}

// TestAuthBoth tests auth negotiation containing both NO AUTHENTICATION
// REQUIRED and USERNAME/PASSWORD.
func TestAuthBoth(t *testing.T) {
	c := new(testReadWriter)
	var err error
	var method byte

	// VER = 05, NMETHODS = 02, METHODS = [00, 02]
	c.writeHex("05020002")
	if method, err = socksNegotiateAuth(c.toBufio()); err != nil {
		t.Error("socksNegotiateAuth(Both) failed:", err)
	}
	if method != socksAuthUsernamePassword {
		t.Error("socksNegotiateAuth(Both) unexpected method:", method)
	}
	if msg := c.readHex(); msg != "0502" {
		t.Error("socksNegotiateAuth(Both) invalid response:", msg)
	}
}

// TestAuthUnsupported tests auth negotiation with a unsupported method.
func TestAuthUnsupported(t *testing.T) {
	c := new(testReadWriter)
	var err error
	var method byte

	// VER = 05, NMETHODS = 01, METHODS = [01] (GSSAPI)
	c.writeHex("050101")
	if method, err = socksNegotiateAuth(c.toBufio()); err != nil {
		t.Error("socksNegotiateAuth(Unknown) failed:", err)
	}
	if method != socksAuthNoAcceptableMethods {
		t.Error("socksNegotiateAuth(Unknown) picked unexpected method:", method)
	}
	if msg := c.readHex(); msg != "05ff" {
		t.Error("socksNegotiateAuth(Unknown) invalid response:", msg)
	}
}

// TestAuthUnsupported2 tests auth negotiation with supported and unsupported
// methods.
func TestAuthUnsupported2(t *testing.T) {
	c := new(testReadWriter)
	var err error
	var method byte

	// VER = 05, NMETHODS = 03, METHODS = [00,01,02]
	c.writeHex("0503000102")
	if method, err = socksNegotiateAuth(c.toBufio()); err != nil {
		t.Error("socksNegotiateAuth(Unknown2) failed:", err)
	}
	if method != socksAuthUsernamePassword {
		t.Error("socksNegotiateAuth(Unknown2) picked unexpected method:", method)
	}
	if msg := c.readHex(); msg != "0502" {
		t.Error("socksNegotiateAuth(Unknown2) invalid response:", msg)
	}
}

// TestRFC1929InvalidVersion tests RFC1929 auth with an invalid version.
func TestRFC1929InvalidVersion(t *testing.T) {
	c := new(testReadWriter)
	var req SocksRequest

	// VER = 03, ULEN = 5, UNAME = "ABCDE", PLEN = 5, PASSWD = "abcde"
	c.writeHex("03054142434445056162636465")
	if err := socksAuthenticate(c.toBufio(), socksAuthUsernamePassword, &req); err == nil {
		t.Error("socksAuthenticate(InvalidVersion) succeded")
	}
	if msg := c.readHex(); msg != "0101" {
		t.Error("socksAuthenticate(InvalidVersion) invalid response:", msg)
	}
}

// TestRFC1929InvalidUlen tests RFC1929 auth with an invalid ULEN.
func TestRFC1929InvalidUlen(t *testing.T) {
	c := new(testReadWriter)
	var req SocksRequest

	// VER = 01, ULEN = 0, UNAME = "", PLEN = 5, PASSWD = "abcde"
	c.writeHex("0100056162636465")
	if err := socksAuthenticate(c.toBufio(), socksAuthUsernamePassword, &req); err == nil {
		t.Error("socksAuthenticate(InvalidUlen) succeded")
	}
	if msg := c.readHex(); msg != "0101" {
		t.Error("socksAuthenticate(InvalidUlen) invalid response:", msg)
	}
}

// TestRFC1929InvalidPlen tests RFC1929 auth with an invalid PLEN.
func TestRFC1929InvalidPlen(t *testing.T) {
	c := new(testReadWriter)
	var req SocksRequest

	// VER = 01, ULEN = 5, UNAME = "ABCDE", PLEN = 0, PASSWD = ""
	c.writeHex("0105414243444500")
	if err := socksAuthenticate(c.toBufio(), socksAuthUsernamePassword, &req); err == nil {
		t.Error("socksAuthenticate(InvalidPlen) succeded")
	}
	if msg := c.readHex(); msg != "0101" {
		t.Error("socksAuthenticate(InvalidPlen) invalid response:", msg)
	}
}

// TestRFC1929InvalidArgs tests RFC1929 auth with invalid pt args.
func TestRFC1929InvalidPTArgs(t *testing.T) {
	c := new(testReadWriter)
	var req SocksRequest

	// VER = 01, ULEN = 5, UNAME = "ABCDE", PLEN = 5, PASSWD = "abcde"
	c.writeHex("01054142434445056162636465")
	if err := socksAuthenticate(c.toBufio(), socksAuthUsernamePassword, &req); err == nil {
		t.Error("socksAuthenticate(InvalidArgs) succeded")
	}
	if msg := c.readHex(); msg != "0101" {
		t.Error("socksAuthenticate(InvalidArgs) invalid response:", msg)
	}
}

// TestRFC1929Success tests RFC1929 auth with valid pt args.
func TestRFC1929Success(t *testing.T) {
	c := new(testReadWriter)
	var req SocksRequest

	// VER = 01, ULEN = 9, UNAME = "key=value", PLEN = 1, PASSWD = "\0"
	c.writeHex("01096b65793d76616c75650100")
	if err := socksAuthenticate(c.toBufio(), socksAuthUsernamePassword, &req); err != nil {
		t.Error("socksAuthenticate(Success) failed:", err)
	}
	if msg := c.readHex(); msg != "0100" {
		t.Error("socksAuthenticate(Success) invalid response:", msg)
	}
	v, ok := req.Args.Get("key")
	if v != "value" || !ok {
		t.Error("RFC1929 k,v parse failure:", v)
	}
}

// TestRequestInvalidHdr tests SOCKS5 requests with invalid VER/CMD/RSV/ATYPE
func TestRequestInvalidHdr(t *testing.T) {
	c := new(testReadWriter)
	var req SocksRequest

	// VER = 03, CMD = 01, RSV = 00, ATYPE = 01, DST.ADDR = 127.0.0.1, DST.PORT = 9050
	c.writeHex("030100017f000001235a")
	if err := socksReadCommand(c.toBufio(), &req); err == nil {
		t.Error("socksReadCommand(InvalidVer) succeded")
	}
	if msg := c.readHex(); msg != "05010001000000000000" {
		t.Error("socksReadCommand(InvalidVer) invalid response:", msg)
	}
	c.reset()

	// VER = 05, CMD = 05, RSV = 00, ATYPE = 01, DST.ADDR = 127.0.0.1, DST.PORT = 9050
	c.writeHex("050500017f000001235a")
	if err := socksReadCommand(c.toBufio(), &req); err == nil {
		t.Error("socksReadCommand(InvalidCmd) succeded")
	}
	if msg := c.readHex(); msg != "05070001000000000000" {
		t.Error("socksReadCommand(InvalidCmd) invalid response:", msg)
	}
	c.reset()

	// VER = 05, CMD = 01, RSV = 30, ATYPE = 01, DST.ADDR = 127.0.0.1, DST.PORT = 9050
	c.writeHex("050130017f000001235a")
	if err := socksReadCommand(c.toBufio(), &req); err == nil {
		t.Error("socksReadCommand(InvalidRsv) succeded")
	}
	if msg := c.readHex(); msg != "05010001000000000000" {
		t.Error("socksReadCommand(InvalidRsv) invalid response:", msg)
	}
	c.reset()

	// VER = 05, CMD = 01, RSV = 01, ATYPE = 05, DST.ADDR = 127.0.0.1, DST.PORT = 9050
	c.writeHex("050100057f000001235a")
	if err := socksReadCommand(c.toBufio(), &req); err == nil {
		t.Error("socksReadCommand(InvalidAtype) succeded")
	}
	if msg := c.readHex(); msg != "05080001000000000000" {
		t.Error("socksAuthenticate(InvalidAtype) invalid response:", msg)
	}
	c.reset()
}

// TestRequestIPv4 tests IPv4 SOCKS5 requests.
func TestRequestIPv4(t *testing.T) {
	c := new(testReadWriter)
	var req SocksRequest

	// VER = 05, CMD = 01, RSV = 00, ATYPE = 01, DST.ADDR = 127.0.0.1, DST.PORT = 9050
	c.writeHex("050100017f000001235a")
	if err := socksReadCommand(c.toBufio(), &req); err != nil {
		t.Error("socksReadCommand(IPv4) failed:", err)
	}
	addr, err := net.ResolveTCPAddr("tcp", req.Target)
	if err != nil {
		t.Error("net.ResolveTCPAddr failed:", err)
	}
	if !tcpAddrsEqual(addr, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9050}) {
		t.Error("Unexpected target:", addr)
	}
}

// TestRequestIPv6 tests IPv4 SOCKS5 requests.
func TestRequestIPv6(t *testing.T) {
	c := new(testReadWriter)
	var req SocksRequest

	// VER = 05, CMD = 01, RSV = 00, ATYPE = 04, DST.ADDR = 0102:0304:0506:0708:090a:0b0c:0d0e:0f10, DST.PORT = 9050
	c.writeHex("050100040102030405060708090a0b0c0d0e0f10235a")
	if err := socksReadCommand(c.toBufio(), &req); err != nil {
		t.Error("socksReadCommand(IPv6) failed:", err)
	}
	addr, err := net.ResolveTCPAddr("tcp", req.Target)
	if err != nil {
		t.Error("net.ResolveTCPAddr failed:", err)
	}
	if !tcpAddrsEqual(addr, &net.TCPAddr{IP: net.ParseIP("0102:0304:0506:0708:090a:0b0c:0d0e:0f10"), Port: 9050}) {
		t.Error("Unexpected target:", addr)
	}
}

// TestRequestFQDN tests FQDN (DOMAINNAME) SOCKS5 requests.
func TestRequestFQDN(t *testing.T) {
	c := new(testReadWriter)
	var req SocksRequest

	// VER = 05, CMD = 01, RSV = 00, ATYPE = 04, DST.ADDR = example.com, DST.PORT = 9050
	c.writeHex("050100030b6578616d706c652e636f6d235a")
	if err := socksReadCommand(c.toBufio(), &req); err != nil {
		t.Error("socksReadCommand(FQDN) failed:", err)
	}
	if req.Target != "example.com:9050" {
		t.Error("Unexpected target:", req.Target)
	}
}

// TestResponseNil tests nil address SOCKS5 responses.
func TestResponseNil(t *testing.T) {
	c := new(testReadWriter)

	b := c.toBufio()
	if err := sendSocks5ResponseGranted(b); err != nil {
		t.Error("sendSocks5ResponseGranted() failed:", err)
	}
	b.Flush()
	if msg := c.readHex(); msg != "05000001000000000000" {
		t.Error("sendSocks5ResponseGranted(nil) invalid response:", msg)
	}
}

var _ io.ReadWriter = (*testReadWriter)(nil)
