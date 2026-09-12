package pt

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path"
	"sort"
	"testing"
	"time"
)

const testAuthCookiePath = "test_authcookie"

func TestErrors(t *testing.T) {
	Stdout = ioutil.Discard

	var err error
	err = envError("XYZ")
	if err.Error() != "ENV-ERROR XYZ" {
		t.Errorf("unexpected string %q from envError", err.Error())
	}
	err = versionError("XYZ")
	if err.Error() != "VERSION-ERROR XYZ" {
		t.Errorf("unexpected string %q from versionError", err.Error())
	}
	err = CmethodError("method", "XYZ")
	if err.Error() != "CMETHOD-ERROR method XYZ" {
		t.Errorf("unexpected string %q from CmethodError", err.Error())
	}
	err = SmethodError("method", "XYZ")
	if err.Error() != "SMETHOD-ERROR method XYZ" {
		t.Errorf("unexpected string %q from SmethodError", err.Error())
	}
	err = ProxyError("XYZ")
	if err.Error() != "PROXY-ERROR XYZ" {
		t.Errorf("unexpected string %q from ProxyError", err.Error())
	}
}

func TestKeywordIsSafe(t *testing.T) {
	tests := [...]struct {
		keyword  string
		expected bool
	}{
		{"", true},
		{"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_", true},
		{"CMETHOD", true},
		{"CMETHOD:", false},
		{"a b c", false},
		{"CMETHOD\x7f", false},
		{"CMETHOD\x80", false},
		{"CMETHOD\x81", false},
		{"CMETHOD\xff", false},
		{"\xffCMETHOD", false},
		{"CMÉTHOD", false},
	}

	for _, input := range tests {
		isSafe := keywordIsSafe(input.keyword)
		if isSafe != input.expected {
			t.Errorf("keywordIsSafe(%q) → %v (expected %v)",
				input.keyword, isSafe, input.expected)
		}
	}
}

func TestArgIsSafe(t *testing.T) {
	tests := [...]struct {
		arg      string
		expected bool
	}{
		{"", true},
		{"abc", true},
		{"127.0.0.1:8000", true},
		{"étude", false},
		{"a\nb", false},
		{"a\\b", true},
		{"ab\\", true},
		{"ab\\\n", false},
		{"ab\n\\", false},
		{"abc\x7f", true},
		{"abc\x80", false},
		{"abc\x81", false},
		{"abc\xff", false},
		{"abc\xff", false},
		{"var=GVsbG8\\=", true},
	}

	for _, input := range tests {
		isSafe := argIsSafe(input.arg)
		if isSafe != input.expected {
			t.Errorf("argIsSafe(%q) → %v (expected %v)",
				input.arg, isSafe, input.expected)
		}
	}
}

func TestGetManagedTransportVer(t *testing.T) {
	badTests := [...]string{
		"",
		"2",
	}
	goodTests := [...]struct {
		input, expected string
	}{
		{"1", "1"},
		{"1,1", "1"},
		{"1,2", "1"},
		{"2,1", "1"},
	}

	Stdout = ioutil.Discard

	os.Clearenv()
	_, err := getManagedTransportVer()
	if err == nil {
		t.Errorf("empty environment unexpectedly succeeded")
	}

	for _, input := range badTests {
		os.Setenv("TOR_PT_MANAGED_TRANSPORT_VER", input)
		_, err := getManagedTransportVer()
		if err == nil {
			t.Errorf("TOR_PT_MANAGED_TRANSPORT_VER=%q unexpectedly succeeded", input)
		}
	}

	for _, test := range goodTests {
		os.Setenv("TOR_PT_MANAGED_TRANSPORT_VER", test.input)
		output, err := getManagedTransportVer()
		if err != nil {
			t.Errorf("TOR_PT_MANAGED_TRANSPORT_VER=%q unexpectedly returned an error: %s", test.input, err)
		}
		if output != test.expected {
			t.Errorf("TOR_PT_MANAGED_TRANSPORT_VER=%q → %q (expected %q)", test.input, output, test.expected)
		}
	}
}

// return true iff the two slices contain the same elements, possibly in a
// different order.
func stringSetsEqual(a, b []string) bool {
	ac := make([]string, len(a))
	bc := make([]string, len(b))
	copy(ac, a)
	copy(bc, b)
	sort.Strings(ac)
	sort.Strings(bc)
	if len(ac) != len(bc) {
		return false
	}
	for i := 0; i < len(ac); i++ {
		if ac[i] != bc[i] {
			return false
		}
	}
	return true
}

func tcpAddrsEqual(a, b *net.TCPAddr) bool {
	return a.IP.Equal(b.IP) && a.Port == b.Port
}

func TestGetClientTransports(t *testing.T) {
	tests := [...]struct {
		ptClientTransports string
		expected           []string
	}{
		{
			"alpha",
			[]string{"alpha"},
		},
		{
			"alpha,beta",
			[]string{"alpha", "beta"},
		},
		{
			"alpha,beta,gamma",
			[]string{"alpha", "beta", "gamma"},
		},
		// In the past, "*" meant to return all known transport names.
		// But now it has no special meaning.
		// https://bugs.torproject.org/15612
		{
			"*",
			[]string{"*"},
		},
		{
			"alpha,*,gamma",
			[]string{"alpha", "*", "gamma"},
		},
		// No escaping is defined for TOR_PT_CLIENT_TRANSPORTS.
		{
			`alpha\,beta`,
			[]string{`alpha\`, `beta`},
		},
	}

	Stdout = ioutil.Discard

	os.Clearenv()
	_, err := getClientTransports()
	if err == nil {
		t.Errorf("empty environment unexpectedly succeeded")
	}

	for _, test := range tests {
		os.Setenv("TOR_PT_CLIENT_TRANSPORTS", test.ptClientTransports)
		output, err := getClientTransports()
		if err != nil {
			t.Errorf("TOR_PT_CLIENT_TRANSPORTS=%q unexpectedly returned an error: %s",
				test.ptClientTransports, err)
		}
		if !stringSetsEqual(output, test.expected) {
			t.Errorf("TOR_PT_CLIENT_TRANSPORTS=%q → %q (expected %q)",
				test.ptClientTransports, output, test.expected)
		}
	}
}

func TestResolveAddr(t *testing.T) {
	badTests := [...]string{
		"",
		"1.2.3.4",
		"1.2.3.4:",
		"9999",
		":9999",
		"[1:2::3:4]",
		"[1:2::3:4]:",
		"[1::2::3:4]",
		"1:2::3:4::9999",
		"1:2:3:4::9999",
		"localhost:9999",
		"[localhost]:9999",
		"1.2.3.4:http",
		"1.2.3.4:0x50",
		"1.2.3.4:-65456",
		"1.2.3.4:65536",
		"1.2.3.4:80\x00",
		"1.2.3.4:80 ",
		" 1.2.3.4:80",
		"1.2.3.4 : 80",
	}
	goodTests := [...]struct {
		input    string
		expected net.TCPAddr
	}{
		{"1.2.3.4:9999", net.TCPAddr{IP: net.ParseIP("1.2.3.4"), Port: 9999}},
		{"[1:2::3:4]:9999", net.TCPAddr{IP: net.ParseIP("1:2::3:4"), Port: 9999}},
		{"1:2::3:4:9999", net.TCPAddr{IP: net.ParseIP("1:2::3:4"), Port: 9999}},
	}

	for _, input := range badTests {
		output, err := resolveAddr(input)
		if err == nil {
			t.Errorf("%q unexpectedly succeeded: %q", input, output)
		}
	}

	for _, test := range goodTests {
		output, err := resolveAddr(test.input)
		if err != nil {
			t.Errorf("%q unexpectedly returned an error: %s", test.input, err)
		}
		if !tcpAddrsEqual(output, &test.expected) {
			t.Errorf("%q → %q (expected %q)", test.input, output, test.expected)
		}
	}
}

func bindaddrSliceContains(s []Bindaddr, v Bindaddr) bool {
	for _, sv := range s {
		if sv.MethodName == v.MethodName && tcpAddrsEqual(sv.Addr, v.Addr) {
			return true
		}
	}
	return false
}

func bindaddrSetsEqual(a, b []Bindaddr) bool {
	for _, v := range a {
		if !bindaddrSliceContains(b, v) {
			return false
		}
	}
	for _, v := range b {
		if !bindaddrSliceContains(a, v) {
			return false
		}
	}
	return true
}

func TestGetServerBindaddrs(t *testing.T) {
	badTests := [...]struct {
		ptServerBindaddr         string
		ptServerTransports       string
		ptServerTransportOptions string
	}{
		// bad TOR_PT_SERVER_BINDADDR
		{
			"alpha",
			"alpha",
			"",
		},
		{
			"alpha-1.2.3.4",
			"alpha",
			"",
		},
		// missing TOR_PT_SERVER_TRANSPORTS
		{
			"alpha-1.2.3.4:1111",
			"",
			"alpha:key=value",
		},
		// bad TOR_PT_SERVER_TRANSPORT_OPTIONS
		{
			"alpha-1.2.3.4:1111",
			"alpha",
			"key=value",
		},
		// no escaping is defined for TOR_PT_SERVER_TRANSPORTS or
		// TOR_PT_SERVER_BINDADDR.
		{
			`alpha\,beta-1.2.3.4:1111`,
			`alpha\,beta`,
			"",
		},
		// duplicates in TOR_PT_SERVER_BINDADDR
		// https://bugs.torproject.org/21261
		{
			`alpha-0.0.0.0:1234,alpha-[::]:1234`,
			`alpha`,
			"",
		},
		{
			`alpha-0.0.0.0:1234,alpha-0.0.0.0:1234`,
			`alpha`,
			"",
		},
	}
	goodTests := [...]struct {
		ptServerBindaddr         string
		ptServerTransports       string
		ptServerTransportOptions string
		expected                 []Bindaddr
	}{
		{
			"alpha-1.2.3.4:1111,beta-[1:2::3:4]:2222",
			"alpha,beta,gamma",
			"alpha:k1=v1,beta:k2=v2,gamma:k3=v3",
			[]Bindaddr{
				{"alpha", &net.TCPAddr{IP: net.ParseIP("1.2.3.4"), Port: 1111}, Args{"k1": []string{"v1"}}},
				{"beta", &net.TCPAddr{IP: net.ParseIP("1:2::3:4"), Port: 2222}, Args{"k2": []string{"v2"}}},
			},
		},
		{
			"alpha-1.2.3.4:1111",
			"xxx",
			"",
			[]Bindaddr{},
		},
		{
			"alpha-1.2.3.4:1111",
			"alpha,beta,gamma",
			"",
			[]Bindaddr{
				{"alpha", &net.TCPAddr{IP: net.ParseIP("1.2.3.4"), Port: 1111}, Args{}},
			},
		},
		{
			"trebuchet-127.0.0.1:1984,ballista-127.0.0.1:4891",
			"trebuchet,ballista",
			"trebuchet:secret=nou;trebuchet:cache=/tmp/cache;ballista:secret=yes",
			[]Bindaddr{
				{"trebuchet", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1984}, Args{"secret": []string{"nou"}, "cache": []string{"/tmp/cache"}}},
				{"ballista", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 4891}, Args{"secret": []string{"yes"}}},
			},
		},
		// In the past, "*" meant to return all known transport names.
		// But now it has no special meaning.
		// https://bugs.torproject.org/15612
		{
			"alpha-1.2.3.4:1111,beta-[1:2::3:4]:2222",
			"*",
			"",
			[]Bindaddr{},
		},
	}

	Stdout = ioutil.Discard

	os.Clearenv()
	_, err := getServerBindaddrs()
	if err == nil {
		t.Errorf("empty environment unexpectedly succeeded")
	}

	for _, test := range badTests {
		os.Setenv("TOR_PT_SERVER_BINDADDR", test.ptServerBindaddr)
		os.Setenv("TOR_PT_SERVER_TRANSPORTS", test.ptServerTransports)
		os.Setenv("TOR_PT_SERVER_TRANSPORT_OPTIONS", test.ptServerTransportOptions)
		_, err := getServerBindaddrs()
		if err == nil {
			t.Errorf("TOR_PT_SERVER_BINDADDR=%q TOR_PT_SERVER_TRANSPORTS=%q TOR_PT_SERVER_TRANSPORT_OPTIONS=%q unexpectedly succeeded",
				test.ptServerBindaddr, test.ptServerTransports, test.ptServerTransportOptions)
		}
	}

	for _, test := range goodTests {
		os.Setenv("TOR_PT_SERVER_BINDADDR", test.ptServerBindaddr)
		os.Setenv("TOR_PT_SERVER_TRANSPORTS", test.ptServerTransports)
		os.Setenv("TOR_PT_SERVER_TRANSPORT_OPTIONS", test.ptServerTransportOptions)
		output, err := getServerBindaddrs()
		if err != nil {
			t.Errorf("TOR_PT_SERVER_BINDADDR=%q TOR_PT_SERVER_TRANSPORTS=%q TOR_PT_SERVER_TRANSPORT_OPTIONS=%q unexpectedly returned an error: %s",
				test.ptServerBindaddr, test.ptServerTransports, test.ptServerTransportOptions, err)
		}
		if !bindaddrSetsEqual(output, test.expected) {
			t.Errorf("TOR_PT_SERVER_BINDADDR=%q TOR_PT_SERVER_TRANSPORTS=%q TOR_PT_SERVER_TRANSPORT_OPTIONS=%q → %q (expected %q)",
				test.ptServerBindaddr, test.ptServerTransports, test.ptServerTransportOptions, output, test.expected)
		}
	}
}

func TestReadAuthCookie(t *testing.T) {
	badTests := [...][]byte{
		[]byte(""),
		// bad header
		[]byte("! Impostor ORPort Auth Cookie !\x0a0123456789ABCDEF0123456789ABCDEF"),
		// too short
		[]byte("! Extended ORPort Auth Cookie !\x0a0123456789ABCDEF0123456789ABCDE"),
		// too long
		[]byte("! Extended ORPort Auth Cookie !\x0a0123456789ABCDEF0123456789ABCDEFX"),
	}
	goodTests := [...][]byte{
		[]byte("! Extended ORPort Auth Cookie !\x0a0123456789ABCDEF0123456789ABCDEF"),
	}

	for _, input := range badTests {
		var buf bytes.Buffer
		buf.Write(input)
		_, err := readAuthCookie(&buf)
		if err == nil {
			t.Errorf("%q unexpectedly succeeded", input)
		}
	}

	for _, input := range goodTests {
		var buf bytes.Buffer
		buf.Write(input)
		cookie, err := readAuthCookie(&buf)
		if err != nil {
			t.Errorf("%q unexpectedly returned an error: %s", input, err)
		}
		if !bytes.Equal(cookie, input[32:64]) {
			t.Errorf("%q → %q (expected %q)", input, cookie, input[:32])
		}
	}
}

func TestComputeServerHash(t *testing.T) {
	authCookie := make([]byte, 32)
	clientNonce := make([]byte, 32)
	serverNonce := make([]byte, 32)
	// hmac.new("\x00"*32, "ExtORPort authentication server-to-client hash" + "\x00"*64, hashlib.sha256).hexdigest()
	expected := []byte("\x9e\x22\x19\x19\x98\x2a\x84\xf7\x5f\xaf\x60\xef\x92\x69\x49\x79\x62\x68\xc9\x78\x33\xe0\x69\x60\xff\x26\x53\x69\xa9\x0f\xd6\xd8")
	hash := computeServerHash(authCookie, clientNonce, serverNonce)
	if !bytes.Equal(hash, expected) {
		t.Errorf("%x %x %x → %x (expected %x)", authCookie,
			clientNonce, serverNonce, hash, expected)
	}
}

func TestComputeClientHash(t *testing.T) {
	authCookie := make([]byte, 32)
	clientNonce := make([]byte, 32)
	serverNonce := make([]byte, 32)
	// hmac.new("\x00"*32, "ExtORPort authentication client-to-server hash" + "\x00"*64, hashlib.sha256).hexdigest()
	expected := []byte("\x0f\x36\x8b\x1b\xee\x24\xaa\xbc\x54\xa9\x11\x4c\xe0\x6c\x07\x0f\x3e\xd9\x9d\x0d\x36\x8f\x59\x9c\xcc\x6d\xfd\xc8\xbf\x45\x7a\x62")
	hash := computeClientHash(authCookie, clientNonce, serverNonce)
	if !bytes.Equal(hash, expected) {
		t.Errorf("%x %x %x → %x (expected %x)", authCookie,
			clientNonce, serverNonce, hash, expected)
	}
}

// Elide a byte slice in case it's really long.
func fmtBytes(s []byte) string {
	if len(s) > 100 {
		return fmt.Sprintf("%q...(%d bytes)", s[:5], len(s))
	} else {
		return fmt.Sprintf("%q", s)
	}
}

func TestExtOrSendCommand(t *testing.T) {
	badTests := [...]struct {
		cmd  uint16
		body []byte
	}{
		{0x0, make([]byte, 65536)},
		{0x1234, make([]byte, 65536)},
	}
	longBody := [65535 + 2 + 2]byte{0x12, 0x34, 0xff, 0xff}
	goodTests := [...]struct {
		cmd      uint16
		body     []byte
		expected []byte
	}{
		{0x0, []byte(""), []byte("\x00\x00\x00\x00")},
		{0x5, []byte(""), []byte("\x00\x05\x00\x00")},
		{0xfffe, []byte(""), []byte("\xff\xfe\x00\x00")},
		{0xffff, []byte(""), []byte("\xff\xff\x00\x00")},
		{0x1234, []byte("hello"), []byte("\x12\x34\x00\x05hello")},
		{0x1234, make([]byte, 65535), longBody[:]},
	}

	for _, test := range badTests {
		var buf bytes.Buffer
		err := extOrPortSendCommand(&buf, test.cmd, test.body)
		if err == nil {
			t.Errorf("0x%04x %s unexpectedly succeeded", test.cmd, fmtBytes(test.body))
		}
	}

	for _, test := range goodTests {
		var buf bytes.Buffer
		err := extOrPortSendCommand(&buf, test.cmd, test.body)
		if err != nil {
			t.Errorf("0x%04x %s unexpectedly returned an error: %s", test.cmd, fmtBytes(test.body), err)
		}
		p := make([]byte, 65535+2+2)
		n, err := buf.Read(p)
		if err != nil {
			t.Fatal(err)
		}
		output := p[:n]
		if !bytes.Equal(output, test.expected) {
			t.Errorf("0x%04x %s → %s (expected %s)", test.cmd, fmtBytes(test.body),
				fmtBytes(output), fmtBytes(test.expected))
		}
	}
}

func TestExtOrSendUserAddr(t *testing.T) {
	addrs := [...]string{
		"0.0.0.0:0",
		"1.2.3.4:9999",
		"255.255.255.255:65535",
		"[::]:0",
		"[ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255]:63335",
	}

	for _, addr := range addrs {
		var buf bytes.Buffer
		err := extOrPortSendUserAddr(&buf, addr)
		if err != nil {
			t.Errorf("%s unexpectedly returned an error: %s", addr, err)
		}
		var cmd, length uint16
		binary.Read(&buf, binary.BigEndian, &cmd)
		if cmd != extOrCmdUserAddr {
			t.Errorf("%s → cmd 0x%04x (expected 0x%04x)", addr, cmd, extOrCmdUserAddr)
		}
		binary.Read(&buf, binary.BigEndian, &length)
		p := make([]byte, length+1)
		n, err := buf.Read(p)
		if n != int(length) {
			t.Errorf("%s said length %d but had at least %d", addr, length, n)
		}
		// test that parsing the address gives something equivalent to
		// parsing the original.
		inputAddr, err := resolveAddr(addr)
		if err != nil {
			t.Fatal(err)
		}
		outputAddr, err := resolveAddr(string(p[:n]))
		if err != nil {
			t.Fatal(err)
		}
		if !tcpAddrsEqual(inputAddr, outputAddr) {
			t.Errorf("%s → %s", addr, outputAddr)
		}
	}
}

func TestExtOrPortSendTransport(t *testing.T) {
	tests := [...]struct {
		methodName string
		expected   []byte
	}{
		{"", []byte("\x00\x02\x00\x00")},
		{"a", []byte("\x00\x02\x00\x01a")},
		{"alpha", []byte("\x00\x02\x00\x05alpha")},
	}

	for _, test := range tests {
		var buf bytes.Buffer
		err := extOrPortSendTransport(&buf, test.methodName)
		if err != nil {
			t.Errorf("%q unexpectedly returned an error: %s", test.methodName, err)
		}
		p := make([]byte, 1024)
		n, err := buf.Read(p)
		if err != nil {
			t.Fatal(err)
		}
		output := p[:n]
		if !bytes.Equal(output, test.expected) {
			t.Errorf("%q → %s (expected %s)", test.methodName,
				fmtBytes(output), fmtBytes(test.expected))
		}
	}
}

func TestExtOrPortSendDone(t *testing.T) {
	expected := []byte("\x00\x00\x00\x00")

	var buf bytes.Buffer
	err := extOrPortSendDone(&buf)
	if err != nil {
		t.Errorf("unexpectedly returned an error: %s", err)
	}
	p := make([]byte, 1024)
	n, err := buf.Read(p)
	if err != nil {
		t.Fatal(err)
	}
	output := p[:n]
	if !bytes.Equal(output, expected) {
		t.Errorf("→ %s (expected %s)", fmtBytes(output), fmtBytes(expected))
	}
}

func TestExtOrPortRecvCommand(t *testing.T) {
	badTests := [...][]byte{
		[]byte(""),
		[]byte("\x12"),
		[]byte("\x12\x34"),
		[]byte("\x12\x34\x00"),
		[]byte("\x12\x34\x00\x01"),
	}
	goodTests := [...]struct {
		input    []byte
		cmd      uint16
		body     []byte
		leftover []byte
	}{
		{
			[]byte("\x12\x34\x00\x00"),
			0x1234, []byte(""), []byte(""),
		},
		{
			[]byte("\x12\x34\x00\x00more"),
			0x1234, []byte(""), []byte("more"),
		},
		{
			[]byte("\x12\x34\x00\x04body"),
			0x1234, []byte("body"), []byte(""),
		},
		{
			[]byte("\x12\x34\x00\x04bodymore"),
			0x1234, []byte("body"), []byte("more"),
		},
	}

	for _, input := range badTests {
		var buf bytes.Buffer
		buf.Write(input)
		_, _, err := extOrPortRecvCommand(&buf)
		if err == nil {
			t.Errorf("%q unexpectedly succeeded", fmtBytes(input))
		}
	}

	for _, test := range goodTests {
		var buf bytes.Buffer
		buf.Write(test.input)
		cmd, body, err := extOrPortRecvCommand(&buf)
		if err != nil {
			t.Errorf("%s unexpectedly returned an error: %s", fmtBytes(test.input), err)
		}
		if cmd != test.cmd {
			t.Errorf("%s → cmd 0x%04x (expected 0x%04x)", fmtBytes(test.input), cmd, test.cmd)
		}
		if !bytes.Equal(body, test.body) {
			t.Errorf("%s → body %s (expected %s)", fmtBytes(test.input),
				fmtBytes(body), fmtBytes(test.body))
		}
		p := make([]byte, 1024)
		n, err := buf.Read(p)
		if err != nil && err != io.EOF {
			t.Fatal(err)
		}
		leftover := p[:n]
		if !bytes.Equal(leftover, test.leftover) {
			t.Errorf("%s → leftover %s (expected %s)", fmtBytes(test.input),
				fmtBytes(leftover), fmtBytes(test.leftover))
		}
	}
}

// set up so that extOrPortSetMetadata can write to one buffer and read from another.
type mockSetMetadataBuf struct {
	ReadBuf  bytes.Buffer
	WriteBuf bytes.Buffer
}

func (buf *mockSetMetadataBuf) Read(p []byte) (int, error) {
	return buf.ReadBuf.Read(p)
}

func (buf *mockSetMetadataBuf) Write(p []byte) (int, error) {
	return buf.WriteBuf.Write(p)
}

func testExtOrPortSetMetadataIndividual(t *testing.T, addr, methodName string) {
	var err error
	var buf mockSetMetadataBuf
	// fake an OKAY response.
	err = extOrPortSendCommand(&buf.ReadBuf, extOrCmdOkay, []byte{})
	if err != nil {
		panic(err)
	}
	err = extOrPortSetMetadata(&buf, addr, methodName)
	if err != nil {
		t.Fatalf("error in extOrPortSetMetadata: %s", err)
	}
	for {
		cmd, body, err := extOrPortRecvCommand(&buf.WriteBuf)
		if err != nil {
			t.Fatalf("error in extOrPortRecvCommand: %s", err)
		}
		if cmd == extOrCmdDone {
			break
		}
		if addr != "" && cmd == extOrCmdUserAddr {
			if string(body) != addr {
				t.Errorf("addr=%q methodName=%q got USERADDR with body %q (expected %q)", addr, methodName, body, addr)
			}
			continue
		}
		if methodName != "" && cmd == extOrCmdTransport {
			if string(body) != methodName {
				t.Errorf("addr=%q methodName=%q got TRANSPORT with body %q (expected %q)", addr, methodName, body, methodName)
			}
			continue
		}
		t.Errorf("addr=%q methodName=%q got unknown cmd %d body %q", addr, methodName, cmd, body)
	}
}

func TestExtOrPortSetMetadata(t *testing.T) {
	const addr = "127.0.0.1:40000"
	const methodName = "alpha"
	testExtOrPortSetMetadataIndividual(t, "", "")
	testExtOrPortSetMetadataIndividual(t, addr, "")
	testExtOrPortSetMetadataIndividual(t, "", methodName)
	testExtOrPortSetMetadataIndividual(t, addr, methodName)
}

func simulateServerExtOrPortAuth(r io.Reader, w io.Writer, authCookie []byte) error {
	// send auth types
	_, err := w.Write([]byte{1, 0})
	if err != nil {
		return err
	}
	// read client auth type
	buf := make([]byte, 1)
	_, err = io.ReadFull(r, buf)
	if err != nil {
		return err
	}
	if buf[0] != 1 {
		return fmt.Errorf("didn't get client auth type 1")
	}
	// read client nonce
	clientNonce := make([]byte, 32)
	_, err = io.ReadFull(r, clientNonce)
	if err != nil {
		return err
	}
	// send server hash and nonce
	serverNonce := make([]byte, 32)
	serverHash := computeServerHash(authCookie, clientNonce, serverNonce)
	_, err = w.Write(serverHash)
	if err != nil {
		return err
	}
	_, err = w.Write(serverNonce)
	if err != nil {
		return err
	}
	// read client hash
	clientHash := make([]byte, 32)
	_, err = io.ReadFull(r, clientHash)
	if err != nil {
		return err
	}
	// send success status
	_, err = w.Write([]byte{1})
	if err != nil {
		return err
	}
	return nil
}

type failSetDeadlineAfter struct {
	n   int
	err error
}

func (c *failSetDeadlineAfter) try() error {
	if c.n > 0 {
		c.n--
		return nil
	}
	return c.err
}

func (c *failSetDeadlineAfter) SetDeadline(_ time.Time) error {
	return c.try()
}

func (c *failSetDeadlineAfter) SetReadDeadline(_ time.Time) error {
	return c.try()
}

func (c *failSetDeadlineAfter) SetWriteDeadline(_ time.Time) error {
	return c.try()
}

// a fake Conn whose Set*Deadline functions fail after a certain number of
// calls.
type connFailSetDeadline struct {
	io.Reader
	io.Writer
	failSetDeadlineAfter
}

func (c *connFailSetDeadline) Close() error {
	return nil
}

func (c *connFailSetDeadline) LocalAddr() net.Addr {
	return &net.IPAddr{net.IPv4(0, 0, 0, 0), ""}
}

func (c *connFailSetDeadline) RemoteAddr() net.Addr {
	return &net.IPAddr{net.IPv4(0, 0, 0, 0), ""}
}

// Test that a failure of SetDeadline is reported.
func TestExtOrPortSetupFailSetDeadline(t *testing.T) {
	authCookie, err := readAuthCookieFile(testAuthCookiePath)
	if err != nil {
		panic(err)
	}

	// extOrPortSetup calls SetDeadline twice, so try failing the call after
	// differing delays.
	expectedErr := fmt.Errorf("distinguished error")
	for _, delay := range []int{0, 1, 2} {
		upstreamR, upstreamW := io.Pipe()
		downstreamR, downstreamW := io.Pipe()

		// mock ExtORPort to talk to
		go func() {
			// handle auth
			err := simulateServerExtOrPortAuth(upstreamR, downstreamW, authCookie)
			if err != nil {
				return
			}
			// discard succeeding client data
			go func() {
				io.Copy(ioutil.Discard, upstreamR)
			}()
			// fake an OKAY response.
			err = extOrPortSendCommand(downstreamW, extOrCmdOkay, []byte{})
			if err != nil {
				return
			}
		}()

		// make a Conn that will fail SetDeadline after a certain number
		// of calls.
		s := &connFailSetDeadline{downstreamR, upstreamW, failSetDeadlineAfter{delay, expectedErr}}
		serverInfo := &ServerInfo{AuthCookiePath: testAuthCookiePath}
		err = extOrPortSetup(s, 1*time.Second, serverInfo, "", "")
		if delay < 2 && err != expectedErr {
			t.Fatalf("delay %v: expected error %v, got %v", delay, expectedErr, err)
		} else if delay >= 2 && err != nil {
			t.Fatalf("delay %v: got error %v", delay, err)
		}
	}
}

func TestMakeStateDir(t *testing.T) {
	os.Clearenv()

	// TOR_PT_STATE_LOCATION not set.
	_, err := MakeStateDir()
	if err == nil {
		t.Errorf("empty environment unexpectedly succeeded")
	}

	// Setup the scratch directory.
	tempDir, err := ioutil.TempDir("", "testMakeStateDir")
	if err != nil {
		t.Fatalf("ioutil.TempDir failed: %s", err)
	}
	defer os.RemoveAll(tempDir)

	goodTests := [...]string{
		// Already existing directory.
		tempDir,

		// Nonexistent directory, parent exists.
		path.Join(tempDir, "parentExists"),

		// Nonexistent directory, parent doesn't exist.
		path.Join(tempDir, "missingParent", "parentMissing"),
	}
	for _, test := range goodTests {
		os.Setenv("TOR_PT_STATE_LOCATION", test)
		dir, err := MakeStateDir()
		if err != nil {
			t.Errorf("MakeStateDir unexpectedly failed: %s", err)
		}
		if dir != test {
			t.Errorf("MakeStateDir returned an unexpected path %s (expecting %s)", dir, test)
		}
	}

	// Name already exists, but is an ordinary file.
	tempFile := path.Join(tempDir, "file")
	f, err := os.Create(tempFile)
	if err != nil {
		t.Fatalf("os.Create failed: %s", err)
	}
	defer f.Close()
	os.Setenv("TOR_PT_STATE_LOCATION", tempFile)
	_, err = MakeStateDir()
	if err == nil {
		t.Errorf("MakeStateDir with a file unexpectedly succeeded")
	}

	// Directory name that cannot be created. (Subdir of a file)
	os.Setenv("TOR_PT_STATE_LOCATION", path.Join(tempFile, "subDir"))
	_, err = MakeStateDir()
	if err == nil {
		t.Errorf("MakeStateDir with a subdirectory of a file unexpectedly succeeded")
	}
}

// Compare with unescape_string in tor's src/lib/encoding/cstring.c. That
// function additionally allows hex escapes, but control-spec.txt's CString
// doesn't say anything about that.
func decodeCString(enc string) (string, error) {
	var result bytes.Buffer
	b := []byte(enc)
	state := "^"
	number := 0
	i := 0
	for i < len(b) {
		c := b[i]
		switch state {
		case "^":
			if c != '"' {
				return "", fmt.Errorf("missing start quote")
			}
			state = "."
		case ".":
			switch c {
			case '\\':
				state = "\\"
			case '"':
				state = "$"
			default:
				result.WriteByte(c)
			}
		case "\\":
			switch c {
			case 'n':
				result.WriteByte('\n')
				state = "."
			case 't':
				result.WriteByte('\t')
				state = "."
			case 'r':
				result.WriteByte('\r')
				state = "."
			case '"', '\\':
				result.WriteByte(c)
				state = "."
			case '0', '1', '2', '3', '4', '5', '6', '7':
				number = int(c - '0')
				state = "o1"
			default:
				return "", fmt.Errorf("unknown escape \\%c", c)
			}
		case "o1": // 1 octal digit read
			switch c {
			case '0', '1', '2', '3', '4', '5', '6', '7':
				number = number*8 + int(c-'0')
				state = "o2"
			default:
				if number > 255 {
					return "", fmt.Errorf("invalid octal escape")
				}
				result.WriteByte(byte(number))
				state = "."
				continue // process the current byte again
			}
		case "o2": // 2 octal digits read
			switch c {
			case '0', '1', '2', '3', '4', '5', '6', '7':
				number = number*8 + int(c-'0')
				if number > 255 {
					return "", fmt.Errorf("invalid octal escape")
				}
				result.WriteByte(byte(number))
				state = "."
			default:
				if number > 255 {
					return "", fmt.Errorf("invalid octal escape")
				}
				result.WriteByte(byte(number))
				state = "."
				continue // process the current byte again
			}
		case "$":
			return "", fmt.Errorf("trailing garbage")
		}
		i++
	}
	if state != "$" {
		return "", fmt.Errorf("unexpected end of string")
	}
	return result.String(), nil
}

func roundtripCString(src string) (string, error) {
	enc := encodeCString(src)
	dec, err := decodeCString(enc)
	if err != nil {
		return enc, fmt.Errorf("failed to decode: %+q → %+q: %v", src, enc, err)
	}
	if dec != src {
		return enc, fmt.Errorf("roundtrip failed: %+q → %+q → %+q", src, enc, dec)
	}
	return enc, nil
}

func TestEncodeCString(t *testing.T) {
	tests := []string{
		"",
		"\"",
		"\"\"",
		"abc\"def",
		"\\",
		"\\\\",
		"\x0123abc", // trap here is if you encode '\x01' as "\\1"; it would join with the following digits: "\\123abc".
		"\n\r\t\x7f",
		"\\377",
	}
	allBytes := make([]byte, 256)
	for i := 0; i < len(allBytes); i++ {
		allBytes[i] = byte(i)
	}
	tests = append(tests, string(allBytes))

	for _, test := range tests {
		enc, err := roundtripCString(test)
		if err != nil {
			t.Error(err)
		}
		if !argIsSafe(enc) {
			t.Errorf("escaping %+q resulted in non-safe %+q", test, enc)
		}
	}
}
