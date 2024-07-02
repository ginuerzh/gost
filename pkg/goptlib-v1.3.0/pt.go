// Package pt implements the Tor pluggable transports specification.
//
// Sample client usage:
// 	var ptInfo pt.ClientInfo
// 	...
// 	func handler(conn *pt.SocksConn) error {
// 		defer conn.Close()
// 		remote, err := net.Dial("tcp", conn.Req.Target)
// 		if err != nil {
// 			conn.Reject()
// 			return err
// 		}
// 		defer remote.Close()
// 		err = conn.Grant(remote.RemoteAddr().(*net.TCPAddr))
// 		if err != nil {
// 			return err
// 		}
// 		// do something with conn and remote.
// 		return nil
// 	}
// 	func acceptLoop(ln *pt.SocksListener) error {
// 		defer ln.Close()
// 		for {
// 			conn, err := ln.AcceptSocks()
// 			if err != nil {
// 				if e, ok := err.(net.Error); ok && e.Temporary() {
// 					pt.Log(pt.LogSeverityError, "accept error: " + err.Error())
// 					continue
// 				}
// 				return err
// 			}
// 			go handler(conn)
// 		}
// 		return nil
// 	}
// 	...
// 	func main() {
// 		var err error
// 		ptInfo, err = pt.ClientSetup(nil)
// 		if err != nil {
// 			os.Exit(1)
// 		}
// 		if ptInfo.ProxyURL != nil {
// 			// you need to interpret the proxy URL yourself
// 			// call pt.ProxyDone instead if it's a type you understand
// 			pt.ProxyError(fmt.Sprintf("proxy %s is not supported", ptInfo.ProxyURL))
// 			os.Exit(1)
// 		}
// 		for _, methodName := range ptInfo.MethodNames {
// 			switch methodName {
// 			case "foo":
// 				ln, err := pt.ListenSocks("tcp", "127.0.0.1:0")
// 				if err != nil {
// 					pt.CmethodError(methodName, err.Error())
// 					break
// 				}
// 				go acceptLoop(ln)
// 				pt.Cmethod(methodName, ln.Version(), ln.Addr())
// 			default:
// 				pt.CmethodError(methodName, "no such method")
// 			}
// 		}
// 		pt.CmethodsDone()
// 	}
//
// Sample server usage:
// 	var ptInfo pt.ServerInfo
// 	...
// 	func handler(conn net.Conn) error {
// 		defer conn.Close()
// 		or, err := pt.DialOr(&ptInfo, conn.RemoteAddr().String(), "foo")
// 		if err != nil {
// 			return
// 		}
// 		defer or.Close()
// 		// do something with or and conn
// 		return nil
// 	}
// 	func acceptLoop(ln net.Listener) error {
// 		defer ln.Close()
// 		for {
// 			conn, err := ln.Accept()
// 			if err != nil {
// 				if e, ok := err.(net.Error); ok && e.Temporary() {
// 					continue
// 				}
// 				pt.Log(pt.LogSeverityError, "accept error: " + err.Error())
// 				return err
// 			}
// 			go handler(conn)
// 		}
// 		return nil
// 	}
// 	...
// 	func main() {
// 		var err error
// 		ptInfo, err = pt.ServerSetup(nil)
// 		if err != nil {
// 			os.Exit(1)
// 		}
// 		for _, bindaddr := range ptInfo.Bindaddrs {
// 			switch bindaddr.MethodName {
// 			case "foo":
// 				ln, err := net.ListenTCP("tcp", bindaddr.Addr)
// 				if err != nil {
// 					pt.SmethodError(bindaddr.MethodName, err.Error())
// 					break
// 				}
// 				go acceptLoop(ln)
// 				pt.Smethod(bindaddr.MethodName, ln.Addr())
// 			default:
// 				pt.SmethodError(bindaddr.MethodName, "no such method")
// 			}
// 		}
// 		pt.SmethodsDone()
// 	}
//
// Some additional care is needed to handle signals and shutdown properly. See
// the example programs dummy-client and dummy-server.
//
// Tor pluggable transports specification:
// https://spec.torproject.org/pt-spec
//
// Extended ORPort:
// https://gitweb.torproject.org/torspec.git/tree/ext-orport-spec.txt
//
// The package implements a SOCKS5 server sufficient for a Tor client transport
// plugin.
//
// https://www.ietf.org/rfc/rfc1928.txt
// https://www.ietf.org/rfc/rfc1929.txt
package pt

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// This type wraps a Write method and calls Sync after each Write.
type syncWriter struct {
	*os.File
}

// Call File.Write and then Sync. An error is returned if either operation
// returns an error.
func (w syncWriter) Write(p []byte) (n int, err error) {
	n, err = w.File.Write(p)
	if err != nil {
		return
	}
	err = w.Sync()
	return
}

// Writer to which pluggable transports negotiation messages are written. It
// defaults to a Writer that writes to os.Stdout and calls Sync after each
// write.
//
// You may, for example, log pluggable transports messages by defining a Writer
// that logs what is written to it:
// 	type logWriteWrapper struct {
// 		io.Writer
// 	}
//
// 	func (w logWriteWrapper) Write(p []byte) (int, error) {
// 		log.Print(string(p))
// 		return w.Writer.Write(p)
// 	}
// and then redefining Stdout:
// 	pt.Stdout = logWriteWrapper{pt.Stdout}
var Stdout io.Writer = syncWriter{os.Stdout}

// Represents an error that can happen during negotiation, for example
// ENV-ERROR. When an error occurs, we print it to stdout and also pass it up
// the return chain.
type ptErr struct {
	Keyword string
	Args    []string
}

// Implements the error interface.
func (err *ptErr) Error() string {
	return formatline(err.Keyword, err.Args...)
}

func getenv(key string) string {
	return os.Getenv(key)
}

// Returns an ENV-ERROR if the environment variable isn't set.
func getenvRequired(key string) (string, error) {
	value := os.Getenv(key)
	if value == "" {
		return "", envError(fmt.Sprintf("no %s environment variable", key))
	}
	return value, nil
}

// Returns true iff keyword contains only bytes allowed in a PT→Tor output line
// keyword.
// <KeywordChar> ::= <any US-ASCII alphanumeric, dash, and underscore>
func keywordIsSafe(keyword string) bool {
	for _, b := range []byte(keyword) {
		switch {
		case '0' <= b && b <= '9':
			continue
		case 'A' <= b && b <= 'Z':
			continue
		case 'a' <= b && b <= 'z':
			continue
		case b == '-' || b == '_':
			continue
		default:
			return false
		}
	}
	return true
}

// Returns true iff arg contains only bytes allowed in a PT→Tor output line arg.
// <ArgChar> ::= <any US-ASCII character but NUL or NL>
func argIsSafe(arg string) bool {
	for _, b := range []byte(arg) {
		if b >= '\x80' || b == '\x00' || b == '\n' {
			return false
		}
	}
	return true
}

func formatline(keyword string, v ...string) string {
	var buf bytes.Buffer
	if !keywordIsSafe(keyword) {
		panic(fmt.Sprintf("keyword %q contains forbidden bytes", keyword))
	}
	buf.WriteString(keyword)
	for _, x := range v {
		if !argIsSafe(x) {
			panic(fmt.Sprintf("arg %q contains forbidden bytes", x))
		}
		buf.WriteString(" " + x)
	}
	return buf.String()
}

// Print a pluggable transports protocol line to Stdout. The line consists of a
// keyword followed by any number of space-separated arg strings. Panics if
// there are forbidden bytes in the keyword or the args (pt-spec.txt 2.2.1).
func line(keyword string, v ...string) {
	fmt.Fprintln(Stdout, formatline(keyword, v...))
}

// Emit and return the given error as a ptErr.
func doError(keyword string, v ...string) *ptErr {
	line(keyword, v...)
	return &ptErr{keyword, v}
}

// Emit an ENV-ERROR line with explanation text. Returns a representation of the
// error.
func envError(msg string) error {
	return doError("ENV-ERROR", msg)
}

// Emit a VERSION-ERROR line with explanation text. Returns a representation of
// the error.
func versionError(msg string) error {
	return doError("VERSION-ERROR", msg)
}

// Emit a CMETHOD-ERROR line with explanation text. Returns a representation of
// the error.
func CmethodError(methodName, msg string) error {
	return doError("CMETHOD-ERROR", methodName, msg)
}

// Emit an SMETHOD-ERROR line with explanation text. Returns a representation of
// the error.
func SmethodError(methodName, msg string) error {
	return doError("SMETHOD-ERROR", methodName, msg)
}

// Emit a PROXY-ERROR line with explanation text. Returns a representation of
// the error.
func ProxyError(msg string) error {
	return doError("PROXY-ERROR", msg)
}

// Emit a CMETHOD line. socks must be "socks4" or "socks5". Call this once for
// each listening client SOCKS port.
func Cmethod(name string, socks string, addr net.Addr) {
	line("CMETHOD", name, socks, addr.String())
}

// Emit a CMETHODS DONE line. Call this after opening all client listeners.
func CmethodsDone() {
	line("CMETHODS", "DONE")
}

// Emit an SMETHOD line. Call this once for each listening server port.
func Smethod(name string, addr net.Addr) {
	line("SMETHOD", name, addr.String())
}

// Emit an SMETHOD line with an ARGS option. args is a name–value mapping that
// will be added to the server's extrainfo document.
//
// This is an example of how to check for a required option:
// 	secret, ok := bindaddr.Options.Get("shared-secret")
// 	if ok {
// 		args := pt.Args{}
// 		args.Add("shared-secret", secret)
// 		pt.SmethodArgs(bindaddr.MethodName, ln.Addr(), args)
// 	} else {
// 		pt.SmethodError(bindaddr.MethodName, "need a shared-secret option")
// 	}
// Or, if you just want to echo back the options provided by Tor from the
// TransportServerOptions configuration,
// 	pt.SmethodArgs(bindaddr.MethodName, ln.Addr(), bindaddr.Options)
func SmethodArgs(name string, addr net.Addr, args Args) {
	line("SMETHOD", name, addr.String(), "ARGS:"+encodeSmethodArgs(args))
}

// Emit an SMETHODS DONE line. Call this after opening all server listeners.
func SmethodsDone() {
	line("SMETHODS", "DONE")
}

// Emit a PROXY DONE line. Call this after parsing ClientInfo.ProxyURL.
func ProxyDone() {
	fmt.Fprintf(Stdout, "PROXY DONE\n")
}

// Unexported type to represent log severities, preventing external callers from
// inventing new severity strings that may violate quoting rules.
//
// pt-spec.txt section 3.3.4 specifies quoting for MESSAGE, but not for
// SEVERITY, and the example shows an unquoted "SEVERITY=debug". While we know
// tor's parser permits quoting of SEVERITY, it's not actually specified.
// Therefore we we need to guard against callers passing a string that violates
// the global protocol constraint of "any US-ASCII character but NUL or NL." So
// here, we instantiate exactly the five supported severities, using a type that
// cannot be constructed outside the package.
type logSeverity struct {
	string
}

// Severity levels for the Log function.
var (
	LogSeverityError   = logSeverity{"error"}
	LogSeverityWarning = logSeverity{"warning"}
	LogSeverityNotice  = logSeverity{"notice"}
	LogSeverityInfo    = logSeverity{"info"}
	LogSeverityDebug   = logSeverity{"debug"}
)

// Encode a string according to the CString rules of section 2.1.1 in
// control-spec.txt.
// 	CString = DQUOTE *qcontent DQUOTE
// "...in a CString, the escapes '\n', '\t', '\r', and the octal escapes '\0'
// ... '\377' represent newline, tab, carriage return, and the 256 possible
// octet values respectively."
// RFC 2822 section 3.2.5 in turn defines what byte values we need to escape:
// everything but
// 	NO-WS-CTL /     ; Non white space controls
// 	%d33 /          ; The rest of the US-ASCII
// 	%d35-91 /       ;  characters not including "\"
// 	%d93-126        ;  or the quote character
// Technically control-spec.txt requires us to escape the space character (32),
// but it is an error in the spec: https://bugs.torproject.org/29432.
//
// We additionally need to ensure that whatever we return passes argIsSafe,
// because strings encoded by this function are printed verbatim by Log.
func encodeCString(s string) string {
	result := bytes.NewBuffer([]byte{})
	result.WriteByte('"')
	for _, c := range []byte(s) {
		if c == 32 || c == 33 || (35 <= c && c <= 91) || (93 <= c && c <= 126) {
			result.WriteByte(c)
		} else {
			fmt.Fprintf(result, "\\%03o", c)
		}
	}
	result.WriteByte('"')
	return result.String()
}

// Emit a LOG message with the given severity (one of LogSeverityError,
// LogSeverityWarning, LogSeverityNotice, LogSeverityInfo, or LogSeverityDebug).
func Log(severity logSeverity, message string) {
	// "<Message> contains the log message which can be a String or CString..."
	// encodeCString always makes the string safe to emit; i.e., it
	// satisfies argIsSafe.
	line("LOG", "SEVERITY="+severity.string, "MESSAGE="+encodeCString(message))
}

// Get a pluggable transports version offered by Tor and understood by us, if
// any. The only version we understand is "1". This function reads the
// environment variable TOR_PT_MANAGED_TRANSPORT_VER.
func getManagedTransportVer() (string, error) {
	const transportVersion = "1"
	managedTransportVer, err := getenvRequired("TOR_PT_MANAGED_TRANSPORT_VER")
	if err != nil {
		return "", err
	}
	for _, offered := range strings.Split(managedTransportVer, ",") {
		if offered == transportVersion {
			return offered, nil
		}
	}
	return "", versionError("no-version")
}

// Return the directory name in the TOR_PT_STATE_LOCATION environment variable,
// creating it if it doesn't exist. Returns non-nil error if
// TOR_PT_STATE_LOCATION is not set or if there is an error creating the
// directory.
func MakeStateDir() (string, error) {
	dir, err := getenvRequired("TOR_PT_STATE_LOCATION")
	if err != nil {
		return "", err
	}
	err = os.MkdirAll(dir, 0700)
	return dir, err
}

// Get the list of method names requested by Tor. This function reads the
// environment variable TOR_PT_CLIENT_TRANSPORTS.
func getClientTransports() ([]string, error) {
	clientTransports, err := getenvRequired("TOR_PT_CLIENT_TRANSPORTS")
	if err != nil {
		return nil, err
	}
	return strings.Split(clientTransports, ","), nil
}

// Get the upstream proxy URL. Returns nil if no proxy is requested. The
// function ensures that the Scheme and Host fields are set; i.e., that the URL
// is absolute. It additionally checks that the Host field contains both a host
// and a port part. This function reads the environment variable TOR_PT_PROXY.
//
// This function doesn't check that the scheme is one of Tor's supported proxy
// schemes; that is, one of "http", "socks5", or "socks4a". The caller must be
// able to handle any returned scheme (which may be by calling ProxyError if
// it doesn't know how to handle the scheme).
func getProxyURL() (*url.URL, error) {
	rawurl := os.Getenv("TOR_PT_PROXY")
	if rawurl == "" {
		return nil, nil
	}
	u, err := url.Parse(rawurl)
	if err != nil {
		return nil, err
	}
	if u.Scheme == "" {
		return nil, fmt.Errorf("missing scheme")
	}
	if u.Host == "" {
		return nil, fmt.Errorf("missing authority")
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		return nil, err
	}
	if host == "" {
		return nil, fmt.Errorf("missing host")
	}
	if port == "" {
		return nil, fmt.Errorf("missing port")
	}
	return u, nil
}

// This structure is returned by ClientSetup. It consists of a list of method
// names and the upstream proxy URL, if any.
type ClientInfo struct {
	MethodNames []string
	ProxyURL    *url.URL
}

// Check the client pluggable transports environment, emitting an error message
// and returning a non-nil error if any error is encountered. Returns a
// ClientInfo struct.
//
// If your program needs to know whether to call ClientSetup or ServerSetup
// (i.e., if the same program can be run as either a client or a server), check
// whether the TOR_PT_CLIENT_TRANSPORTS environment variable is set:
// 	if os.Getenv("TOR_PT_CLIENT_TRANSPORTS") != "" {
// 		// Client mode; call pt.ClientSetup.
// 	} else {
// 		// Server mode; call pt.ServerSetup.
// 	}
//
// Always pass nil for the unused single parameter. In the past, the parameter
// was a list of transport names to use in case Tor requested "*". That feature
// was never implemented and has been removed from the pluggable transports
// specification.
// https://bugs.torproject.org/15612
func ClientSetup(_ []string) (info ClientInfo, err error) {
	ver, err := getManagedTransportVer()
	if err != nil {
		return
	}
	line("VERSION", ver)

	info.MethodNames, err = getClientTransports()
	if err != nil {
		return
	}

	info.ProxyURL, err = getProxyURL()
	if err != nil {
		return
	}

	return info, nil
}

// A combination of a method name and an address, as extracted from
// TOR_PT_SERVER_BINDADDR.
type Bindaddr struct {
	MethodName string
	Addr       *net.TCPAddr
	// Options from TOR_PT_SERVER_TRANSPORT_OPTIONS that pertain to this
	// transport.
	Options Args
}

func parsePort(portStr string) (int, error) {
	port, err := strconv.ParseUint(portStr, 10, 16)
	return int(port), err
}

// Resolve an address string into a net.TCPAddr. We are a bit more strict than
// net.ResolveTCPAddr; we don't allow an empty host or port, and the host part
// must be a literal IP address.
func resolveAddr(addrStr string) (*net.TCPAddr, error) {
	ipStr, portStr, err := net.SplitHostPort(addrStr)
	if err != nil {
		// Before the fixing of bug #7011, tor doesn't put brackets around IPv6
		// addresses. Split after the last colon, assuming it is a port
		// separator, and try adding the brackets.
		// https://bugs.torproject.org/7011
		parts := strings.Split(addrStr, ":")
		if len(parts) <= 2 {
			return nil, err
		}
		addrStr := "[" + strings.Join(parts[:len(parts)-1], ":") + "]:" + parts[len(parts)-1]
		ipStr, portStr, err = net.SplitHostPort(addrStr)
	}
	if err != nil {
		return nil, err
	}
	if ipStr == "" {
		return nil, net.InvalidAddrError(fmt.Sprintf("address string %q lacks a host part", addrStr))
	}
	if portStr == "" {
		return nil, net.InvalidAddrError(fmt.Sprintf("address string %q lacks a port part", addrStr))
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, net.InvalidAddrError(fmt.Sprintf("not an IP string: %q", ipStr))
	}
	port, err := parsePort(portStr)
	if err != nil {
		return nil, err
	}
	return &net.TCPAddr{IP: ip, Port: port}, nil
}

// Return a new slice, the members of which are those members of addrs having a
// MethodName in methodNames.
func filterBindaddrs(addrs []Bindaddr, methodNames []string) []Bindaddr {
	var result []Bindaddr

	for _, ba := range addrs {
		for _, methodName := range methodNames {
			if ba.MethodName == methodName {
				result = append(result, ba)
				break
			}
		}
	}

	return result
}

// Return an array of Bindaddrs, being the contents of TOR_PT_SERVER_BINDADDR
// with keys filtered by TOR_PT_SERVER_TRANSPORTS. Transport-specific options
// from TOR_PT_SERVER_TRANSPORT_OPTIONS are assigned to the Options member.
func getServerBindaddrs() ([]Bindaddr, error) {
	var result []Bindaddr

	// Parse the list of server transport options.
	serverTransportOptions := getenv("TOR_PT_SERVER_TRANSPORT_OPTIONS")
	optionsMap, err := parseServerTransportOptions(serverTransportOptions)
	if err != nil {
		return nil, envError(fmt.Sprintf("TOR_PT_SERVER_TRANSPORT_OPTIONS: %q: %s", serverTransportOptions, err.Error()))
	}

	// Get the list of all requested bindaddrs.
	serverBindaddr, err := getenvRequired("TOR_PT_SERVER_BINDADDR")
	if err != nil {
		return nil, err
	}
	seenMethods := make(map[string]bool)
	for _, spec := range strings.Split(serverBindaddr, ",") {
		var bindaddr Bindaddr

		parts := strings.SplitN(spec, "-", 2)
		if len(parts) != 2 {
			return nil, envError(fmt.Sprintf("TOR_PT_SERVER_BINDADDR: %q: doesn't contain \"-\"", spec))
		}
		bindaddr.MethodName = parts[0]
		// Check for duplicate method names: "Applications MUST NOT set
		// more than one <address>:<port> pair per PT name."
		if seenMethods[bindaddr.MethodName] {
			return nil, envError(fmt.Sprintf("TOR_PT_SERVER_BINDADDR: %q: duplicate method name %q", spec, bindaddr.MethodName))
		}
		seenMethods[bindaddr.MethodName] = true
		addr, err := resolveAddr(parts[1])
		if err != nil {
			return nil, envError(fmt.Sprintf("TOR_PT_SERVER_BINDADDR: %q: %s", spec, err.Error()))
		}
		bindaddr.Addr = addr
		bindaddr.Options = optionsMap[bindaddr.MethodName]
		result = append(result, bindaddr)
	}

	// Filter by TOR_PT_SERVER_TRANSPORTS.
	serverTransports, err := getenvRequired("TOR_PT_SERVER_TRANSPORTS")
	if err != nil {
		return nil, err
	}
	result = filterBindaddrs(result, strings.Split(serverTransports, ","))

	return result, nil
}

func readAuthCookie(f io.Reader) ([]byte, error) {
	authCookieHeader := []byte("! Extended ORPort Auth Cookie !\x0a")
	buf := make([]byte, 64)

	n, err := io.ReadFull(f, buf)
	if err != nil {
		return nil, err
	}
	// Check that the file ends here.
	n, err = f.Read(make([]byte, 1))
	if n != 0 {
		return nil, fmt.Errorf("file is longer than 64 bytes")
	} else if err != io.EOF {
		return nil, fmt.Errorf("did not find EOF at end of file")
	}
	header := buf[0:32]
	cookie := buf[32:64]
	if subtle.ConstantTimeCompare(header, authCookieHeader) != 1 {
		return nil, fmt.Errorf("missing auth cookie header")
	}

	return cookie, nil
}

// Read and validate the contents of an auth cookie file. Returns the 32-byte
// cookie. See section 4.2.1.2 of 217-ext-orport-auth.txt.
func readAuthCookieFile(filename string) (cookie []byte, err error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer func() {
		closeErr := f.Close()
		if err == nil {
			err = closeErr
		}
	}()

	return readAuthCookie(f)
}

// This structure is returned by ServerSetup. It consists of a list of
// Bindaddrs, an address for the ORPort, an address for the extended ORPort (if
// any), and an authentication cookie (if any).
type ServerInfo struct {
	Bindaddrs      []Bindaddr
	OrAddr         *net.TCPAddr
	ExtendedOrAddr *net.TCPAddr
	AuthCookiePath string
}

// Check the server pluggable transports environment, emitting an error message
// and returning a non-nil error if any error is encountered. Resolves the
// various requested bind addresses, the server ORPort and extended ORPort, and
// reads the auth cookie file. Returns a ServerInfo struct.
//
// If your program needs to know whether to call ClientSetup or ServerSetup
// (i.e., if the same program can be run as either a client or a server), check
// whether the TOR_PT_CLIENT_TRANSPORTS environment variable is set:
// 	if os.Getenv("TOR_PT_CLIENT_TRANSPORTS") != "" {
// 		// Client mode; call pt.ClientSetup.
// 	} else {
// 		// Server mode; call pt.ServerSetup.
// 	}
//
// Always pass nil for the unused single parameter. In the past, the parameter
// was a list of transport names to use in case Tor requested "*". That feature
// was never implemented and has been removed from the pluggable transports
// specification.
// https://bugs.torproject.org/15612
func ServerSetup(_ []string) (info ServerInfo, err error) {
	ver, err := getManagedTransportVer()
	if err != nil {
		return
	}
	line("VERSION", ver)

	info.Bindaddrs, err = getServerBindaddrs()
	if err != nil {
		return
	}

	orPort := getenv("TOR_PT_ORPORT")
	if orPort != "" {
		info.OrAddr, err = resolveAddr(orPort)
		if err != nil {
			err = envError(fmt.Sprintf("cannot resolve TOR_PT_ORPORT %q: %s", orPort, err.Error()))
			return
		}
	}

	info.AuthCookiePath = getenv("TOR_PT_AUTH_COOKIE_FILE")

	extendedOrPort := getenv("TOR_PT_EXTENDED_SERVER_PORT")
	if extendedOrPort != "" {
		if info.AuthCookiePath == "" {
			err = envError("need TOR_PT_AUTH_COOKIE_FILE environment variable with TOR_PT_EXTENDED_SERVER_PORT")
			return
		}
		info.ExtendedOrAddr, err = resolveAddr(extendedOrPort)
		if err != nil {
			err = envError(fmt.Sprintf("cannot resolve TOR_PT_EXTENDED_SERVER_PORT %q: %s", extendedOrPort, err.Error()))
			return
		}
	}

	// Need either OrAddr or ExtendedOrAddr.
	if info.OrAddr == nil && info.ExtendedOrAddr == nil {
		err = envError("need TOR_PT_ORPORT or TOR_PT_EXTENDED_SERVER_PORT environment variable")
		return
	}

	return info, nil
}

// See 217-ext-orport-auth.txt section 4.2.1.3.
func computeServerHash(authCookie, clientNonce, serverNonce []byte) []byte {
	h := hmac.New(sha256.New, authCookie)
	io.WriteString(h, "ExtORPort authentication server-to-client hash")
	h.Write(clientNonce)
	h.Write(serverNonce)
	return h.Sum([]byte{})
}

// See 217-ext-orport-auth.txt section 4.2.1.3.
func computeClientHash(authCookie, clientNonce, serverNonce []byte) []byte {
	h := hmac.New(sha256.New, authCookie)
	io.WriteString(h, "ExtORPort authentication client-to-server hash")
	h.Write(clientNonce)
	h.Write(serverNonce)
	return h.Sum([]byte{})
}

func extOrPortAuthenticate(s io.ReadWriter, info *ServerInfo) error {
	// Read auth types. 217-ext-orport-auth.txt section 4.1.
	var authTypes [256]bool
	var count int
	for count = 0; count < 256; count++ {
		buf := make([]byte, 1)
		_, err := io.ReadFull(s, buf)
		if err != nil {
			return err
		}
		b := buf[0]
		if b == 0 {
			break
		}
		authTypes[b] = true
	}
	if count >= 256 {
		return fmt.Errorf("read 256 auth types without seeing \\x00")
	}

	// We support only type 1, SAFE_COOKIE.
	if !authTypes[1] {
		return fmt.Errorf("server didn't offer auth type 1")
	}
	_, err := s.Write([]byte{1})
	if err != nil {
		return err
	}

	clientNonce := make([]byte, 32)
	clientHash := make([]byte, 32)
	serverNonce := make([]byte, 32)
	serverHash := make([]byte, 32)

	_, err = io.ReadFull(rand.Reader, clientNonce)
	if err != nil {
		return err
	}
	_, err = s.Write(clientNonce)
	if err != nil {
		return err
	}

	_, err = io.ReadFull(s, serverHash)
	if err != nil {
		return err
	}
	_, err = io.ReadFull(s, serverNonce)
	if err != nil {
		return err
	}

	// Work around tor bug #15240 where the auth cookie is generated after
	// pluggable transports are launched, leading to a stale cookie getting
	// cached forever if it is only read once as part of ServerSetup.
	// https://bugs.torproject.org/15240
	authCookie, err := readAuthCookieFile(info.AuthCookiePath)
	if err != nil {
		return fmt.Errorf("error reading TOR_PT_AUTH_COOKIE_FILE %q: %s", info.AuthCookiePath, err.Error())
	}

	expectedServerHash := computeServerHash(authCookie, clientNonce, serverNonce)
	if subtle.ConstantTimeCompare(serverHash, expectedServerHash) != 1 {
		return fmt.Errorf("mismatch in server hash")
	}

	clientHash = computeClientHash(authCookie, clientNonce, serverNonce)
	_, err = s.Write(clientHash)
	if err != nil {
		return err
	}

	status := make([]byte, 1)
	_, err = io.ReadFull(s, status)
	if err != nil {
		return err
	}
	if status[0] != 1 {
		return fmt.Errorf("server rejected authentication")
	}

	return nil
}

// See section 3.1.1 of 196-transport-control-ports.txt.
const (
	extOrCmdDone      = 0x0000
	extOrCmdUserAddr  = 0x0001
	extOrCmdTransport = 0x0002
	extOrCmdOkay      = 0x1000
	extOrCmdDeny      = 0x1001
)

func extOrPortSendCommand(s io.Writer, cmd uint16, body []byte) error {
	var buf bytes.Buffer
	if len(body) > 65535 {
		return fmt.Errorf("body length %d exceeds maximum of 65535", len(body))
	}
	err := binary.Write(&buf, binary.BigEndian, cmd)
	if err != nil {
		return err
	}
	err = binary.Write(&buf, binary.BigEndian, uint16(len(body)))
	if err != nil {
		return err
	}
	err = binary.Write(&buf, binary.BigEndian, body)
	if err != nil {
		return err
	}
	_, err = s.Write(buf.Bytes())
	if err != nil {
		return err
	}

	return nil
}

// Send a USERADDR command on s. See section 3.1.2.1 of
// 196-transport-control-ports.txt.
func extOrPortSendUserAddr(s io.Writer, addr string) error {
	return extOrPortSendCommand(s, extOrCmdUserAddr, []byte(addr))
}

// Send a TRANSPORT command on s. See section 3.1.2.2 of
// 196-transport-control-ports.txt.
func extOrPortSendTransport(s io.Writer, methodName string) error {
	return extOrPortSendCommand(s, extOrCmdTransport, []byte(methodName))
}

// Send a DONE command on s. See section 3.1 of 196-transport-control-ports.txt.
func extOrPortSendDone(s io.Writer) error {
	return extOrPortSendCommand(s, extOrCmdDone, []byte{})
}

func extOrPortRecvCommand(s io.Reader) (cmd uint16, body []byte, err error) {
	var bodyLen uint16
	data := make([]byte, 4)

	_, err = io.ReadFull(s, data)
	if err != nil {
		return
	}
	buf := bytes.NewBuffer(data)
	err = binary.Read(buf, binary.BigEndian, &cmd)
	if err != nil {
		return
	}
	err = binary.Read(buf, binary.BigEndian, &bodyLen)
	if err != nil {
		return
	}
	body = make([]byte, bodyLen)
	_, err = io.ReadFull(s, body)
	if err != nil {
		return
	}

	return cmd, body, err
}

// Send USERADDR and TRANSPORT commands followed by a DONE command. Wait for an
// OKAY or DENY response command from the server. If addr or methodName is "",
// the corresponding command is not sent. Returns nil if and only if OKAY is
// received.
func extOrPortSetMetadata(s io.ReadWriter, addr, methodName string) error {
	var err error

	if addr != "" {
		err = extOrPortSendUserAddr(s, addr)
		if err != nil {
			return err
		}
	}
	if methodName != "" {
		err = extOrPortSendTransport(s, methodName)
		if err != nil {
			return err
		}
	}
	err = extOrPortSendDone(s)
	if err != nil {
		return err
	}
	cmd, _, err := extOrPortRecvCommand(s)
	if err != nil {
		return err
	}
	if cmd == extOrCmdDeny {
		return fmt.Errorf("server returned DENY after our USERADDR and DONE")
	} else if cmd != extOrCmdOkay {
		return fmt.Errorf("server returned unknown command 0x%04x after our USERADDR and DONE", cmd)
	}

	return nil
}

func extOrPortSetup(s net.Conn, timeout time.Duration,
	info *ServerInfo, addr, methodName string) error {
	err := s.SetDeadline(time.Now().Add(timeout))
	if err != nil {
		return err
	}
	err = extOrPortAuthenticate(s, info)
	if err != nil {
		return err
	}
	err = extOrPortSetMetadata(s, addr, methodName)
	if err != nil {
		return err
	}
	err = s.SetDeadline(time.Time{})
	if err != nil {
		return err
	}
	return nil
}

// Dial (using the given net.Dialer) info.ExtendedOrAddr if defined, or else
// info.OrAddr, and return an open net.Conn. If connecting to the extended
// OR port, extended OR port authentication à la 217-ext-orport-auth.txt is done
// before returning; an error is returned if authentication fails.
//
// The addr and methodName arguments are put in USERADDR and TRANSPORT ExtOrPort
// commands, respectively. If either is "", the corresponding command is not
// sent.
func DialOrWithDialer(dialer *net.Dialer, info *ServerInfo, addr, methodName string) (net.Conn, error) {
	if info.ExtendedOrAddr == nil || info.AuthCookiePath == "" {
		return dialer.Dial("tcp", info.OrAddr.String())
	}

	s, err := dialer.Dial("tcp", info.ExtendedOrAddr.String())
	if err != nil {
		return nil, err
	}
	err = extOrPortSetup(s, 5*time.Second, info, addr, methodName)
	if err != nil {
		s.Close()
		return nil, err
	}

	return s, nil
}

// Dial info.ExtendedOrAddr if defined, or else info.OrAddr, and return an open
// *net.TCPConn. If connecting to the extended OR port, extended OR port
// authentication à la 217-ext-orport-auth.txt is done before returning; an
// error is returned if authentication fails.
//
// The addr and methodName arguments are put in USERADDR and TRANSPORT ExtOrPort
// commands, respectively. If either is "", the corresponding command is not
// sent.
func DialOr(info *ServerInfo, addr, methodName string) (*net.TCPConn, error) {
	c, err := DialOrWithDialer(&net.Dialer{}, info, addr, methodName)
	return c.(*net.TCPConn), err
}
