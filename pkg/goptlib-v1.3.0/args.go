package pt

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
)

// Key–value mappings for the representation of client and server options.

// Args maps a string key to a list of values. It is similar to url.Values.
type Args map[string][]string

// Get the first value associated with the given key. If there are any values
// associated with the key, the value return has the value and ok is set to
// true. If there are no values for the given key, value is "" and ok is false.
// If you need access to multiple values, use the map directly.
func (args Args) Get(key string) (value string, ok bool) {
	if args == nil {
		return "", false
	}
	vals, ok := args[key]
	if !ok || len(vals) == 0 {
		return "", false
	}
	return vals[0], true
}

// Append value to the list of values for key.
func (args Args) Add(key, value string) {
	args[key] = append(args[key], value)
}

// Return the index of the next unescaped byte in s that is in the term set, or
// else the length of the string if no terminators appear. Additionally return
// the unescaped string up to the returned index.
func indexUnescaped(s string, term []byte) (int, string, error) {
	var i int
	unesc := make([]byte, 0)
	for i = 0; i < len(s); i++ {
		b := s[i]
		// A terminator byte?
		if bytes.IndexByte(term, b) != -1 {
			break
		}
		if b == '\\' {
			i++
			if i >= len(s) {
				return 0, "", fmt.Errorf("nothing following final escape in %q", s)
			}
			b = s[i]
		}
		unesc = append(unesc, b)
	}
	return i, string(unesc), nil
}

// Parse a name–value mapping as from an encoded SOCKS username/password.
//
// "First the '<Key>=<Value>' formatted arguments MUST be escaped, such that all
// backslash, equal sign, and semicolon characters are escaped with a
// backslash."
func parseClientParameters(s string) (args Args, err error) {
	args = make(Args)
	if len(s) == 0 {
		return
	}
	i := 0
	for {
		var key, value string
		var offset, begin int

		begin = i
		// Read the key.
		offset, key, err = indexUnescaped(s[i:], []byte{'=', ';'})
		if err != nil {
			return
		}
		i += offset
		// End of string or no equals sign?
		if i >= len(s) || s[i] != '=' {
			err = fmt.Errorf("no equals sign in %q", s[begin:i])
			return
		}
		// Skip the equals sign.
		i++
		// Read the value.
		offset, value, err = indexUnescaped(s[i:], []byte{';'})
		if err != nil {
			return
		}
		i += offset
		if len(key) == 0 {
			err = fmt.Errorf("empty key in %q", s[begin:i])
			return
		}
		args.Add(key, value)
		if i >= len(s) {
			break
		}
		// Skip the semicolon.
		i++
	}
	return args, nil
}

// Parse a transport–name–value mapping as from TOR_PT_SERVER_TRANSPORT_OPTIONS.
//
// "...a semicolon-separated list of <key>:<value> pairs, where <key> is a PT
// name and <value> is a k=v string value with options that are to be passed to
// the transport. Colons, semicolons, equal signs and backslashes must be
// escaped with a backslash."
// Example: scramblesuit:key=banana;automata:rule=110;automata:depth=3
func parseServerTransportOptions(s string) (opts map[string]Args, err error) {
	opts = make(map[string]Args)
	if len(s) == 0 {
		return
	}
	i := 0
	for {
		var methodName, key, value string
		var offset, begin int

		begin = i
		// Read the method name.
		offset, methodName, err = indexUnescaped(s[i:], []byte{':', '=', ';'})
		if err != nil {
			return
		}
		i += offset
		// End of string or no colon?
		if i >= len(s) || s[i] != ':' {
			err = fmt.Errorf("no colon in %q", s[begin:i])
			return
		}
		// Skip the colon.
		i++
		// Read the key.
		offset, key, err = indexUnescaped(s[i:], []byte{'=', ';'})
		if err != nil {
			return
		}
		i += offset
		// End of string or no equals sign?
		if i >= len(s) || s[i] != '=' {
			err = fmt.Errorf("no equals sign in %q", s[begin:i])
			return
		}
		// Skip the equals sign.
		i++
		// Read the value.
		offset, value, err = indexUnescaped(s[i:], []byte{';'})
		if err != nil {
			return
		}
		i += offset
		if len(methodName) == 0 {
			err = fmt.Errorf("empty method name in %q", s[begin:i])
			return
		}
		if len(key) == 0 {
			err = fmt.Errorf("empty key in %q", s[begin:i])
			return
		}
		if opts[methodName] == nil {
			opts[methodName] = make(Args)
		}
		opts[methodName].Add(key, value)
		if i >= len(s) {
			break
		}
		// Skip the semicolon.
		i++
	}
	return opts, nil
}

// Escape backslashes and all the bytes that are in set.
func backslashEscape(s string, set []byte) string {
	var buf bytes.Buffer
	for _, b := range []byte(s) {
		if b == '\\' || bytes.IndexByte(set, b) != -1 {
			buf.WriteByte('\\')
		}
		buf.WriteByte(b)
	}
	return buf.String()
}

// Encode a name–value mapping so that it is suitable to go in the ARGS option
// of an SMETHOD line. The output is sorted by key. The "ARGS:" prefix is not
// added.
//
// "Equal signs and commas [and backslashes] MUST be escaped with a backslash."
func encodeSmethodArgs(args Args) string {
	if args == nil {
		return ""
	}

	keys := make([]string, 0, len(args))
	for key := range args {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	escape := func(s string) string {
		return backslashEscape(s, []byte{'=', ','})
	}

	var pairs []string
	for _, key := range keys {
		for _, value := range args[key] {
			pairs = append(pairs, escape(key)+"="+escape(value))
		}
	}

	return strings.Join(pairs, ",")
}
