package gost

import "testing"
import "net/url"

var nodeTests = []struct {
	in       string
	out      Node
	hasError bool
}{
	{"", Node{}, false},
	{"://", Node{}, true},
	{"localhost", Node{Addr: "localhost", Transport: "tcp"}, false},
	{":", Node{Addr: ":", Transport: "tcp"}, false},
	{":8080", Node{Addr: ":8080", Transport: "tcp"}, false},
	{"http://:8080", Node{Addr: ":8080", Protocol: "http", Transport: "tcp"}, false},
	{"http://localhost:8080", Node{Addr: "localhost:8080", Protocol: "http", Transport: "tcp"}, false},
	{"http://admin:123456@:8080", Node{Addr: ":8080", Protocol: "http", Transport: "tcp", User: url.UserPassword("admin", "123456")}, false},
	{"http://admin@localhost:8080", Node{Addr: "localhost:8080", Protocol: "http", Transport: "tcp", User: url.User("admin")}, false},
	{"http://:123456@localhost:8080", Node{Addr: "localhost:8080", Protocol: "http", Transport: "tcp", User: url.UserPassword("", "123456")}, false},
	{"http://@localhost:8080", Node{Addr: "localhost:8080", Protocol: "http", Transport: "tcp", User: url.User("")}, false},
	{"http://:@localhost:8080", Node{Addr: "localhost:8080", Protocol: "http", Transport: "tcp", User: url.UserPassword("", "")}, false},
	{"https://:8080", Node{Addr: ":8080", Protocol: "http", Transport: "tls"}, false},
	{"socks+tls://:8080", Node{Addr: ":8080", Protocol: "socks5", Transport: "tls"}, false},
	{"tls://:8080", Node{Addr: ":8080", Transport: "tls"}, false},
	{"tcp://:8080/:8081", Node{Addr: ":8080", Remote: ":8081", Protocol: "tcp", Transport: "tcp"}, false},
	{"udp://:8080/:8081", Node{Addr: ":8080", Remote: ":8081", Protocol: "udp", Transport: "udp"}, false},
	{"rtcp://:8080/:8081", Node{Addr: ":8080", Remote: ":8081", Protocol: "rtcp", Transport: "rtcp"}, false},
	{"rudp://:8080/:8081", Node{Addr: ":8080", Remote: ":8081", Protocol: "rudp", Transport: "rudp"}, false},
	{"redirect://:8080", Node{Addr: ":8080", Protocol: "redirect", Transport: "tcp"}, false},
}

func TestParseNode(t *testing.T) {
	for _, test := range nodeTests {
		actual, err := ParseNode(test.in)
		if err != nil {
			if test.hasError {
				t.Logf("ParseNode(%q) got expected error: %v", test.in, err)
				continue
			}
			t.Errorf("ParseNode(%q) got error: %v", test.in, err)
		} else {
			if test.hasError {
				t.Errorf("ParseNode(%q) got %v, but should return error", test.in, actual)
				continue
			}
			if actual.Addr != test.out.Addr || actual.Protocol != test.out.Protocol ||
				actual.Transport != test.out.Transport || actual.Remote != test.out.Remote {
				t.Errorf("ParseNode(%q) got %v, want %v", test.in, actual, test.out)
			}
			if actual.User == nil {
				if test.out.User != nil {
					t.Errorf("ParseNode(%q) got %v, want %v", test.in, actual, test.out)
				}
				continue
			}
			if actual.User != nil {
				if test.out.User == nil {
					t.Errorf("ParseNode(%q) got %v, want %v", test.in, actual, test.out)
					continue
				}
				if *actual.User != *test.out.User {
					t.Errorf("ParseNode(%q) got %v, want %v", test.in, actual, test.out)
				}
			}
		}
	}
}
