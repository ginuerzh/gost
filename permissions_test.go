package gost

import (
	"fmt"
	"testing"
)

var portRangeTests = []struct {
	in  string
	out *PortRange
}{
	{"1", &PortRange{Min: 1, Max: 1}},
	{"1-3", &PortRange{Min: 1, Max: 3}},
	{"3-1", &PortRange{Min: 1, Max: 3}},
	{"0-100000", &PortRange{Min: 0, Max: 65535}},
	{"*", &PortRange{Min: 0, Max: 65535}},
}

var stringSetTests = []struct {
	in  string
	out *StringSet
}{
	{"*", &StringSet{"*"}},
	{"google.pl,google.com", &StringSet{"google.pl", "google.com"}},
}

var portSetTests = []struct {
	in  string
	out *PortSet
}{
	{"1,3", &PortSet{PortRange{Min: 1, Max: 1}, PortRange{Min: 3, Max: 3}}},
	{"1-3,7-5", &PortSet{PortRange{Min: 1, Max: 3}, PortRange{Min: 5, Max: 7}}},
	{"0-100000", &PortSet{PortRange{Min: 0, Max: 65535}}},
	{"*", &PortSet{PortRange{Min: 0, Max: 65535}}},
}

var permissionsTests = []struct {
	in  string
	out *Permissions
}{
	{"", &Permissions{}},
	{"*:*:*", &Permissions{
		Permission{
			Actions: StringSet{"*"},
			Hosts:   StringSet{"*"},
			Ports:   PortSet{PortRange{Min: 0, Max: 65535}},
		},
	}},
	{"bind:127.0.0.1,localhost:80,443,8000-8100 connect:*.google.pl:80,443", &Permissions{
		Permission{
			Actions: StringSet{"bind"},
			Hosts:   StringSet{"127.0.0.1", "localhost"},
			Ports: PortSet{
				PortRange{Min: 80, Max: 80},
				PortRange{Min: 443, Max: 443},
				PortRange{Min: 8000, Max: 8100},
			},
		},
		Permission{
			Actions: StringSet{"connect"},
			Hosts:   StringSet{"*.google.pl"},
			Ports: PortSet{
				PortRange{Min: 80, Max: 80},
				PortRange{Min: 443, Max: 443},
			},
		},
	}},
}

func TestPortRangeParse(t *testing.T) {
	for _, test := range portRangeTests {
		actual, err := ParsePortRange(test.in)
		if err != nil {
			t.Errorf("ParsePortRange(%q) returned error: %v", test.in, err)
		} else if *actual != *test.out {
			t.Errorf("ParsePortRange(%q): got %v, want %v", test.in, actual, test.out)
		}
	}
}

func TestPortRangeContains(t *testing.T) {
	actual, _ := ParsePortRange("5-10")

	if !actual.Contains(5) || !actual.Contains(7) || !actual.Contains(10) {
		t.Errorf("5-10 should contain 5, 7 and 10")
	}

	if actual.Contains(4) || actual.Contains(11) {
		t.Errorf("5-10 should not contain 4, 11")
	}
}

func TestStringSetParse(t *testing.T) {
	for _, test := range stringSetTests {
		actual, err := ParseStringSet(test.in)
		if err != nil {
			t.Errorf("ParseStringSet(%q) returned error: %v", test.in, err)
		} else if fmt.Sprintln(actual) != fmt.Sprintln(test.out) {
			t.Errorf("ParseStringSet(%q): got %v, want %v", test.in, actual, test.out)
		}
	}
}

func TestStringSetContains(t *testing.T) {
	ss, _ := ParseStringSet("google.pl,*.google.com")

	if !ss.Contains("google.pl") || !ss.Contains("www.google.com") {
		t.Errorf("google.pl,*.google.com should contain google.pl and www.google.com")
	}

	if ss.Contains("www.google.pl") || ss.Contains("foobar.com") {
		t.Errorf("google.pl,*.google.com shound not contain www.google.pl and foobar.com")
	}
}

func TestPortSetParse(t *testing.T) {
	for _, test := range portSetTests {
		actual, err := ParsePortSet(test.in)
		if err != nil {
			t.Errorf("ParsePortRange(%q) returned error: %v", test.in, err)
		} else if fmt.Sprintln(actual) != fmt.Sprintln(test.out) {
			t.Errorf("ParsePortRange(%q): got %v, want %v", test.in, actual, test.out)
		}
	}
}

func TestPortSetContains(t *testing.T) {
	actual, _ := ParsePortSet("5-10,20-30")

	if !actual.Contains(5) || !actual.Contains(7) || !actual.Contains(10) {
		t.Errorf("5-10,20-30 should contain 5, 7 and 10")
	}

	if !actual.Contains(20) || !actual.Contains(27) || !actual.Contains(30) {
		t.Errorf("5-10,20-30 should contain 20, 27 and 30")
	}

	if actual.Contains(4) || actual.Contains(11) || actual.Contains(31) {
		t.Errorf("5-10,20-30 should not contain 4, 11, 31")
	}
}

func TestPermissionsParse(t *testing.T) {
	for _, test := range permissionsTests {
		actual, err := ParsePermissions(test.in)
		if err != nil {
			t.Errorf("ParsePermissions(%q) returned error: %v", test.in, err)
		} else if fmt.Sprintln(actual) != fmt.Sprintln(test.out) {
			t.Errorf("ParsePermissions(%q): got %v, want %v", test.in, actual, test.out)
		}
	}
}
