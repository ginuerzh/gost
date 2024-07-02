package pt

import (
	"testing"
)

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func argsEqual(a, b Args) bool {
	for k, av := range a {
		bv := b[k]
		if !stringSlicesEqual(av, bv) {
			return false
		}
	}
	for k, bv := range b {
		av := a[k]
		if !stringSlicesEqual(av, bv) {
			return false
		}
	}
	return true
}

func TestArgsGet(t *testing.T) {
	args := Args{
		"a": []string{},
		"b": []string{"value"},
		"c": []string{"v1", "v2", "v3"},
	}
	var uninit Args

	var v string
	var ok bool

	// Get on nil map should be the same as Get on empty map.
	v, ok = uninit.Get("a")
	if !(v == "" && !ok) {
		t.Errorf("unexpected result from Get on nil Args: %q %v", v, ok)
	}

	v, ok = args.Get("a")
	if ok {
		t.Errorf("Unexpected Get success for %q", "a")
	}
	if v != "" {
		t.Errorf("Get failure returned other than %q: %q", "", v)
	}
	v, ok = args.Get("b")
	if !ok {
		t.Errorf("Unexpected Get failure for %q", "b")
	}
	if v != "value" {
		t.Errorf("Get(%q) → %q (expected %q)", "b", v, "value")
	}
	v, ok = args.Get("c")
	if !ok {
		t.Errorf("Unexpected Get failure for %q", "c")
	}
	if v != "v1" {
		t.Errorf("Get(%q) → %q (expected %q)", "c", v, "v1")
	}
	v, ok = args.Get("d")
	if ok {
		t.Errorf("Unexpected Get success for %q", "d")
	}
}

func TestArgsAdd(t *testing.T) {
	args := make(Args)
	expected := Args{}
	if !argsEqual(args, expected) {
		t.Fatalf("%q != %q", args, expected)
	}
	args.Add("k1", "v1")
	expected = Args{"k1": []string{"v1"}}
	if !argsEqual(args, expected) {
		t.Fatalf("%q != %q", args, expected)
	}
	args.Add("k2", "v2")
	expected = Args{"k1": []string{"v1"}, "k2": []string{"v2"}}
	if !argsEqual(args, expected) {
		t.Fatalf("%q != %q", args, expected)
	}
	args.Add("k1", "v3")
	expected = Args{"k1": []string{"v1", "v3"}, "k2": []string{"v2"}}
	if !argsEqual(args, expected) {
		t.Fatalf("%q != %q", args, expected)
	}
}

func TestParseClientParameters(t *testing.T) {
	badTests := [...]string{
		"key",
		"key\\",
		"=value",
		"==value",
		"==key=value",
		"key=value\\",
		"a=b;key=value\\",
		"a;b=c",
		";",
		"key=value;",
		";key=value",
		"key\\=value",
	}
	goodTests := [...]struct {
		input    string
		expected Args
	}{
		{
			"",
			Args{},
		},
		{
			"key=",
			Args{"key": []string{""}},
		},
		{
			"key==",
			Args{"key": []string{"="}},
		},
		{
			"key=value",
			Args{"key": []string{"value"}},
		},
		{
			"a=b=c",
			Args{"a": []string{"b=c"}},
		},
		{
			"a=bc==",
			Args{"a": []string{"bc=="}},
		},
		{
			"key=a\nb",
			Args{"key": []string{"a\nb"}},
		},
		{
			"key=value\\;",
			Args{"key": []string{"value;"}},
		},
		{
			"key=\"value\"",
			Args{"key": []string{"\"value\""}},
		},
		{
			"key=\"\"value\"\"",
			Args{"key": []string{"\"\"value\"\""}},
		},
		{
			"\"key=value\"",
			Args{"\"key": []string{"value\""}},
		},
		{
			"key=value;key=value",
			Args{"key": []string{"value", "value"}},
		},
		{
			"key=value1;key=value2",
			Args{"key": []string{"value1", "value2"}},
		},
		{
			"key1=value1;key2=value2;key1=value3",
			Args{"key1": []string{"value1", "value3"}, "key2": []string{"value2"}},
		},
		{
			"\\;=\\;;\\\\=\\;",
			Args{";": []string{";"}, "\\": []string{";"}},
		},
		{
			"a\\=b=c",
			Args{"a=b": []string{"c"}},
		},
		{
			"shared-secret=rahasia;secrets-file=/tmp/blob",
			Args{"shared-secret": []string{"rahasia"}, "secrets-file": []string{"/tmp/blob"}},
		},
		{
			"rocks=20;height=5.6",
			Args{"rocks": []string{"20"}, "height": []string{"5.6"}},
		},
	}

	for _, input := range badTests {
		_, err := parseClientParameters(input)
		if err == nil {
			t.Errorf("%q unexpectedly succeeded", input)
		}
	}

	for _, test := range goodTests {
		args, err := parseClientParameters(test.input)
		if err != nil {
			t.Errorf("%q unexpectedly returned an error: %s", test.input, err)
		}
		if !argsEqual(args, test.expected) {
			t.Errorf("%q → %q (expected %q)", test.input, args, test.expected)
		}
	}
}

func optsEqual(a, b map[string]Args) bool {
	for k, av := range a {
		bv, ok := b[k]
		if !ok || !argsEqual(av, bv) {
			return false
		}
	}
	for k, bv := range b {
		av, ok := a[k]
		if !ok || !argsEqual(av, bv) {
			return false
		}
	}
	return true
}

func TestParseServerTransportOptions(t *testing.T) {
	badTests := [...]string{
		"t\\",
		":=",
		"t:=",
		":k=",
		":=v",
		"t:=v",
		"t:=v",
		"t:k\\",
		"t:k=v;",
		"abc",
		"t:",
		"key=value",
		"=value",
		"t:k=v\\",
		"t1:k=v;t2:k=v\\",
		"t:=key=value",
		"t:==key=value",
		"t:;key=value",
		"t:key\\=value",
	}
	goodTests := [...]struct {
		input    string
		expected map[string]Args
	}{
		{
			"",
			map[string]Args{},
		},
		{
			"t:k=v",
			map[string]Args{
				"t": {"k": []string{"v"}},
			},
		},
		{
			"t:k=v=v",
			map[string]Args{
				"t": {"k": []string{"v=v"}},
			},
		},
		{
			"t:k=vv==",
			map[string]Args{
				"t": {"k": []string{"vv=="}},
			},
		},
		{
			"t1:k=v1;t2:k=v2;t1:k=v3",
			map[string]Args{
				"t1": {"k": []string{"v1", "v3"}},
				"t2": {"k": []string{"v2"}},
			},
		},
		{
			"t\\:1:k=v;t\\=2:k=v;t\\;3:k=v;t\\\\4:k=v",
			map[string]Args{
				"t:1":  {"k": []string{"v"}},
				"t=2":  {"k": []string{"v"}},
				"t;3":  {"k": []string{"v"}},
				"t\\4": {"k": []string{"v"}},
			},
		},
		{
			"t:k\\:1=v;t:k\\=2=v;t:k\\;3=v;t:k\\\\4=v",
			map[string]Args{
				"t": {
					"k:1":  []string{"v"},
					"k=2":  []string{"v"},
					"k;3":  []string{"v"},
					"k\\4": []string{"v"},
				},
			},
		},
		{
			"t:k=v\\:1;t:k=v\\=2;t:k=v\\;3;t:k=v\\\\4",
			map[string]Args{
				"t": {"k": []string{"v:1", "v=2", "v;3", "v\\4"}},
			},
		},
		{
			"trebuchet:secret=nou;trebuchet:cache=/tmp/cache;ballista:secret=yes",
			map[string]Args{
				"trebuchet": {"secret": []string{"nou"}, "cache": []string{"/tmp/cache"}},
				"ballista":  {"secret": []string{"yes"}},
			},
		},
	}

	for _, input := range badTests {
		_, err := parseServerTransportOptions(input)
		if err == nil {
			t.Errorf("%q unexpectedly succeeded", input)
		}
	}

	for _, test := range goodTests {
		opts, err := parseServerTransportOptions(test.input)
		if err != nil {
			t.Errorf("%q unexpectedly returned an error: %s", test.input, err)
		}
		if !optsEqual(opts, test.expected) {
			t.Errorf("%q → %q (expected %q)", test.input, opts, test.expected)
		}
	}
}

func TestEncodeSmethodArgs(t *testing.T) {
	tests := [...]struct {
		args     Args
		expected string
	}{
		{
			nil,
			"",
		},
		{
			Args{},
			"",
		},
		{
			Args{"j": []string{"v1", "v2", "v3"}, "k": []string{"v1", "v2", "v3"}},
			"j=v1,j=v2,j=v3,k=v1,k=v2,k=v3",
		},
		{
			Args{"=,\\": []string{"=", ",", "\\"}},
			"\\=\\,\\\\=\\=,\\=\\,\\\\=\\,,\\=\\,\\\\=\\\\",
		},
		{
			Args{"secret": []string{"yes"}},
			"secret=yes",
		},
		{
			Args{"secret": []string{"nou"}, "cache": []string{"/tmp/cache"}},
			"cache=/tmp/cache,secret=nou",
		},
	}

	for _, test := range tests {
		encoded := encodeSmethodArgs(test.args)
		if encoded != test.expected {
			t.Errorf("%q → %q (expected %q)", test.args, encoded, test.expected)
		}
	}
}
