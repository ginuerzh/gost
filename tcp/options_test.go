package tcp

import "testing"
import "net/url"
import "reflect"

var tests = []struct {
	Opt   string
	Value interface{}
}{
	{"addr", "localhost:8080"},
	{"protocol", "http"},
	{"transport", "tcp"},
	{"users", []url.Userinfo{*url.UserPassword("admin", "123456")}},
}

func TestOptions(t *testing.T) {
	opts := new(tcpNodeOptions)
	for _, test := range tests {
		opts.Set(test.Opt, test.Value)
		v := opts.Get(test.Opt)
		if !reflect.DeepEqual(v, test.Value) {
			t.Log("not equal:", test.Opt, v)
			t.Fail()
		}
	}
	t.Log("addr:", opts.Addr)
	t.Log("protocol:", opts.Protocol)
	t.Log("transport:", opts.Transport)
	t.Log("users:", opts.Users)
}
