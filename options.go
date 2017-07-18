package gost

import (
	"log"
	"net/url"
	"reflect"
)

// Options holds options of node
type Options interface {
	BaseOptions() *BaseOptions
}

type Option func(Options)

type BaseOptions struct {
	Addr      string         `opt:"addr"`      // [host]:port
	Protocol  string         `opt:"protocol"`  // protocol: http/socks5/ss
	Transport string         `opt:"transport"` // transport: ws/wss/tls/http2/tcp/udp/rtcp/rudp
	Users     []url.Userinfo `opt:"users"`     // authentication for proxy
}

func AddrOption(a string) Option {
	return func(opts Options) {
		opts.BaseOptions().Addr = a
	}
}

func ProtocolOption(p string) Option {
	return func(opts Options) {
		opts.BaseOptions().Protocol = p
	}
}

func TransportOption(t string) Option {
	return func(opts Options) {
		opts.BaseOptions().Transport = t
	}
}

func UsersOption(users ...url.Userinfo) Option {
	return func(opts Options) {
		opts.BaseOptions().Users = users
	}
}

func GetOption(i interface{}, opt string) interface{} {
	ps := reflect.ValueOf(i)
	if ps.Kind() != reflect.Ptr && ps.Kind() != reflect.Interface {
		return nil
	}
	s := ps.Elem()
	for n := 0; n < s.NumField(); n++ {
		log.Println("tag:", s.Type().Field(n).Tag.Get("opt"))
		if opt == s.Type().Field(n).Tag.Get("opt") && s.Field(n).CanInterface() {
			//	return s.Field(n).Interface()
		}
	}
	return nil
}

func SetOption(i interface{}, opt string, v interface{}) {
	ps := reflect.ValueOf(i)
	if ps.Kind() != reflect.Ptr || ps.Kind() != reflect.Interface {
		return
	}
	s := ps.Elem()

	for n := 0; n < s.NumField(); n++ {
		if opt == s.Type().Field(n).Tag.Get("opt") &&
			s.Field(n).IsValid() && s.Field(n).CanSet() {
			s.Field(n).Set(reflect.ValueOf(v))
			return
		}
	}
}
