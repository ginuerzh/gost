package main

import (
	"crypto/tls"
	"fmt"
	"github.com/golang/glog"
	"io"
	"net"
	"net/url"
	"strings"
)

type strSlice []string

func (ss *strSlice) String() string {
	return fmt.Sprintf("%s", *ss)
}
func (ss *strSlice) Set(value string) error {
	*ss = append(*ss, value)
	return nil
}

// socks://admin:123456@localhost:8080/tls
type Args struct {
	Addr      string // host:port
	Protocol  string // protocol: http&socks5/http/socks/socks5/ss, default is http&socks5
	Transport string // transport: tcp/ws/tls, default is tcp(raw tcp)
	User      *url.Userinfo
	EncMeth   string          // data encryption method
	EncPass   string          // data encryption password
	Cert      tls.Certificate // tls certificate
}

func (args Args) String() string {
	var authUser, authPass string
	if args.User != nil {
		authUser = args.User.Username()
		authPass, _ = args.User.Password()
	}
	return fmt.Sprintf("host: %s, proto: %s, trans: %s, auth: %s:%s, enc: %s:%s",
		args.Addr, args.Protocol, args.Transport, authUser, authPass,
		args.EncMeth, args.EncPass)
}

func parseArgs(ss []string) (args []Args) {
	for _, s := range ss {
		if !strings.Contains(s, "://") {
			s = "tcp://" + s
		}
		u, err := url.Parse(s)
		if err != nil {
			if glog.V(LWARNING) {
				glog.Warningln(err)
			}
			continue
		}

		arg := Args{
			Addr: u.Host,
			User: u.User,
		}

		schemes := strings.Split(u.Scheme, "+")
		if len(schemes) == 1 {
			arg.Protocol = schemes[0]
			arg.Transport = schemes[0]
		}
		if len(schemes) == 2 {
			arg.Protocol = schemes[0]
			arg.Transport = schemes[1]
		}

		switch arg.Protocol {
		case "http", "socks", "socks5", "ss":
		default:
			arg.Protocol = "default"
		}
		switch arg.Transport {
		case "ws", "tls", "tcp":
		default:
			arg.Transport = "tcp"
		}

		mp := strings.Split(strings.Trim(u.Path, "/"), ":")
		if len(mp) == 1 {
			arg.EncMeth = mp[0]
		}
		if len(mp) == 2 {
			arg.EncMeth = mp[0]
			arg.EncPass = mp[1]
		}

		if arg.Cert, err = tls.LoadX509KeyPair("cert.pem", "key.pem"); err != nil {
			if glog.V(LFATAL) {
				glog.Fatalln(err)
			}
		}
		args = append(args, arg)
	}

	return
}

// based on io.Copy
func Copy(dst io.Writer, src io.Reader) (written int64, err error) {
	buf := make([]byte, 32*1024)

	for {
		nr, er := src.Read(buf)
		//log.Println("cp r", nr, er)
		if nr > 0 {
			nw, ew := dst.Write(buf[:nr])
			//log.Println("cp w", nw, ew)
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
			/*
				if nr != nw {
					err = io.ErrShortWrite
					break
				}
			*/
		}
		if er == io.EOF {
			break
		}
		if er != nil {
			err = er
			break
		}
	}
	return
}

func Pipe(src io.Reader, dst io.Writer, c chan<- error) {
	_, err := Copy(dst, src)
	c <- err
}

func Transport(conn, conn2 net.Conn) (err error) {
	rChan := make(chan error, 1)
	wChan := make(chan error, 1)

	go Pipe(conn, conn2, wChan)
	go Pipe(conn2, conn, rChan)

	select {
	case err = <-wChan:
		//log.Println("w exit", err)
	case err = <-rChan:
		//log.Println("r exit", err)
	}

	return
}
