package stun

import (
	"errors"
	"net"
)

const (
	EndpointIndependent  = "endpoint-independent"
	AddressDependent     = "address-dependent"
	AddressPortDependent = "address-port-dependent"
)

type Detector struct {
	*Conn
}

func NewDetector(c *Conn) *Detector {
	d := &Detector{c}
	d.agent.Handler = &Server{agent: c.agent}
	return d
}

func (d *Detector) Hairpinning() error {
	mapped, err := d.Discover()
	if err != nil {
		return err
	}
	conn, err := net.Dial(d.Network(), mapped.String())
	if err != nil {
		return err
	}
	// not using stop channel
	c := NewConn(conn, d.agent.config, make(chan struct{}))
	defer c.Close()
	_, err = c.Discover()
	return err
}

func (d *Detector) DiscoverChange(change uint64) error {
	req := &Message{Type: MethodBinding, Attributes: []Attr{Int(AttrChangeRequest, change)}}
	_, from, err := d.RequestTransport(req, d)
	if err != nil {
		return err
	}
	ip, port := SockAddr(d.RemoteAddr())
	chip, chport := SockAddr(from.RemoteAddr())
	if change&ChangeIP != 0 {
		if ip.Equal(chip) {
			return errors.New("stun: bad response, ip address is not changed")
		}
	} else if change&ChangePort != 0 {
		if port == chport {
			return errors.New("stun: bad response, port is not changed")
		}
	}
	return nil
}

func (d *Detector) Filtering() (string, error) {
	n := d.Network()
	if n != "udp" {
		return "", errors.New("stun: filtering test is not applicable to " + n)
	}
	_, err := d.Request(&Message{Type: MethodBinding})
	if err != nil {
		return "", err
	}
	err = d.DiscoverChange(ChangeIP | ChangePort)
	switch err {
	case nil:
		return EndpointIndependent, nil
	case errTimeout:
		err = d.DiscoverChange(ChangePort)
		switch err {
		case nil:
			return AddressDependent, nil
		case errTimeout:
			return AddressPortDependent, nil
		}
	}
	return "", err
}

func (d *Detector) DiscoverOther(addr net.Addr) (net.Addr, error) {
	n := addr.Network()
	conn, err := net.Dial(n, addr.String())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	// not using stop channel
	go d.agent.ServeConn(conn, make(chan struct{}))
	res, _, err := d.RequestTransport(&Message{Type: MethodBinding}, conn)
	if err != nil {
		return nil, err
	}
	mapped := res.GetAddr(n, AttrXorMappedAddress, AttrMappedAddress)
	if mapped != nil {
		return mapped, nil
	}
	return nil, errors.New("stun: bad response, no mapped address")
}

func (d *Detector) Mapping() (string, error) {
	n := d.Network()
	msg, err := d.Request(&Message{Type: MethodBinding})
	if err != nil {
		return "", err
	}
	mapped, other := msg.GetAddr(n, AttrXorMappedAddress), msg.GetAddr(n, AttrOtherAddress)
	if mapped == nil {
		return "", errors.New("stun: bad response, no mapped address")
	}
	if other == nil {
		return "", errors.New("stun: bad response, no other address")
	}
	ip, _ := SockAddr(mapped)
	if ip.IsLoopback() {
		return EndpointIndependent, nil
	}
	for _, it := range local {
		if it.IP.Equal(ip) {
			return EndpointIndependent, nil
		}
	}
	ip, _ = SockAddr(other)
	_, port := SockAddr(d.RemoteAddr())
	a, err := d.DiscoverOther(NewAddr(n, ip, port))
	if err != nil {
		return "", err
	}
	if sameAddr(a, mapped) {
		return EndpointIndependent, nil
	}
	b, err := d.DiscoverOther(other)
	if err != nil {
		return "", err
	}
	if sameAddr(b, a) {
		return AddressDependent, nil
	}
	return AddressPortDependent, nil
}

func LocalAddrs() []*net.IPAddr {
	return local
}

var local []*net.IPAddr

func init() {
	ifaces, err := net.Interfaces()
	if err != nil {
		return
	}
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		for _, it := range addrs {
			var ip net.IP
			switch it := it.(type) {
			case *net.IPNet:
				ip = it.IP
			case *net.IPAddr:
				ip = it.IP
			}
			if ip != nil && ip.IsGlobalUnicast() {
				local = append(local, &net.IPAddr{ip, iface.Name})
			}
		}
	}
}
