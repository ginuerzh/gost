package stun

import (
	"errors"
	"math/rand"
	"net"
	"sync"
	"time"
)

var DefaultConfig = &Config{
	RetransmissionTimeout: 500 * time.Millisecond,
	TransactionTimeout:    39500 * time.Millisecond,
	Software:              "pixelbender/go-stun",
}

type Handler interface {
	ServeSTUN(msg *Message, tr Transport)
}

type HandlerFunc func(msg *Message, tr Transport)

func (h HandlerFunc) ServeSTUN(msg *Message, tr Transport) {
	h(msg, tr)
}

type Config struct {
	// AuthMethod returns a key for MESSAGE-INTEGRITY attribute
	AuthMethod AuthMethod
	// Retransmission timeout, default is 500 milliseconds
	RetransmissionTimeout time.Duration
	// Transaction timeout, default is 39.5 seconds
	TransactionTimeout time.Duration
	// Fingerprint, if true all outgoing messages contain FINGERPRINT attribute
	Fingerprint bool
	// Software is a SOFTWARE attribute value for outgoing messages, if not empty
	Software string
	// Logf, if set all sent and received messages printed using Logf
	Logf func(format string, args ...interface{})
}

func (c *Config) attrs() []Attr {
	if c == nil {
		return nil
	}
	var a []Attr
	if c.Software != "" {
		a = append(a, String(AttrSoftware, c.Software))
	}
	if c.Fingerprint {
		a = append(a, Fingerprint)
	}
	return a
}

func (c *Config) Clone() *Config {
	r := *c
	return &r
}

type Agent struct {
	config  *Config
	Handler Handler
	m       mux
}

func NewAgent(config *Config) *Agent {
	if config == nil {
		config = DefaultConfig
	}
	return &Agent{
		config: config,
	}
}

func (a *Agent) Send(msg *Message, tr Transport) (err error) {
	msg = &Message{
		msg.Type,
		msg.Transaction,
		append(a.config.attrs(), msg.Attributes...),
	}
	if log := a.config.Logf; log != nil {
		log("%v → %v %v", tr.LocalAddr(), tr.RemoteAddr(), msg)
	}
	b := msg.Marshal(getBuffer()[:0])
	_, err = tr.Write(b)
	putBuffer(b)
	return
}

func (a *Agent) ServeConn(c net.Conn, stop chan struct{}) error {
	if c, ok := c.(net.PacketConn); ok {
		return a.ServePacket(c, stop)
	}
	var (
		b = getBuffer()
		p int
	)
	defer putBuffer(b)
	for {
		select {
		case <-stop:
			return nil
		default:
		}
		if p >= len(b) {
			return errBufferOverflow
		}
		n, err := c.Read(b[p:])
		if err != nil {
			return err
		}
		p += n
		n = 0
		for n < p {
			r, err := a.ServeTransport(b[n:p], c)
			if err != nil {
				return err
			}
			n += r
		}
		if n > 0 {
			if n < p {
				p = copy(b, b[n:p])
			} else {
				p = 0
			}
		}
	}
}

func (a *Agent) ServePacket(c net.PacketConn, stop chan struct{}) error {
	b := getBuffer()
	defer putBuffer(b)
	// don't close the connection since we're going to reuse it
	// defer c.Close()

	for {
		select {
		case <-stop:
			return nil
		default:
		}
		n, addr, err := c.ReadFrom(b)
		if err != nil {
			return err
		}
		if n > 0 {
			a.ServeTransport(b[:n], &packetConn{c, addr})
		}
	}
}

func (a *Agent) ServeTransport(b []byte, tr Transport) (n int, err error) {
	msg := &Message{}
	n, err = msg.Unmarshal(b)
	if err != nil {
		return
	}
	a.ServeSTUN(msg, tr)
	return
}

func (a *Agent) ServeSTUN(msg *Message, tr Transport) {
	if log := a.config.Logf; log != nil {
		log("%v ← %v %v", tr.LocalAddr(), tr.RemoteAddr(), msg)
	}
	if a.m.serve(msg, tr) {
		return
	}
	if h := a.Handler; h != nil {
		go h.ServeSTUN(msg, tr)
	}
}

func (a *Agent) RoundTrip(req *Message, to Transport) (res *Message, from Transport, err error) {
	var (
		start = time.Now()
		rto   = a.config.RetransmissionTimeout
		udp   = to.LocalAddr().Network() == "udp"
		tx    = a.m.newTx()
	)
	defer a.m.closeTx(tx)
	req = &Message{req.Type, tx.id, req.Attributes}
	if err = a.Send(req, to); err != nil {
		return
	}
	for {
		d := a.config.TransactionTimeout - time.Since(start)
		if d < 0 {
			err = errTimeout
			return
		}
		if udp && d > rto {
			d = rto
		}
		res, from, err = tx.Receive(d)
		if udp && err == errTimeout && d == rto {
			rto <<= 1
			a.Send(req, to)
			continue
		}
		return
	}
}

type mux struct {
	sync.RWMutex
	t map[string]*transaction
}

func (m *mux) serve(msg *Message, tr Transport) bool {
	m.RLock()
	tx, ok := m.t[string(msg.Transaction)]
	m.RUnlock()
	if ok {
		tx.msg, tx.from = msg, tr
		tx.Done()
		return true
	}
	return false
}

func (m *mux) newTx() *transaction {
	tx := &transaction{id: NewTransaction()}
	m.Lock()
	if m.t == nil {
		m.t = make(map[string]*transaction)
	} else {
		for m.t[string(tx.id)] != nil {
			rand.Read(tx.id[4:])
		}
	}
	m.t[string(tx.id)] = tx
	m.Unlock()
	return tx
}

func (m *mux) closeTx(tx *transaction) {
	m.Lock()
	delete(m.t, string(tx.id))
	m.Unlock()
}

func (m *mux) Close() {
	m.Lock()
	defer m.Unlock()
	for _, it := range m.t {
		it.Close()
	}
	m.t = nil
}

type transaction struct {
	sync.WaitGroup
	id   []byte
	from Transport
	msg  *Message
	err  error
}

func (tx *transaction) Receive(d time.Duration) (msg *Message, from Transport, err error) {
	tx.Add(1)
	t := time.AfterFunc(d, tx.timeout)
	tx.Wait()
	t.Stop()
	if err = tx.err; err != nil {
		return
	}
	return tx.msg, tx.from, nil
}

func (tx *transaction) timeout() {
	tx.err = errTimeout
	tx.Done()
}

func (tx *transaction) Close() {
	tx.err = errCanceled
	tx.Done()
}

var errCanceled = errors.New("stun: transaction canceled")
var errTimeout = errors.New("stun: transaction timeout")
