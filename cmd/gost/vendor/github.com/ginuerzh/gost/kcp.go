// KCP feature is based on https://github.com/xtaci/kcptun

package gost

import (
	"crypto/sha1"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"github.com/golang/glog"
	"github.com/klauspost/compress/snappy"
	"golang.org/x/crypto/pbkdf2"
	"gopkg.in/xtaci/kcp-go.v2"
	"gopkg.in/xtaci/smux.v1"
	"net"
	"os"
	"time"
)

const (
	DefaultKCPConfigFile = "kcp.json"
)

var (
	SALT = "kcp-go"
)

type KCPConfig struct {
	Key          string `json:"key"`
	Crypt        string `json:"crypt"`
	Mode         string `json:"mode"`
	MTU          int    `json:"mtu"`
	SndWnd       int    `json:"sndwnd"`
	RcvWnd       int    `json:"rcvwnd"`
	DataShard    int    `json:"datashard"`
	ParityShard  int    `json:"parityshard"`
	DSCP         int    `json:"dscp"`
	NoComp       bool   `json:"nocomp"`
	AckNodelay   bool   `json:"acknodelay"`
	NoDelay      int    `json:"nodelay"`
	Interval     int    `json:"interval"`
	Resend       int    `json:"resend"`
	NoCongestion int    `json:"nc"`
	SockBuf      int    `json:"sockbuf"`
	KeepAlive    int    `json:"keepalive"`
	SnmpLog      string `json:"snmplog"`
	SnmpPeriod   int    `json:"snmpperiod"`
}

func ParseKCPConfig(configFile string) (*KCPConfig, error) {
	if configFile == "" {
		configFile = DefaultKCPConfigFile
	}
	file, err := os.Open(configFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	config := &KCPConfig{}
	if err = json.NewDecoder(file).Decode(config); err != nil {
		return nil, err
	}
	return config, nil
}

func (c *KCPConfig) Init() {
	switch c.Mode {
	case "normal":
		c.NoDelay, c.Interval, c.Resend, c.NoCongestion = 0, 50, 2, 1
	case "fast2":
		c.NoDelay, c.Interval, c.Resend, c.NoCongestion = 1, 30, 2, 1
	case "fast3":
		c.NoDelay, c.Interval, c.Resend, c.NoCongestion = 1, 20, 2, 1
	case "fast":
		fallthrough
	default:
		c.NoDelay, c.Interval, c.Resend, c.NoCongestion = 0, 40, 2, 1
	}
}

var (
	DefaultKCPConfig = &KCPConfig{
		Key:          "it's a secrect",
		Crypt:        "aes",
		Mode:         "fast",
		MTU:          1350,
		SndWnd:       1024,
		RcvWnd:       1024,
		DataShard:    10,
		ParityShard:  3,
		DSCP:         0,
		NoComp:       false,
		AckNodelay:   false,
		NoDelay:      0,
		Interval:     50,
		Resend:       0,
		NoCongestion: 0,
		SockBuf:      4194304,
		KeepAlive:    10,
		SnmpLog:      "",
		SnmpPeriod:   60,
	}
)

type KCPServer struct {
	Base   *ProxyServer
	Config *KCPConfig
}

func NewKCPServer(base *ProxyServer, config *KCPConfig) *KCPServer {
	return &KCPServer{Base: base, Config: config}
}

func (s *KCPServer) ListenAndServe() (err error) {
	if s.Config == nil {
		s.Config = DefaultKCPConfig
	}
	s.Config.Init()

	ln, err := kcp.ListenWithOptions(s.Base.Node.Addr,
		blockCrypt(s.Config.Key, s.Config.Crypt, SALT), s.Config.DataShard, s.Config.ParityShard)
	if err != nil {
		return err
	}
	if err = ln.SetDSCP(s.Config.DSCP); err != nil {
		glog.V(LWARNING).Infoln("[kcp]", err)
	}
	if err = ln.SetReadBuffer(s.Config.SockBuf); err != nil {
		glog.V(LWARNING).Infoln("[kcp]", err)
	}
	if err = ln.SetWriteBuffer(s.Config.SockBuf); err != nil {
		glog.V(LWARNING).Infoln("[kcp]", err)
	}

	go snmpLogger(s.Config.SnmpLog, s.Config.SnmpPeriod)
	go kcpSigHandler()
	for {
		conn, err := ln.AcceptKCP()
		if err != nil {
			glog.V(LWARNING).Infoln("[kcp]", err)
			continue
		}

		conn.SetStreamMode(true)
		conn.SetNoDelay(s.Config.NoDelay, s.Config.Interval, s.Config.Resend, s.Config.NoCongestion)
		conn.SetMtu(s.Config.MTU)
		conn.SetWindowSize(s.Config.SndWnd, s.Config.RcvWnd)
		conn.SetACKNoDelay(s.Config.AckNodelay)
		conn.SetKeepAlive(s.Config.KeepAlive)

		go s.handleMux(conn)
	}
}

func (s *KCPServer) handleMux(conn net.Conn) {
	smuxConfig := smux.DefaultConfig()
	smuxConfig.MaxReceiveBuffer = s.Config.SockBuf

	glog.V(LINFO).Infof("[kcp] %s - %s", conn.RemoteAddr(), s.Base.Node.Addr)

	if !s.Config.NoComp {
		conn = newCompStreamConn(conn)
	}

	mux, err := smux.Server(conn, smuxConfig)
	if err != nil {
		glog.V(LWARNING).Infoln("[kcp]", err)
		return
	}
	defer mux.Close()

	glog.V(LINFO).Infof("[kcp] %s <-> %s", conn.RemoteAddr(), s.Base.Node.Addr)
	defer glog.V(LINFO).Infof("[kcp] %s >-< %s", conn.RemoteAddr(), s.Base.Node.Addr)

	for {
		stream, err := mux.AcceptStream()
		if err != nil {
			glog.V(LWARNING).Infoln("[kcp]", err)
			return
		}
		go s.Base.handleConn(NewKCPConn(conn, stream))
	}
}

func blockCrypt(key, crypt, salt string) (block kcp.BlockCrypt) {
	pass := pbkdf2.Key([]byte(key), []byte(salt), 4096, 32, sha1.New)

	switch crypt {
	case "tea":
		block, _ = kcp.NewTEABlockCrypt(pass[:16])
	case "xor":
		block, _ = kcp.NewSimpleXORBlockCrypt(pass)
	case "none":
		block, _ = kcp.NewNoneBlockCrypt(pass)
	case "aes-128":
		block, _ = kcp.NewAESBlockCrypt(pass[:16])
	case "aes-192":
		block, _ = kcp.NewAESBlockCrypt(pass[:24])
	case "blowfish":
		block, _ = kcp.NewBlowfishBlockCrypt(pass)
	case "twofish":
		block, _ = kcp.NewTwofishBlockCrypt(pass)
	case "cast5":
		block, _ = kcp.NewCast5BlockCrypt(pass[:16])
	case "3des":
		block, _ = kcp.NewTripleDESBlockCrypt(pass[:24])
	case "xtea":
		block, _ = kcp.NewXTEABlockCrypt(pass[:16])
	case "salsa20":
		block, _ = kcp.NewSalsa20BlockCrypt(pass)
	case "aes":
		fallthrough
	default: // aes
		block, _ = kcp.NewAESBlockCrypt(pass)
	}
	return
}

func snmpLogger(path string, interval int) {
	if path == "" || interval == 0 {
		return
	}
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			f, err := os.OpenFile(time.Now().Format(path), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
			if err != nil {
				glog.V(LWARNING).Infoln("[kcp]", err)
				return
			}
			w := csv.NewWriter(f)
			// write header in empty file
			if stat, err := f.Stat(); err == nil && stat.Size() == 0 {
				if err := w.Write(append([]string{"Unix"}, kcp.DefaultSnmp.Header()...)); err != nil {
					glog.V(LWARNING).Infoln("[kcp]", err)
				}
			}
			if err := w.Write(append([]string{fmt.Sprint(time.Now().Unix())}, kcp.DefaultSnmp.ToSlice()...)); err != nil {
				glog.V(LWARNING).Infoln("[kcp]", err)
			}
			kcp.DefaultSnmp.Reset()
			w.Flush()
			f.Close()
		}
	}
}

type KCPSession struct {
	conn    net.Conn
	session *smux.Session
}

func DialKCP(addr string, config *KCPConfig) (*KCPSession, error) {
	if config == nil {
		config = DefaultKCPConfig
	}
	config.Init()

	kcpconn, err := kcp.DialWithOptions(addr,
		blockCrypt(config.Key, config.Crypt, SALT), config.DataShard, config.ParityShard)
	if err != nil {
		return nil, err
	}

	kcpconn.SetStreamMode(true)
	kcpconn.SetNoDelay(config.NoDelay, config.Interval, config.Resend, config.NoCongestion)
	kcpconn.SetWindowSize(config.SndWnd, config.RcvWnd)
	kcpconn.SetMtu(config.MTU)
	kcpconn.SetACKNoDelay(config.AckNodelay)
	kcpconn.SetKeepAlive(config.KeepAlive)

	if err := kcpconn.SetDSCP(config.DSCP); err != nil {
		glog.V(LWARNING).Infoln("[kcp]", err)
	}
	if err := kcpconn.SetReadBuffer(config.SockBuf); err != nil {
		glog.V(LWARNING).Infoln("[kcp]", err)
	}
	if err := kcpconn.SetWriteBuffer(config.SockBuf); err != nil {
		glog.V(LWARNING).Infoln("[kcp]", err)
	}

	// stream multiplex
	smuxConfig := smux.DefaultConfig()
	smuxConfig.MaxReceiveBuffer = config.SockBuf
	var conn net.Conn = kcpconn
	if !config.NoComp {
		conn = newCompStreamConn(kcpconn)
	}
	session, err := smux.Client(conn, smuxConfig)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return &KCPSession{conn: conn, session: session}, nil
}

func (session *KCPSession) GetConn() (*KCPConn, error) {
	stream, err := session.session.OpenStream()
	if err != nil {
		session.Close()
		return nil, err
	}
	return NewKCPConn(session.conn, stream), nil
}

func (session *KCPSession) Close() error {
	return session.session.Close()
}

func (session *KCPSession) IsClosed() bool {
	return session.session.IsClosed()
}

func (session *KCPSession) NumStreams() int {
	return session.session.NumStreams()
}

type KCPConn struct {
	conn   net.Conn
	stream *smux.Stream
}

func NewKCPConn(conn net.Conn, stream *smux.Stream) *KCPConn {
	return &KCPConn{conn: conn, stream: stream}
}

func (c *KCPConn) Read(b []byte) (n int, err error) {
	return c.stream.Read(b)
}

func (c *KCPConn) Write(b []byte) (n int, err error) {
	return c.stream.Write(b)
}

func (c *KCPConn) Close() error {
	return c.stream.Close()
}

func (c *KCPConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *KCPConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *KCPConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *KCPConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *KCPConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

type compStreamConn struct {
	conn net.Conn
	w    *snappy.Writer
	r    *snappy.Reader
}

func newCompStreamConn(conn net.Conn) *compStreamConn {
	c := new(compStreamConn)
	c.conn = conn
	c.w = snappy.NewBufferedWriter(conn)
	c.r = snappy.NewReader(conn)
	return c
}

func (c *compStreamConn) Read(b []byte) (n int, err error) {
	return c.r.Read(b)
}

func (c *compStreamConn) Write(b []byte) (n int, err error) {
	n, err = c.w.Write(b)
	err = c.w.Flush()
	return n, err
}

func (c *compStreamConn) Close() error {
	return c.conn.Close()
}

func (c *compStreamConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *compStreamConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *compStreamConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *compStreamConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *compStreamConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}
