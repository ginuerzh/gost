package main

import (
	//"bufio"
	//"bytes"
	//"crypto/tls"
	//"errors"
	"io"
	//"io/ioutil"
	"log"
	"net"
	//"net/http"
	//"strconv"
	//"strings"
	//"sync/atomic"
	"time"
)

const (
	readWait  = 300 * time.Second
	writeWait = 300 * time.Second
)

type Gost struct {
	Laddr, Saddr, Proxy string
}

func (g *Gost) Run() error {
	addr, err := net.ResolveTCPAddr("tcp", g.Laddr)
	if err != nil {
		return err
	}

	ln, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return err
	}

	for {
		conn, err := ln.AcceptTCP()
		if err != nil {
			log.Println("accept:", err)
			continue
		}
		go g.serve(conn)
	}

	return ln.Close()
}

func (g *Gost) serve(conn net.Conn) error {
	var pconn net.Conn
	defer conn.Close()

	paddr, err := net.ResolveTCPAddr("tcp", g.Proxy)
	if err != nil {
		log.Println(err)
	}
	if paddr != nil {
		pconn, err = net.DialTCP("tcp", nil, paddr)
		if err != nil {
			return err
		}
		return g.foward(conn, pconn)
	}

	saddr, err := net.ResolveTCPAddr("tcp", g.Saddr)
	if err != nil {
		log.Println(err)
	}
	if saddr != nil {
		sconn, err := net.DialTCP("tcp", nil, saddr)
		if err != nil {
			return err
		}
		defer sconn.Close()

		return g.transport(conn, sconn)
	}

	return nil
}

func (g *Gost) foward(conn, pconn net.Conn) error {
	defer pconn.Close()

	saddr, err := net.ResolveTCPAddr("tcp", g.Saddr)
	if err != nil {
		log.Println(err)
	}

	if saddr != nil {

	}

	return nil
}

func (g *Gost) pipe(src io.Reader, dst io.Writer, c chan<- error) {
	_, err := io.Copy(dst, src)
	c <- err
}

func (g *Gost) transport(conn net.Conn, conn2 net.Conn) (err error) {
	rChan := make(chan error, 1)
	wChan := make(chan error, 1)

	go g.pipe(conn, conn2, wChan)
	go g.pipe(conn2, conn, rChan)

	select {
	case err = <-wChan:
	case err = <-rChan:
	}

	return
}
