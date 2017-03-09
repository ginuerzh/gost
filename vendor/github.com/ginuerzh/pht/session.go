package pht

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
)

const (
	defaultRChanLen = 64
	defaultWChanLen = 64
)

type session struct {
	rchan  chan []byte
	wchan  chan []byte
	closed chan interface{}
}

func newSession(rlen, wlen int) *session {
	if rlen <= 0 {
		rlen = defaultRChanLen
	}
	if wlen <= 0 {
		wlen = defaultWChanLen
	}

	return &session{
		rchan:  make(chan []byte, rlen),
		wchan:  make(chan []byte, wlen),
		closed: make(chan interface{}),
	}
}

type sessionManager struct {
	sessions map[string]*session
	mux      sync.Mutex
}

func newSessionManager() *sessionManager {
	return &sessionManager{
		sessions: make(map[string]*session),
		mux:      sync.Mutex{},
	}
}

func (m *sessionManager) NewSession(rlen, wlen int) (token string, s *session, err error) {
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return
	}
	token = hex.EncodeToString(nonce[:])
	s = newSession(rlen, wlen)

	m.mux.Lock()
	defer m.mux.Unlock()
	m.sessions[token] = s

	return
}

func (m *sessionManager) SetSession(token string, session *session) {
	m.mux.Lock()
	defer m.mux.Unlock()
	m.sessions[token] = session
}

func (m *sessionManager) GetSession(token string) *session {
	m.mux.Lock()
	defer m.mux.Unlock()

	return m.sessions[token]
}

func (m *sessionManager) DelSession(token string) {
	m.mux.Lock()
	defer m.mux.Unlock()

	delete(m.sessions, token)
}
