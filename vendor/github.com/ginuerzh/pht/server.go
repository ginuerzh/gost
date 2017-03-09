package pht

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

const (
	tokenURI = "/token"
	pushURI  = "/push"
	pollURI  = "/poll"
)

type Server struct {
	Addr    string
	Key     string
	Handler func(net.Conn)
	manager *sessionManager
}

func (s *Server) ListenAndServe() error {
	s.manager = newSessionManager()

	mux := http.NewServeMux()
	mux.Handle(tokenURI, http.HandlerFunc(s.tokenHandler))
	mux.Handle(pushURI, http.HandlerFunc(s.pushHandler))
	mux.Handle(pollURI, http.HandlerFunc(s.pollHandler))

	return http.ListenAndServe(s.Addr, mux)
}

func (s *Server) tokenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	m := parseAuth(r.Header.Get("Authorization"))
	if m["key"] != s.Key {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	token, session, err := s.manager.NewSession(0, 0)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	conn, err := s.upgrade(session, r)
	if err != nil {
		s.manager.DelSession(token)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if s.Handler != nil {
		go s.Handler(conn)
	}

	w.Write([]byte(fmt.Sprintf("token=%s", token)))
}

func (s *Server) pushHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	m := parseAuth(r.Header.Get("Authorization"))
	if m["key"] != s.Key {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	token := m["token"]
	session := s.manager.GetSession(token)
	if session == nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	br := bufio.NewReader(r.Body)
	data, err := br.ReadString('\n')
	if err != nil {
		s.manager.DelSession(token)
		close(session.rchan)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	data = strings.TrimSuffix(data, "\n")
	if len(data) == 0 {
		s.manager.DelSession(token)
		close(session.rchan)
		return
	}

	b, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		s.manager.DelSession(token)
		close(session.rchan)
		return
	}

	select {
	case <-session.closed:
		s.manager.DelSession(token)
		return
	case session.rchan <- b:
		w.WriteHeader(http.StatusOK)
	case <-time.After(time.Second * 90):
		s.manager.DelSession(token)
		w.WriteHeader(http.StatusRequestTimeout)
	}
}

func (s *Server) pollHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	m := parseAuth(r.Header.Get("Authorization"))
	if m["key"] != s.Key {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	token := m["token"]
	session := s.manager.GetSession(token)
	if session == nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	w.WriteHeader(http.StatusOK)
	if fw, ok := w.(http.Flusher); ok {
		fw.Flush()
	}

	for {
		select {
		case data, ok := <-session.wchan:
			if !ok {
				s.manager.DelSession(token)
				return // session is closed
			}
			bw := bufio.NewWriter(w)
			bw.WriteString(base64.StdEncoding.EncodeToString(data))
			bw.WriteString("\n")
			if err := bw.Flush(); err != nil {
				return
			}

			if fw, ok := w.(http.Flusher); ok {
				fw.Flush()
			}
		case <-time.After(time.Second * 25):
			return
		}
	}
}

func (s *Server) upgrade(sess *session, r *http.Request) (net.Conn, error) {
	conn := newConn(sess)
	raddr, err := net.ResolveTCPAddr("tcp", r.RemoteAddr)
	if err != nil {
		raddr = &net.TCPAddr{}
	}
	conn.remoteAddr = raddr

	laddr, err := net.ResolveTCPAddr("tcp", s.Addr)
	if err != nil {
		laddr = &net.TCPAddr{}
	}
	conn.localAddr = laddr

	return conn, nil
}

func parseAuth(auth string) map[string]string {
	mkv := make(map[string]string)

	for _, s := range strings.Split(auth, ";") {
		n := strings.Index(s, "=")
		if n < 0 {
			continue
		}
		mkv[strings.TrimSpace(s[:n])] = strings.TrimSpace(s[n+1:])
	}

	return mkv
}
