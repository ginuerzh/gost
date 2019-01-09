package gost

import (
	"bufio"
	"io"
	"strings"
	"sync"
	"time"
)

// Authenticator is an interface for user authentication.
type Authenticator interface {
	Authenticate(user, password string) bool
}

// LocalAuthenticator is an Authenticator that authenticates client by local key-value pairs.
type LocalAuthenticator struct {
	kvs     map[string]string
	period  time.Duration
	stopped chan struct{}
	mux     sync.RWMutex
}

// NewLocalAuthenticator creates an Authenticator that authenticates client by local infos.
func NewLocalAuthenticator(kvs map[string]string) *LocalAuthenticator {
	return &LocalAuthenticator{
		kvs:     kvs,
		stopped: make(chan struct{}),
	}
}

// Authenticate checks the validity of the provided user-password pair.
func (au *LocalAuthenticator) Authenticate(user, password string) bool {
	if au == nil {
		return true
	}

	au.mux.RLock()
	defer au.mux.RUnlock()

	if len(au.kvs) == 0 {
		return true
	}

	v, ok := au.kvs[user]
	return ok && (v == "" || password == v)
}

// Add adds a key-value pair to the Authenticator.
func (au *LocalAuthenticator) Add(k, v string) {
	au.mux.Lock()
	defer au.mux.Unlock()
	if au.kvs == nil {
		au.kvs = make(map[string]string)
	}
	au.kvs[k] = v
}

// Reload parses config from r, then live reloads the bypass.
func (au *LocalAuthenticator) Reload(r io.Reader) error {
	var period time.Duration
	kvs := make(map[string]string)

	if r == nil || au.Stopped() {
		return nil
	}

	// splitLine splits a line text by white space.
	// A line started with '#' will be ignored, otherwise it is valid.
	split := func(line string) []string {
		if line == "" {
			return nil
		}
		line = strings.Replace(line, "\t", " ", -1)
		line = strings.TrimSpace(line)

		if strings.IndexByte(line, '#') == 0 {
			return nil
		}

		var ss []string
		for _, s := range strings.Split(line, " ") {
			if s = strings.TrimSpace(s); s != "" {
				ss = append(ss, s)
			}
		}
		return ss
	}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		ss := split(line)
		if len(ss) == 0 {
			continue
		}

		switch ss[0] {
		case "reload": // reload option
			if len(ss) > 1 {
				period, _ = time.ParseDuration(ss[1])
			}
		default:
			var k, v string
			k = ss[0]
			if len(ss) > 1 {
				v = ss[1]
			}
			kvs[k] = v
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	au.mux.Lock()
	defer au.mux.Unlock()

	au.period = period
	au.kvs = kvs

	return nil
}

// Period returns the reload period.
func (au *LocalAuthenticator) Period() time.Duration {
	if au.Stopped() {
		return -1
	}

	au.mux.RLock()
	defer au.mux.RUnlock()

	return au.period
}

// Stop stops reloading.
func (au *LocalAuthenticator) Stop() {
	select {
	case <-au.stopped:
	default:
		close(au.stopped)
	}
}

// Stopped checks whether the reloader is stopped.
func (au *LocalAuthenticator) Stopped() bool {
	select {
	case <-au.stopped:
		return true
	default:
		return false
	}
}
