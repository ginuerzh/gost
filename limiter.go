package gost

import (
	"bufio"
	"errors"
	"io"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Limiter interface {
	CheckRate(key string, checkConcurrent bool) (func(), bool)
}

func NewLocalLimiter(user string, cfg string) (*LocalLimiter, error) {
	limiter := LocalLimiter{
		buckets:    map[string]*limiterBucket{},
		concurrent: map[string]chan bool{},
		stopped:    make(chan struct{}),
	}
	if cfg == "" || user == "" {
		return &limiter, nil
	}
	if err := limiter.AddRule(user, cfg); err != nil {
		return nil, err
	}
	return &limiter, nil
}

// Token Bucket
type limiterBucket struct {
	max      int64
	cur      int64
	duration int64
	batch    int64
}

type LocalLimiter struct {
	buckets    map[string]*limiterBucket
	concurrent map[string]chan bool
	mux        sync.RWMutex
	stopped    chan struct{}
	period     time.Duration
}

func (l *LocalLimiter) CheckRate(key string, checkConcurrent bool) (func(), bool) {
	if checkConcurrent {
		done, ok := l.checkConcurrent(key)
		if !ok {
			return nil, false
		}
		if t := l.getToken(key); !t {
			done()
			return nil, false
		}
		return done, true
	} else {
		if t := l.getToken(key); !t {
			return nil, false
		}
		return nil, true
	}
}

func (l *LocalLimiter) AddRule(user string, cfg string) error {
	if user == "" {
		return nil
	}
	if cfg == "" {
		//reload need check old limit exists
		if _, ok := l.buckets[user]; ok {
			delete(l.buckets, user)
		}
		if _, ok := l.concurrent[user]; ok {
			delete(l.concurrent, user)
		}
		return nil
	}
	args := strings.Split(cfg, ",")
	if len(args) < 2 || len(args) > 3 {
		return errors.New("parse limiter fail:" + cfg)
	}
	if len(args) == 2 {
		args = append(args, "0")
	}

	duration, e1 := strconv.ParseInt(strings.TrimSpace(args[0]), 10, 64)
	count, e2 := strconv.ParseInt(strings.TrimSpace(args[1]), 10, 64)
	cur, e3 := strconv.ParseInt(strings.TrimSpace(args[2]), 10, 64)
	if e1 != nil || e2 != nil || e3 != nil {
		return errors.New("parse limiter fail:" + cfg)
	}
	// 0 means not limit
	if duration > 0 && count > 0 {
		bu := &limiterBucket{
			cur:      count * 10,
			max:      count * 10,
			duration: duration * 100,
			batch:    count,
		}
		go func() {
			for {
				time.Sleep(time.Millisecond * time.Duration(bu.duration))
				if bu.cur+bu.batch > bu.max {
					bu.cur = bu.max
				} else {
					atomic.AddInt64(&bu.cur, bu.batch)
				}
			}
		}()
		l.buckets[user] = bu
	} else {
		if _, ok := l.buckets[user]; ok {
			delete(l.buckets, user)
		}
	}
	// zero means not limit
	if cur > 0 {
		l.concurrent[user] = make(chan bool, cur)
	} else {
		if _, ok := l.concurrent[user]; ok {
			delete(l.concurrent, user)
		}
	}
	return nil
}

// Reload parses config from r, then live reloads the LocalLimiter.
func (l *LocalLimiter) Reload(r io.Reader) error {
	var period time.Duration
	kvs := make(map[string]string)

	if r == nil || l.Stopped() {
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
			if len(ss) > 2 {
				v = ss[2]
			}
			kvs[k] = v
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	l.mux.Lock()
	defer l.mux.Unlock()

	l.period = period
	for user, args := range kvs {
		err := l.AddRule(user, args)
		if err != nil {
			return err
		}
	}

	return nil
}

// Period returns the reload period.
func (l *LocalLimiter) Period() time.Duration {
	if l.Stopped() {
		return -1
	}

	l.mux.RLock()
	defer l.mux.RUnlock()

	return l.period
}

// Stop stops reloading.
func (l *LocalLimiter) Stop() {
	select {
	case <-l.stopped:
	default:
		close(l.stopped)
	}
}

// Stopped checks whether the reloader is stopped.
func (l *LocalLimiter) Stopped() bool {
	select {
	case <-l.stopped:
		return true
	default:
		return false
	}
}

func (l *LocalLimiter) getToken(key string) bool {
	b, ok := l.buckets[key]
	if !ok || b == nil {
		return true
	}
	if b.cur <= 0 {
		return false
	}
	atomic.AddInt64(&b.cur, -10)
	return true
}

func (l *LocalLimiter) checkConcurrent(key string) (func(), bool) {
	c, ok := l.concurrent[key]
	if !ok || c == nil {
		return func() {}, true
	}
	select {
	case c <- true:
		return func() {
			<-c
		}, true
	default:
		return nil, false
	}
}
