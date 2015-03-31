// pool for buffer
package main

import (
	"container/list"
	//"log"
	"time"
)

type poolItem struct {
	when time.Time
	item interface{}
}

type pool struct {
	quque             *list.List
	takeChan, putChan chan interface{}
	age               time.Duration
	max               int
}

func (p *pool) run() {
	for {
		if p.size() == 0 {
			select {
			case b := <-p.putChan:
				p.put(b)
			}
			continue
		}

		i := p.quque.Front()
		timeout := time.NewTimer(p.age)

		select {
		case b := <-p.putChan:
			timeout.Stop()
			p.put(b)
		case p.takeChan <- i.Value.(*poolItem).item:
			timeout.Stop()
			p.quque.Remove(i)
		case <-timeout.C:
			i = p.quque.Back()
			for i != nil {
				if time.Since(i.Value.(*poolItem).when) < p.age {
					break
				}
				e := i.Prev()
				p.quque.Remove(i)
				i = e
			}
		}
	}
}

func (p *pool) size() int {
	return p.quque.Len()
}

func (p *pool) put(v interface{}) {
	if p.size() < p.max {
		p.quque.PushFront(&poolItem{when: time.Now(), item: v})
		return
	}
}

type MemPool struct {
	pool
	bs int
}

func NewMemPool(bs int, age time.Duration, max int) *MemPool {
	if bs <= 0 {
		bs = 8192
	}

	if age == 0 {
		age = 1 * time.Minute
	}

	p := &MemPool{
		pool: pool{
			quque:    list.New(),
			takeChan: make(chan interface{}),
			putChan:  make(chan interface{}),
			age:      age,
			max:      max,
		},
		bs: bs,
	}

	go p.run()

	return p
}

func (p *MemPool) Take() []byte {
	select {
	case v := <-p.takeChan:
		return v.([]byte)
	default:
		return make([]byte, p.bs)
	}
}

func (p *MemPool) Put(b []byte) {
	p.putChan <- b
}
