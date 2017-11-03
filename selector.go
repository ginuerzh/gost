package gost

import (
	"errors"
	"sync/atomic"
	"time"
)

var (
	// ErrNoneAvailable indicates there is no node available
	ErrNoneAvailable = errors.New("none available")
)

// NodeSelector as a mechanism to pick nodes and mark their status.
type NodeSelector interface {
	Select(nodes []Node, opts ...SelectOption) (Node, error)
	// Mark(node Node)
}

type defaultSelector struct {
}

func (s *defaultSelector) Select(nodes []Node, opts ...SelectOption) (Node, error) {
	sopts := SelectOptions{
		Strategy: &RoundStrategy{},
	}
	for _, opt := range opts {
		opt(&sopts)
	}

	for _, filter := range sopts.Filters {
		nodes = filter.Filter(nodes)
	}
	if len(nodes) == 0 {
		return Node{}, ErrNoneAvailable
	}
	return sopts.Strategy.Apply(nodes), nil
}

// Filter is used to filter a node during the selection process
type Filter interface {
	Filter([]Node) []Node
}

// Strategy is a selection strategy e.g random, round robin
type Strategy interface {
	Apply([]Node) Node
	String() string
}

// RoundStrategy is a strategy for node selector
type RoundStrategy struct {
	count uint64
}

// Apply applies the round robin strategy for the nodes
func (s *RoundStrategy) Apply(nodes []Node) Node {
	if len(nodes) == 0 {
		return Node{}
	}
	old := s.count
	atomic.AddUint64(&s.count, 1)
	return nodes[int(old%uint64(len(nodes)))]
}

func (s *RoundStrategy) String() string {
	return "round"
}

// RandomStrategy is a strategy for node selector
type RandomStrategy struct{}

// Apply applies the random strategy for the nodes
func (s *RandomStrategy) Apply(nodes []Node) Node {
	if len(nodes) == 0 {
		return Node{}
	}

	return nodes[time.Now().Nanosecond()%len(nodes)]
}

func (s *RandomStrategy) String() string {
	return "random"
}

// SelectOption used when making a select call
type SelectOption func(*SelectOptions)

// SelectOptions is the options for node selection
type SelectOptions struct {
	Filters  []Filter
	Strategy Strategy
}

// WithFilter adds a filter function to the list of filters
// used during the Select call.
func WithFilter(f ...Filter) SelectOption {
	return func(o *SelectOptions) {
		o.Filters = append(o.Filters, f...)
	}
}

// WithStrategy sets the selector strategy
func WithStrategy(s Strategy) SelectOption {
	return func(o *SelectOptions) {
		o.Strategy = s
	}
}

// IPSelector as a mechanism to pick IPs and mark their status.
type IPSelector interface {
	Select(ips []string) (string, error)
	String() string
}

// RandomIPSelector is an IP Selector that selects an IP with random strategy.
type RandomIPSelector struct {
}

// Select selects an IP from ips list.
func (s *RandomIPSelector) Select(ips []string) (string, error) {
	if len(ips) == 0 {
		return "", nil
	}
	return ips[time.Now().Nanosecond()%len(ips)], nil
}

func (s *RandomIPSelector) String() string {
	return "random"
}

// RoundRobinIPSelector is an IP Selector that selects an IP with round-robin strategy.
type RoundRobinIPSelector struct {
	count uint64
}

// Select selects an IP from ips list.
func (s *RoundRobinIPSelector) Select(ips []string) (string, error) {
	if len(ips) == 0 {
		return "", nil
	}
	old := s.count
	atomic.AddUint64(&s.count, 1)
	return ips[int(old%uint64(len(ips)))], nil
}

func (s *RoundRobinIPSelector) String() string {
	return "round"
}
