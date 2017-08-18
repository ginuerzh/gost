package gost

import "errors"

var (
	// ErrNoneAvailable indicates there is no node available
	ErrNoneAvailable = errors.New("none available")
)

// SelectOption used when making a select call
type SelectOption func(*SelectOptions)

// Selector as a mechanism to pick nodes and mark their status.
type Selector interface {
	Select(nodes []Node, opts ...SelectOption) (Node, error)
	// Mark(node Node)
	String() string
}

type defaultSelector struct {
}

func (s *defaultSelector) Select(nodes []Node, opts ...SelectOption) (Node, error) {
	sopts := SelectOptions{
		Strategy: defaultStrategy,
	}
	for _, opt := range opts {
		opt(&sopts)
	}

	for _, filter := range sopts.Filters {
		nodes = filter(nodes)
	}
	if len(nodes) == 0 {
		return Node{}, ErrNoneAvailable
	}
	return sopts.Strategy(nodes), nil
}

func (s *defaultSelector) String() string {
	return "default"
}

// Filter is used to filter a node during the selection process
type Filter func([]Node) []Node

// Strategy is a selection strategy e.g random, round robin
type Strategy func([]Node) Node

func defaultStrategy(nodes []Node) Node {
	return nodes[0]
}

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
