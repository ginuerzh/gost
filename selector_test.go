package gost

import (
	"testing"
	"time"
)

func TestRoundStrategy(t *testing.T) {
	nodes := []Node{
		Node{ID: 1},
		Node{ID: 2},
		Node{ID: 3},
	}
	s := NewStrategy("round")
	t.Log(s.String())

	if node := s.Apply(nil); node.ID > 0 {
		t.Error("unexpected node", node.String())
	}
	for i := 0; i <= len(nodes); i++ {
		node := s.Apply(nodes)
		if node.ID != nodes[i%len(nodes)].ID {
			t.Error("unexpected node", node.String())
		}
	}
}

func TestRandomStrategy(t *testing.T) {
	nodes := []Node{
		Node{ID: 1},
		Node{ID: 2},
		Node{ID: 3},
	}
	s := NewStrategy("random")
	t.Log(s.String())

	if node := s.Apply(nil); node.ID > 0 {
		t.Error("unexpected node", node.String())
	}
	for i := 0; i <= len(nodes); i++ {
		node := s.Apply(nodes)
		if node.ID == 0 {
			t.Error("unexpected node", node.String())
		}
	}
}

func TestFIFOStrategy(t *testing.T) {
	nodes := []Node{
		Node{ID: 1},
		Node{ID: 2},
		Node{ID: 3},
	}
	s := NewStrategy("fifo")
	t.Log(s.String())

	if node := s.Apply(nil); node.ID > 0 {
		t.Error("unexpected node", node.String())
	}
	for i := 0; i <= len(nodes); i++ {
		node := s.Apply(nodes)
		if node.ID != 1 {
			t.Error("unexpected node", node.String())
		}
	}
}

func TestFailFilter(t *testing.T) {
	nodes := []Node{
		Node{ID: 1, marker: &failMarker{}},
		Node{ID: 2, marker: &failMarker{}},
		Node{ID: 3, marker: &failMarker{}},
	}
	filter := &FailFilter{}
	t.Log(filter.String())

	isEqual := func(a, b []Node) bool {
		if a == nil && b == nil {
			return true
		}
		if a == nil || b == nil || len(a) != len(b) {
			return false
		}

		for i := range a {
			if a[i].ID != b[i].ID {
				return false
			}
		}
		return true
	}
	if v := filter.Filter(nil); v != nil {
		t.Error("unexpected node", v)
	}

	if v := filter.Filter(nodes); !isEqual(v, nodes) {
		t.Error("unexpected node", v)
	}

	filter.MaxFails = -1
	nodes[0].MarkDead()
	if v := filter.Filter(nodes); !isEqual(v, nodes) {
		t.Error("unexpected node", v)
	}

	filter.MaxFails = 0
	if v := filter.Filter(nodes); isEqual(v, nodes) {
		t.Error("unexpected node", v)
	}

	filter.FailTimeout = 5 * time.Second
	if v := filter.Filter(nodes); isEqual(v, nodes) {
		t.Error("unexpected node", v)
	}

	nodes[1].MarkDead()
	nodes[2].MarkDead()
	if v := filter.Filter(nodes); len(v) > 0 {
		t.Error("unexpected node", v)
	}

	for i := range nodes {
		nodes[i].ResetDead()
	}
	if v := filter.Filter(nodes); !isEqual(v, nodes) {
		t.Error("unexpected node", v)
	}
}

func TestSelector(t *testing.T) {
	nodes := []Node{
		Node{ID: 1, marker: &failMarker{}},
		Node{ID: 2, marker: &failMarker{}},
		Node{ID: 3, marker: &failMarker{}},
	}
	selector := &defaultSelector{}
	if _, err := selector.Select(nil); err != ErrNoneAvailable {
		t.Error("got unexpected error:", err)
	}

	if node, _ := selector.Select(nodes); node.ID != 1 {
		t.Error("unexpected node:", node)
	}

	if node, _ := selector.Select(nodes,
		WithStrategy(NewStrategy("")),
		WithFilter(&FailFilter{MaxFails: 1, FailTimeout: 3 * time.Second}),
	); node.ID != 1 {
		t.Error("unexpected node:", node)
	}
}
