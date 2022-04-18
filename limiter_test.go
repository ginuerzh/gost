package gost

import (
	"fmt"
	"testing"
)

func TestNewLocalLimiter(t *testing.T) {
	items := []struct {
		user    string
		args    string
		success bool
	}{
		{"admin", "10,1", true},
		{"admin", "", true},
		{"admin", "10,1,1", true},
		{"admin", "10", false},
		{"admin", "0,1", true},
		{"admin", "0,1,1", true},
		{"admin", "a,b", false},
		{"", "", true},
		{"", "1,2", true},
	}
	for i, item := range items {
		item := item
		t.Run(fmt.Sprintf("#%d", i), func(t *testing.T) {
			_, err := NewLocalLimiter(item.user, item.args)
			if (err == nil) != item.success {
				t.Error("test NewLocalLimiter fail", item.user, item.args)
			}
		})
	}
}

func TestCheckRate(t *testing.T) {
	items := []struct {
		user               string
		args               string
		testUser           string
		checkCount         int
		shouldSuccessCount int
	}{
		{"admin", "10,3", "admin", 10, 3},
		{"admin", "10,3,0", "admin", 10, 3},
		{"admin", "10,3,2", "admin", 10, 2},
		{"admin", "0,0", "admin", 10, 10},
		{"admin", "10,3,5", "admin", 10, 3},
		{"admin", "10,3,5", "admin22", 10, 10},
		{"admin", "0,0,5", "admin", 10, 5},
	}
	for i, item := range items {
		item := item
		t.Run(fmt.Sprintf("#%d", i), func(t *testing.T) {
			l, err := NewLocalLimiter(item.user, item.args)
			if err != nil {
				t.Error("test NewLocalLimiter fail", item.user, item.args)
			}
			successCount := 0
			for j := 0; j < item.checkCount; j++ {
				if _, ok := l.CheckRate(item.testUser, true); ok {
					successCount++
				}
			}
			if successCount != item.shouldSuccessCount {
				t.Error("test localLimiter fail", item)
			}
		})
	}
}
