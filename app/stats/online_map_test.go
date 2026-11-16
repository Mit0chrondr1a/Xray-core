package stats

import (
	"fmt"
	"sync"
	"testing"
)

func TestOnlineMapAddAndCount(t *testing.T) {
	om := NewOnlineMap()
	if om.Count() != 0 {
		t.Fatalf("empty map count=%d, want 0", om.Count())
	}
	om.AddIP("10.0.0.1")
	if om.Count() != 1 {
		t.Fatalf("count=%d after add, want 1", om.Count())
	}
	om.AddIP("10.0.0.2")
	if om.Count() != 2 {
		t.Fatalf("count=%d after second add, want 2", om.Count())
	}
}

func TestOnlineMapAddDuplicate(t *testing.T) {
	om := NewOnlineMap()
	om.AddIP("10.0.0.1")
	om.AddIP("10.0.0.1")
	if om.Count() != 1 {
		t.Fatalf("duplicate add: count=%d, want 1", om.Count())
	}
}

func TestOnlineMapRefCountedRemove(t *testing.T) {
	om := NewOnlineMap()
	om.AddIP("10.0.0.1")
	om.AddIP("10.0.0.1")
	om.RemoveIP("10.0.0.1")
	if om.Count() != 1 {
		t.Fatalf("count=%d after one of two removes, want 1", om.Count())
	}
	om.RemoveIP("10.0.0.1")
	if om.Count() != 0 {
		t.Fatalf("count=%d after final remove, want 0", om.Count())
	}
	om.RemoveIP("10.0.0.1") // removing an absent IP is a no-op
	if om.Count() != 0 {
		t.Fatalf("count=%d after extra remove, want 0", om.Count())
	}
}

func TestOnlineMapIgnoresLoopback(t *testing.T) {
	om := NewOnlineMap()
	om.AddIP("127.0.0.1")
	if om.Count() != 0 {
		t.Fatal("127.0.0.1 should be ignored")
	}
}

func TestOnlineMapForEach(t *testing.T) {
	om := NewOnlineMap()
	om.AddIP("10.0.0.1")
	om.AddIP("10.0.0.2")

	seen := map[string]bool{}
	om.ForEach(func(ip string, lastSeen int64) bool {
		if lastSeen <= 0 {
			t.Errorf("ip %s has non-positive lastSeen %d", ip, lastSeen)
		}
		seen[ip] = true
		return true
	})
	if len(seen) != 2 || !seen["10.0.0.1"] || !seen["10.0.0.2"] {
		t.Fatalf("ForEach saw %v, want both IPs", seen)
	}

	calls := 0
	om.ForEach(func(string, int64) bool {
		calls++
		return false
	})
	if calls != 1 {
		t.Fatalf("ForEach did not stop early: %d calls", calls)
	}
}

func TestOnlineMapConcurrentAccess(t *testing.T) {
	om := NewOnlineMap()
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ip := fmt.Sprintf("10.0.0.%d", idx%10)
			om.AddIP(ip)
			_ = om.Count()
			om.ForEach(func(string, int64) bool { return true })
		}(i)
	}
	wg.Wait()

	// Verify the map contains the expected IPs (10 unique).
	count := om.Count()
	if count != 10 {
		t.Fatalf("expected 10 unique IPs, got %d", count)
	}
}
