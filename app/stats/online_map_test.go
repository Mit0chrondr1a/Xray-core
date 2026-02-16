package stats

import (
	"fmt"
	"sync"
	"testing"
	"time"
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

func TestOnlineMapIgnoresLoopback(t *testing.T) {
	om := NewOnlineMap()
	om.AddIP("127.0.0.1")
	if om.Count() != 0 {
		t.Fatal("127.0.0.1 should be ignored")
	}
}

func TestOnlineMapList(t *testing.T) {
	om := NewOnlineMap()
	om.AddIP("10.0.0.1")
	om.AddIP("10.0.0.2")
	list := om.List()
	if len(list) != 2 {
		t.Fatalf("List() len=%d, want 2", len(list))
	}
}

func TestOnlineMapRemoveExpiredIPs(t *testing.T) {
	om := NewOnlineMap()
	om.AddIP("10.0.0.1")
	// Manually expire by setting timestamp in the past.
	om.ipList["10.0.0.1"] = time.Now().Add(-30 * time.Second)
	om.RemoveExpiredIPs()
	if om.Count() != 0 {
		t.Fatalf("expired IP should be removed: count=%d", om.Count())
	}
}

func TestOnlineMapIpTimeMap(t *testing.T) {
	om := NewOnlineMap()
	om.AddIP("192.168.1.1")
	m := om.IpTimeMap()
	if _, ok := m["192.168.1.1"]; !ok {
		t.Fatal("IpTimeMap should contain added IP")
	}
}

func TestOnlineMapIpTimeMapTriggerCleanup(t *testing.T) {
	om := NewOnlineMap()
	om.cleanupPeriod = 0 // trigger cleanup every time

	om.AddIP("10.0.0.1")
	om.ipList["10.0.0.1"] = time.Now().Add(-30 * time.Second)

	m := om.IpTimeMap()
	if _, ok := m["10.0.0.1"]; ok {
		t.Fatal("expired IP should be cleaned up by IpTimeMap")
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
			_ = om.List()
			_ = om.IpTimeMap()
		}(i)
	}
	wg.Wait()

	// Verify the map contains the expected IPs (10 unique).
	count := om.Count()
	if count != 10 {
		t.Fatalf("expected 10 unique IPs, got %d", count)
	}
}

func TestOnlineMapCleaningTryLock(t *testing.T) {
	om := NewOnlineMap()
	om.cleanupPeriod = 0

	// Simulate concurrent cleanup attempts.
	// The atomic trylock should prevent both from running RemoveExpiredIPs simultaneously.
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			om.AddIP("10.0.0.1")
		}()
	}
	wg.Wait()
}

func TestOnlineMapGetKeys(t *testing.T) {
	om := NewOnlineMap()
	om.AddIP("a.b.c.d")
	om.AddIP("e.f.g.h")
	keys := om.GetKeys()
	if len(keys) != 2 {
		t.Fatalf("GetKeys() len=%d, want 2", len(keys))
	}
}
