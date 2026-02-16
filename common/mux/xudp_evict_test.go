package mux

import (
	"context"
	"testing"
	"time"

	"github.com/xtls/xray-core/transport/pipe"
)

// makeTestXUDP creates a test XUDP entry with pipe-backed sessions.
func makeTestXUDP(gid [8]byte, status uint64, createdAt time.Time, expire time.Time) *XUDP {
	r, w := pipe.New(pipe.OptionsFromContext(context.Background())...)
	return &XUDP{
		GlobalID:  gid,
		Status:    status,
		CreatedAt: createdAt,
		Expire:    expire,
		Mux: &Session{
			input:  r,
			output: w,
		},
	}
}

func clearXUDPMap() {
	for id := range XUDPManager.Map {
		delete(XUDPManager.Map, id)
	}
}

func TestXudpEvictExpiringEmpty(t *testing.T) {
	XUDPManager.Lock()
	defer XUDPManager.Unlock()
	clearXUDPMap()

	if xudpEvictExpiring() {
		t.Fatal("xudpEvictExpiring should return false on empty map")
	}
}

func TestXudpEvictExpiringEvictsOldestExpiring(t *testing.T) {
	XUDPManager.Lock()
	defer XUDPManager.Unlock()
	clearXUDPMap()

	now := time.Now()
	id1 := [8]byte{1}
	id2 := [8]byte{2}
	id3 := [8]byte{3}

	XUDPManager.Map[id1] = makeTestXUDP(id1, Expiring, now, now.Add(-2*time.Minute))
	XUDPManager.Map[id2] = makeTestXUDP(id2, Expiring, now, now.Add(-1*time.Minute))
	XUDPManager.Map[id3] = makeTestXUDP(id3, Active, now, time.Time{})

	if !xudpEvictExpiring() {
		t.Fatal("xudpEvictExpiring should return true when Expiring entries exist")
	}

	// The oldest Expiring entry (id1, Expire=-2min) should be evicted.
	if _, ok := XUDPManager.Map[id1]; ok {
		t.Fatal("oldest Expiring entry (id1) should have been evicted")
	}
	if _, ok := XUDPManager.Map[id2]; !ok {
		t.Fatal("newer Expiring entry (id2) should still exist")
	}
	if _, ok := XUDPManager.Map[id3]; !ok {
		t.Fatal("Active entry (id3) should still exist")
	}
	if len(XUDPManager.Map) != 2 {
		t.Fatalf("map should have 2 entries, got %d", len(XUDPManager.Map))
	}
}

func TestXudpEvictExpiringFallsBackToOldestActive(t *testing.T) {
	XUDPManager.Lock()
	defer XUDPManager.Unlock()
	clearXUDPMap()

	now := time.Now()
	id1 := [8]byte{10}
	id2 := [8]byte{20}

	// No Expiring entries -- both Active.
	XUDPManager.Map[id1] = makeTestXUDP(id1, Active, now.Add(-10*time.Minute), time.Time{})
	XUDPManager.Map[id2] = makeTestXUDP(id2, Active, now.Add(-1*time.Minute), time.Time{})

	if !xudpEvictExpiring() {
		t.Fatal("xudpEvictExpiring should return true when Active entries exist as fallback")
	}

	// The oldest Active entry (id1, CreatedAt=-10min) should be evicted.
	if _, ok := XUDPManager.Map[id1]; ok {
		t.Fatal("oldest Active entry (id1) should have been evicted")
	}
	if _, ok := XUDPManager.Map[id2]; !ok {
		t.Fatal("newer Active entry (id2) should still exist")
	}
}

func TestXudpEvictExpiringInitializingOnly(t *testing.T) {
	XUDPManager.Lock()
	defer XUDPManager.Unlock()
	clearXUDPMap()

	now := time.Now()
	id1 := [8]byte{30}
	XUDPManager.Map[id1] = makeTestXUDP(id1, Initializing, now, time.Time{})

	// Initializing entries should not be evicted by either path.
	if xudpEvictExpiring() {
		t.Fatal("xudpEvictExpiring should return false when only Initializing entries exist")
	}
	if len(XUDPManager.Map) != 1 {
		t.Fatal("Initializing entry should not be removed")
	}
}

func TestXudpEvictExpiringSingleEntry(t *testing.T) {
	XUDPManager.Lock()
	defer XUDPManager.Unlock()
	clearXUDPMap()

	now := time.Now()
	id1 := [8]byte{40}
	XUDPManager.Map[id1] = makeTestXUDP(id1, Active, now, time.Time{})

	if !xudpEvictExpiring() {
		t.Fatal("should evict the sole Active entry")
	}
	if len(XUDPManager.Map) != 0 {
		t.Fatal("map should be empty after evicting sole entry")
	}
}
