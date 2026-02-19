package tls

import (
	"sync/atomic"
	"testing"
)

func TestStopOcspTickersForOwnerScopesTickerStops(t *testing.T) {
	StopAllOcspTickers()
	t.Cleanup(StopAllOcspTickers)

	ownerA := new(int)
	ownerB := new(int)

	var ownerAStops atomic.Int32
	var ownerBStops atomic.Int32

	registerOcspTicker(ownerA, func() { ownerAStops.Add(1) })
	registerOcspTicker(ownerA, func() { ownerAStops.Add(1) })
	registerOcspTicker(ownerB, func() { ownerBStops.Add(1) })

	StopOcspTickersForOwner(ownerA)
	if got := ownerAStops.Load(); got != 2 {
		t.Fatalf("owner A stop count = %d, want 2", got)
	}
	if got := ownerBStops.Load(); got != 0 {
		t.Fatalf("owner B stop count = %d, want 0", got)
	}

	// Second stop should be a no-op for already cleared owner.
	StopOcspTickersForOwner(ownerA)
	if got := ownerAStops.Load(); got != 2 {
		t.Fatalf("owner A stop count after second stop = %d, want 2", got)
	}

	StopOcspTickersForOwner(ownerB)
	if got := ownerBStops.Load(); got != 1 {
		t.Fatalf("owner B stop count = %d, want 1", got)
	}
}
