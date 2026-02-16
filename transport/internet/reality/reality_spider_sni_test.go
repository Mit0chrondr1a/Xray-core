package reality

import (
	"testing"
)

// TestMaxRealitySpiderSNIsDefault verifies the SNI cap is set to a
// reasonable positive value and matches the declared constant.
func TestMaxRealitySpiderSNIsDefault(t *testing.T) {
	if maxRealitySpiderSNIs <= 0 {
		t.Fatalf("maxRealitySpiderSNIs = %d, want > 0", maxRealitySpiderSNIs)
	}
	if maxRealitySpiderSNIs != 256 {
		t.Fatalf("maxRealitySpiderSNIs = %d, want 256", maxRealitySpiderSNIs)
	}
}

// TestSpiderSNICapEnforcement simulates the SNI-limiting logic that
// runs inside UClient when a new ServerName is encountered.
// The check is: if len(maps.maps) >= maxRealitySpiderSNIs, reject.
func TestSpiderSNICapEnforcement(t *testing.T) {
	// Save and restore global state.
	prevLimit := maxRealitySpiderSNIs
	defer func() { maxRealitySpiderSNIs = prevLimit }()

	maps.Lock()
	prevMaps := maps.maps
	maps.maps = make(map[string]map[string]struct{})
	maps.Unlock()
	defer func() {
		maps.Lock()
		maps.maps = prevMaps
		maps.Unlock()
	}()

	maxRealitySpiderSNIs = 3

	// Simulate adding SNIs up to the cap.
	addSNI := func(sni string) bool {
		maps.Lock()
		defer maps.Unlock()
		if maps.maps == nil {
			maps.maps = make(map[string]map[string]struct{})
		}
		paths := maps.maps[sni]
		if paths == nil {
			if len(maps.maps) >= maxRealitySpiderSNIs {
				return false // would be rejected
			}
			paths = make(map[string]struct{})
			paths["/"] = struct{}{}
			maps.maps[sni] = paths
		}
		return true
	}

	// Should accept first 3 distinct SNIs.
	for i, sni := range []string{"a.com", "b.com", "c.com"} {
		if !addSNI(sni) {
			t.Fatalf("SNI %d (%s) rejected, should have been accepted", i, sni)
		}
	}

	// 4th distinct SNI should be rejected.
	if addSNI("d.com") {
		t.Fatal("4th SNI accepted, should have been rejected (cap=3)")
	}

	// Existing SNI should still work (it's a lookup, not a new entry).
	if !addSNI("a.com") {
		t.Fatal("existing SNI rejected, should have been accepted")
	}

	maps.Lock()
	count := len(maps.maps)
	maps.Unlock()
	if count != 3 {
		t.Fatalf("maps.maps has %d entries, want 3", count)
	}
}
