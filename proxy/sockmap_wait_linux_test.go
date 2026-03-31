//go:build linux

package proxy

import "testing"

func TestSockmapIdleFallbackRounds(t *testing.T) {
	if sockmapMaxIdleRounds != 1 {
		t.Fatalf("sockmapMaxIdleRounds = %d, want 1", sockmapMaxIdleRounds)
	}
}

func TestForwardProgressCursorAdvancedFrom(t *testing.T) {
	prev := forwardProgressCursor{writerBytesAcked: 1}
	next := forwardProgressCursor{writerBytesAcked: 2}
	if !next.advancedFrom(prev) {
		t.Fatal("advancedFrom() = false, want true for sockmap-era counter delta")
	}

	same := forwardProgressCursor{writerBytesAcked: 2}
	if same.advancedFrom(next) {
		t.Fatal("advancedFrom() = true, want false when counters did not advance")
	}
}
