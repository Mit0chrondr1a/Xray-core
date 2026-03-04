package tcp

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/native"
)

func TestIsDeferredRealityPeekTimeout(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "peek header receive timeout",
			err:  errors.New("native REALITY deferred: peek header: peek_exact: receive timeout"),
			want: true,
		},
		{
			name: "peek record handshake timeout",
			err:  errors.New("native REALITY deferred: peek record: peek_exact: handshake timeout exceeded"),
			want: true,
		},
		{
			name: "peek short read timeout",
			err:  errors.New("native REALITY deferred: peek record: peek_exact: short read after 5 retries (17/517 bytes)"),
			want: true,
		},
		{
			name: "sentinel timeout wraps",
			err:  fmt.Errorf("%w: simulated", native.ErrRealityDeferredPeekTimeout),
			want: true,
		},
		{
			name: "auth failure should not match",
			err:  errors.New("REALITY auth failed: needs fallback"),
			want: false,
		},
		{
			name: "non-timeout deferred error should not match",
			err:  errors.New("native REALITY deferred: handshake: bad certificate"),
			want: false,
		},
		{
			name: "nil",
			err:  nil,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isDeferredRealityPeekTimeout(tt.err); got != tt.want {
				t.Fatalf("isDeferredRealityPeekTimeout() = %v, want %v", got, tt.want)
			}
		})
	}
}

func resetRustPeekBypassMapForTest() {
	rustPeekBypassByRemote = sync.Map{}
}

func TestRustPeekBypassKey(t *testing.T) {
	addr := &net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 443}
	if got, want := rustPeekBypassKey(addr), "203.0.113.7"; got != want {
		t.Fatalf("rustPeekBypassKey() = %q, want %q", got, want)
	}
}

func TestRustPeekBypassKeyLoopbackIncludesPort(t *testing.T) {
	addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8443}
	if got, want := rustPeekBypassKey(addr), "127.0.0.1:8443"; got != want {
		t.Fatalf("rustPeekBypassKey() = %q, want %q", got, want)
	}
}

func TestRustPeekBypassLifecycle(t *testing.T) {
	resetRustPeekBypassMapForTest()
	t.Cleanup(resetRustPeekBypassMapForTest)

	addr := &net.TCPAddr{IP: net.ParseIP("198.51.100.20"), Port: 8443}
	now := time.Now().UnixNano()

	if shouldBypassRustDeferredForRemote(addr, now) {
		t.Fatal("expected bypass to be inactive before first set")
	}

	setRustPeekBypassForRemote(addr, now)
	if !shouldBypassRustDeferredForRemote(addr, now+int64(time.Second)) {
		t.Fatal("expected bypass to be active shortly after set")
	}

	if shouldBypassRustDeferredForRemote(addr, now+int64(rustPeekBypassWindow)+1) {
		t.Fatal("expected bypass to expire after window")
	}
}

func TestRustPeekBypassLifecycleLoopbackWindow(t *testing.T) {
	resetRustPeekBypassMapForTest()
	t.Cleanup(resetRustPeekBypassMapForTest)

	addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8443}
	now := time.Now().UnixNano()

	window, ok := setRustPeekBypassForRemote(addr, now)
	if !ok {
		t.Fatal("expected loopback bypass set to succeed")
	}
	if window != rustPeekBypassLoopbackWindow {
		t.Fatalf("expected loopback window %v, got %v", rustPeekBypassLoopbackWindow, window)
	}

	if !shouldBypassRustDeferredForRemote(addr, now+int64(time.Second)) {
		t.Fatal("expected loopback bypass to be active shortly after set")
	}
	if shouldBypassRustDeferredForRemote(addr, now+int64(rustPeekBypassLoopbackWindow)+1) {
		t.Fatal("expected loopback bypass to expire after loopback window")
	}
}

func TestRustPeekBypassLoopbackNoCrossFlow(t *testing.T) {
	resetRustPeekBypassMapForTest()
	t.Cleanup(resetRustPeekBypassMapForTest)

	now := time.Now().UnixNano()
	first := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 50001}
	second := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 50002}

	setRustPeekBypassForRemote(first, now)
	if !shouldBypassRustDeferredForRemote(first, now+int64(time.Second)) {
		t.Fatal("expected loopback bypass on the same endpoint")
	}
	if shouldBypassRustDeferredForRemote(second, now+int64(time.Second)) {
		t.Fatal("expected no loopback cross-flow bypass across different endpoints")
	}
}

func TestRustPeekBypassNonLoopbackStillSharedByIP(t *testing.T) {
	resetRustPeekBypassMapForTest()
	t.Cleanup(resetRustPeekBypassMapForTest)

	now := time.Now().UnixNano()
	first := &net.TCPAddr{IP: net.ParseIP("198.51.100.20"), Port: 50001}
	second := &net.TCPAddr{IP: net.ParseIP("198.51.100.20"), Port: 50002}

	setRustPeekBypassForRemote(first, now)
	if !shouldBypassRustDeferredForRemote(second, now+int64(time.Second)) {
		t.Fatal("expected non-loopback bypass to stay shared by remote IP")
	}
}

func TestPruneAndCountRustPeekBypass(t *testing.T) {
	resetRustPeekBypassMapForTest()
	t.Cleanup(resetRustPeekBypassMapForTest)

	now := time.Now().UnixNano()
	active := &net.TCPAddr{IP: net.ParseIP("203.0.113.1"), Port: 443}
	expired := &net.TCPAddr{IP: net.ParseIP("203.0.113.2"), Port: 443}

	setRustPeekBypassForRemote(active, now)
	setRustPeekBypassForRemote(expired, now-int64(rustPeekBypassWindow)-1)

	tracked := pruneAndCountRustPeekBypass(now)
	if tracked != 1 {
		t.Fatalf("expected 1 tracked bypass entry after prune, got %d", tracked)
	}
}
