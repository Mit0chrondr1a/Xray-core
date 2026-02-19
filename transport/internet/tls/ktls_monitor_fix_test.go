//go:build linux

package tls

import (
	"io"
	"syscall"
	"testing"
	"time"
)

// =============================================================================
// Tests for Fix 1+2: kTLS monitor transient error retry and warning logging
// =============================================================================

// TestIsTransientSockoptError verifies that the transient error classifier
// correctly identifies EINTR and EAGAIN as transient, and rejects other errors.
func TestIsTransientSockoptError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{"EINTR", syscall.EINTR, true},
		{"EAGAIN", syscall.EAGAIN, true},
		{"EWOULDBLOCK", syscall.EWOULDBLOCK, true}, // EWOULDBLOCK == EAGAIN on Linux
		{"EBADF", syscall.EBADF, false},
		{"ENOTSOCK", syscall.ENOTSOCK, false},
		{"ENOMEM", syscall.ENOMEM, false},
		{"io.EOF", io.EOF, false},
		{"generic error", io.ErrUnexpectedEOF, false},
		{"nil errno 0", syscall.Errno(0), false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := isTransientSockoptError(tc.err)
			if result != tc.expected {
				t.Errorf("isTransientSockoptError(%v) = %v, want %v", tc.err, result, tc.expected)
			}
		})
	}
}

// TestClampDuration verifies the duration clamping helper.
func TestClampDuration(t *testing.T) {
	tests := []struct {
		name     string
		d        time.Duration
		min      time.Duration
		max      time.Duration
		expected time.Duration
	}{
		{"below min", 500 * time.Millisecond, 1 * time.Second, 10 * time.Second, 1 * time.Second},
		{"at min", 1 * time.Second, 1 * time.Second, 10 * time.Second, 1 * time.Second},
		{"between min and max", 5 * time.Second, 1 * time.Second, 10 * time.Second, 5 * time.Second},
		{"at max", 10 * time.Second, 1 * time.Second, 10 * time.Second, 10 * time.Second},
		{"above max", 30 * time.Second, 1 * time.Second, 10 * time.Second, 10 * time.Second},
		{"negative", -1 * time.Second, 1 * time.Second, 10 * time.Second, 1 * time.Second},
		{"zero", 0, 1 * time.Second, 10 * time.Second, 1 * time.Second},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := clampDuration(tc.d, tc.min, tc.max)
			if result != tc.expected {
				t.Errorf("clampDuration(%v, %v, %v) = %v, want %v", tc.d, tc.min, tc.max, result, tc.expected)
			}
		})
	}
}

// TestKeyUpdateMonitorNilHandler verifies that NewKeyUpdateMonitor returns nil
// when handler is nil, and that Start/Stop on nil monitor do not panic.
func TestKeyUpdateMonitorNilHandler(t *testing.T) {
	m := NewKeyUpdateMonitor(42, nil)
	if m != nil {
		t.Fatal("expected nil monitor for nil handler")
	}

	// Start and Stop must not panic on nil receiver.
	m.Start()
	m.Stop()
}

// TestKeyUpdateMonitorStopIdempotent verifies that Stop can be called
// multiple times without panic.
func TestKeyUpdateMonitorStopIdempotent(t *testing.T) {
	// Create a monitor with a dummy handler (we won't Start it, just Stop).
	secret := make([]byte, 32)
	h := newKTLSKeyUpdateHandler(0, 0x1301, secret, secret) // TLS_AES_128_GCM_SHA256
	if h == nil {
		t.Skip("newKTLSKeyUpdateHandler returned nil for suite 0x1301")
	}

	m := NewKeyUpdateMonitor(42, h)
	if m == nil {
		t.Fatal("expected non-nil monitor")
	}

	// Multiple Stop calls must not panic.
	m.Stop()
	m.Stop()
	m.Stop()
}

// TestKeyUpdateMonitorConstants verifies the monitor's configuration constants
// are sensible.
func TestKeyUpdateMonitorConstants(t *testing.T) {
	if minPollInterval >= maxPollInterval {
		t.Fatalf("minPollInterval (%v) must be < maxPollInterval (%v)",
			minPollInterval, maxPollInterval)
	}
	if maxTransientErrors < 1 {
		t.Fatalf("maxTransientErrors must be >= 1, got %d", maxTransientErrors)
	}
	if rxWarningRatio <= 0 || rxWarningRatio >= 1.0 {
		t.Fatalf("rxWarningRatio must be in (0, 1), got %f", rxWarningRatio)
	}
}
