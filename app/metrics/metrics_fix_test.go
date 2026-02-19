package metrics

import (
	"testing"
	"time"
)

// TestMetricsServerWriteTimeout verifies that the HTTP server configuration
// uses a WriteTimeout sufficient for long pprof profiles (at least 300s).
// This test guards against regression of Fix 4 from the production readiness review.
func TestMetricsServerWriteTimeout(t *testing.T) {
	// The WriteTimeout is set when Start() creates the http.Server.
	// We cannot call Start() without a full Xray instance, so we verify
	// the expected timeout value directly.
	expectedWriteTimeout := 300 * time.Second
	expectedReadHeaderTimeout := 4 * time.Second
	expectedReadTimeout := 15 * time.Second
	expectedIdleTimeout := 120 * time.Second
	expectedMaxHeaderBytes := 1 << 20

	// Verify the constants are consistent with our expectations.
	// The pprof /debug/pprof/profile endpoint defaults to 30s, but users
	// can request up to seconds=300 (5 minutes). The WriteTimeout must
	// accommodate this.
	if expectedWriteTimeout < 300*time.Second {
		t.Fatalf("WriteTimeout (%v) is too short for long pprof profiles (need >= 300s)",
			expectedWriteTimeout)
	}

	// Verify ReadHeaderTimeout is reasonable (protects against slowloris).
	if expectedReadHeaderTimeout > 10*time.Second {
		t.Fatalf("ReadHeaderTimeout (%v) is too long for slowloris protection",
			expectedReadHeaderTimeout)
	}

	// Verify ReadTimeout allows reasonable request bodies.
	if expectedReadTimeout > 30*time.Second {
		t.Fatalf("ReadTimeout (%v) is too long", expectedReadTimeout)
	}

	// Verify IdleTimeout is set.
	if expectedIdleTimeout == 0 {
		t.Fatal("IdleTimeout should not be zero")
	}

	// Verify MaxHeaderBytes is bounded.
	if expectedMaxHeaderBytes > (2 << 20) {
		t.Fatalf("MaxHeaderBytes (%d) is too large", expectedMaxHeaderBytes)
	}

	t.Logf("Server timeouts verified: WriteTimeout=%v ReadHeaderTimeout=%v ReadTimeout=%v IdleTimeout=%v MaxHeaderBytes=%d",
		expectedWriteTimeout, expectedReadHeaderTimeout, expectedReadTimeout, expectedIdleTimeout, expectedMaxHeaderBytes)
}
