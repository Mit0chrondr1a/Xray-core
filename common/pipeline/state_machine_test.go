package pipeline

import "testing"

func TestDecideVisionPathSplicePrimary(t *testing.T) {
	got := DecideVisionPath(DecisionInput{
		Caps: CapabilitySummary{
			SpliceSupported: true,
		},
		ReaderCrypto: "none",
		WriterCrypto: "none",
	})

	if got.Path != PathSplice {
		t.Fatalf("Path=%q, want %q", got.Path, PathSplice)
	}
	if got.Reason != ReasonSplicePrimary {
		t.Fatalf("Reason=%q, want %s", got.Reason, ReasonSplicePrimary)
	}
}

func TestDecideVisionPathDeferredTLSGuard(t *testing.T) {
	got := DecideVisionPath(DecisionInput{
		DeferredTLSActive: true,
		Caps: CapabilitySummary{
			SpliceSupported: true,
		},
	})

	if got.Path != PathUserspace {
		t.Fatalf("Path=%q, want %q", got.Path, PathUserspace)
	}
	if got.Reason != ReasonDeferredTLSGuard {
		t.Fatalf("Reason=%q, want %s", got.Reason, ReasonDeferredTLSGuard)
	}
}

func TestDecideVisionPathUserspaceTLSGuard(t *testing.T) {
	got := DecideVisionPath(DecisionInput{
		Caps: CapabilitySummary{
			SpliceSupported: true,
		},
		ReaderCrypto: "userspace-tls",
		WriterCrypto: "none",
	})

	if got.Path != PathUserspace {
		t.Fatalf("Path=%q, want %q", got.Path, PathUserspace)
	}
	if got.Reason != ReasonUserspaceTLSGuard {
		t.Fatalf("Reason=%q, want %s", got.Reason, ReasonUserspaceTLSGuard)
	}
}

func TestDecideVisionPathLoopbackUserspaceTLSGuard(t *testing.T) {
	got := DecideVisionPath(DecisionInput{
		LoopbackPair: true,
		Caps: CapabilitySummary{
			SpliceSupported: true,
		},
		ReaderCrypto: "userspace_tls",
		WriterCrypto: "none",
	})

	if got.Path != PathUserspace {
		t.Fatalf("Path=%q, want %q", got.Path, PathUserspace)
	}
	if got.Reason != ReasonLoopbackUserspaceTLSGuard {
		t.Fatalf("Reason=%q, want %s", got.Reason, ReasonLoopbackUserspaceTLSGuard)
	}
}
