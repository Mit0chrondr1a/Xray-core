//go:build linux

package ebpf

import (
	"syscall"
	"testing"
)

func TestShouldCollectCapabilityGateDiagnostics(t *testing.T) {
	capsPermission := Capabilities{
		SockmapSupported:  false,
		KernelVersion:     KernelVersion{Major: 6, Minor: 1, Patch: 0},
		sockmapProbeErrno: syscall.EPERM,
	}
	if !shouldCollectCapabilityGateDiagnostics(capsPermission) {
		t.Fatal("permission/seccomp probe failures should collect diagnostics")
	}

	capsKernelUnsupported := Capabilities{
		SockmapSupported: false,
		KernelVersion:    KernelVersion{Major: 4, Minor: 15, Patch: 0},
	}
	if shouldCollectCapabilityGateDiagnostics(capsKernelUnsupported) {
		t.Fatal("kernel-unsupported capability gate should skip deep diagnostics")
	}
}

func TestClassifySockmapEPERMCause(t *testing.T) {
	tests := []struct {
		name        string
		seccomp     string
		inContainer bool
		want        string
	}{
		{
			name:        "container seccomp",
			seccomp:     "2",
			inContainer: true,
			want:        "docker/container seccomp filter",
		},
		{
			name:        "host seccomp",
			seccomp:     "2",
			inContainer: false,
			want:        "seccomp filter",
		},
		{
			name:        "capability or lsm",
			seccomp:     "0",
			inContainer: true,
			want:        "missing capabilities or LSM policy",
		},
	}

	for _, tt := range tests {
		if got := classifySockmapEPERMCause(tt.seccomp, tt.inContainer); got != tt.want {
			t.Fatalf("%s: got %q, want %q", tt.name, got, tt.want)
		}
	}
}
