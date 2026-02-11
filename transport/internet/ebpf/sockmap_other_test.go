//go:build !linux

package ebpf

import (
	"testing"
)

func TestSockmapNotSupportedOnNonLinux(t *testing.T) {
	mgr := NewSockmapManager(DefaultSockmapConfig())
	if err := mgr.Enable(); err == nil {
		t.Fatal("Enable should fail on non-Linux")
	}
}

func TestGlobalSockmapManagerNonLinux(t *testing.T) {
	mgr := GlobalSockmapManager()
	if mgr != nil {
		t.Fatal("GlobalSockmapManager should be nil on non-Linux")
	}
}
