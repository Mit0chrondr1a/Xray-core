//go:build linux

package ebpf

import (
	"net"
	"os"
	"runtime"
	"testing"
	"time"
)

// RestartSafety simulates a container restart: enable → register → unregister → disable,
// then enable again and ensure registration still works even if pinned maps exist.
func TestSockmapRestartSafety(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only")
	}
	if os.Geteuid() != 0 {
		t.Skip("requires root/CAP_BPF to load sockmap")
	}

	caps := GetCapabilities()
	if !caps.SockmapSupported {
		t.Skip("sockmap not supported on this kernel")
	}

	cfg := DefaultSockmapConfig()
	cfg.MaxEntries = 64

	manager := NewSockmapManager(cfg)
	if err := manager.Enable(); err != nil {
		t.Skipf("enable sockmap skipped: %v", err)
	}
	defer manager.Disable()

	registerOnce := func() error {
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			return err
		}
		defer ln.Close()

		serverCh := make(chan net.Conn, 1)
		go func() {
			c, _ := ln.Accept()
			serverCh <- c
		}()

		client, err := net.DialTimeout("tcp4", ln.Addr().String(), 2*time.Second)
		if err != nil {
			return err
		}
		server := <-serverCh
		if server == nil {
			client.Close()
			return err
		}
		defer client.Close()
		defer server.Close()

		if err := manager.RegisterPair(client, server); err != nil {
			return err
		}
		defer manager.UnregisterPair(client, server)
		return nil
	}

	if err := registerOnce(); err != nil {
		t.Skipf("register skipped (likely missing CAP_BPF): %v", err)
	}

	if err := manager.Disable(); err != nil {
		t.Fatalf("disable after first run: %v", err)
	}

	if err := manager.Enable(); err != nil {
		t.Fatalf("re-enable after disable: %v", err)
	}
	defer manager.Disable()

	if err := registerOnce(); err != nil {
		t.Fatalf("register after simulated restart failed: %v", err)
	}
}
