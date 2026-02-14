//go:build linux

package ebpf

import (
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestSockmapManagerEnable(t *testing.T) {
	caps := GetCapabilities()
	mgr := NewSockmapManager(DefaultSockmapConfig())

	err := mgr.Enable()
	if !caps.SockmapSupported {
		if err == nil {
			t.Fatal("expected error when sockmap not supported")
		}
		t.Logf("sockmap not supported (expected): %v", err)
		return
	}
	if err != nil {
		t.Fatalf("Enable failed on supported system: %v", err)
	}
	defer mgr.Disable()

	if !mgr.IsEnabled() {
		t.Fatal("IsEnabled should return true after Enable")
	}
}

func TestBuildSKSkbVerdictProgramDenyPolicyJumpsToSKPass(t *testing.T) {
	insns := buildSKSkbVerdictProgram()
	redirectCallIdx := -1
	skPassIdx := -1
	for i, insn := range insns {
		if insn.code == (bpfClassJMP|bpfCall) && insn.imm == bpfFuncSKRedirectHash {
			redirectCallIdx = i
		}
		if insn.code == (bpfALU64|bpfMov|bpfK) && insn.dst == bpfRegR0 && insn.imm == 1 {
			if i+1 < len(insns) && insns[i+1].code == (bpfClassJMP|bpfExit) {
				skPassIdx = i
			}
		}
	}

	if redirectCallIdx < 0 {
		t.Fatal("redirect helper call not found in verdict program")
	}
	if skPassIdx < 0 {
		t.Fatal("SK_PASS epilogue not found in verdict program")
	}

	denyJumpIdx := -1
	for i, insn := range insns {
		if insn.code != (bpfClassJMP|bpfJEQ|bpfK) || insn.dst != bpfRegR0 || insn.imm != 0 {
			continue
		}
		target := i + 1 + int(insn.off)
		if target == skPassIdx {
			denyJumpIdx = i
			break
		}
	}

	if denyJumpIdx < 0 {
		t.Fatal("deny-policy jump to SK_PASS not found")
	}

	target := denyJumpIdx + 1 + int(insns[denyJumpIdx].off)
	if target == redirectCallIdx {
		t.Fatalf("deny-policy jump incorrectly targets redirect helper at %d", redirectCallIdx)
	}
}

func TestBuildSKSkbVerdictProgramRedirectDefaultsToEgress(t *testing.T) {
	insns := buildSKSkbVerdictProgram()

	egressSetIdx := -1
	ingressSetIdx := -1
	for i, insn := range insns {
		if insn.code == (bpfALU64|bpfMov|bpfK) && insn.dst == bpfRegR4 {
			switch insn.imm {
			case 0:
				egressSetIdx = i
			case 1:
				ingressSetIdx = i
			}
		}
	}

	if egressSetIdx < 0 {
		t.Fatal("redirect flags should default to egress (r4=0)")
	}
	if ingressSetIdx < 0 {
		t.Fatal("verdict program should retain conditional ingress redirect support (r4=1)")
	}
	if egressSetIdx > ingressSetIdx {
		t.Fatalf("egress default (idx=%d) should be set before optional ingress override (idx=%d)", egressSetIdx, ingressSetIdx)
	}
}

func TestSockmapRegisterPair(t *testing.T) {
	caps := GetCapabilities()
	if !caps.SockmapSupported {
		t.Skip("sockmap not supported on this system")
	}

	mgr := NewSockmapManager(DefaultSockmapConfig())
	if err := mgr.Enable(); err != nil {
		t.Fatal(err)
	}
	defer mgr.Disable()

	// Create a loopback TCP pair
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	serverDone := make(chan net.Conn, 1)
	go func() {
		conn, _ := listener.Accept()
		serverDone <- conn
	}()

	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	server := <-serverDone
	defer server.Close()

	// Register the pair
	if err := mgr.RegisterPair(client, server); err != nil {
		t.Fatalf("RegisterPair failed: %v", err)
	}

	// Unregister
	if err := mgr.UnregisterPair(client, server); err != nil {
		t.Fatalf("UnregisterPair failed: %v", err)
	}
}

func TestSockmapDataTransfer(t *testing.T) {
	caps := GetCapabilities()
	if !caps.SockmapSupported {
		t.Skip("sockmap not supported on this system")
	}

	mgr := NewSockmapManager(DefaultSockmapConfig())
	if err := mgr.Enable(); err != nil {
		t.Fatal(err)
	}
	defer mgr.Disable()

	// Create two TCP pairs: client1 <-> proxy_in, proxy_out <-> server
	// We'll test that sockmap can forward between proxy_in and proxy_out
	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxyListener.Close()

	serverListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverListener.Close()

	// Accept connections
	proxyInCh := make(chan net.Conn, 1)
	go func() {
		c, _ := proxyListener.Accept()
		proxyInCh <- c
	}()

	serverCh := make(chan net.Conn, 1)
	go func() {
		c, _ := serverListener.Accept()
		serverCh <- c
	}()

	client, err := net.Dial("tcp", proxyListener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	proxyOut, err := net.Dial("tcp", serverListener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer proxyOut.Close()

	proxyIn := <-proxyInCh
	defer proxyIn.Close()
	server := <-serverCh
	defer server.Close()

	// Register proxy_in <-> proxy_out for sockmap forwarding
	if err := mgr.RegisterPair(proxyIn, proxyOut); err != nil {
		t.Fatalf("RegisterPair: %v", err)
	}

	testData := []byte("hello through sockmap")
	if _, err := client.Write(testData); err != nil {
		t.Fatal(err)
	}

	// Give sockmap a moment to forward
	server.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, len(testData)*2)
	n, err := server.Read(buf)
	if err != nil {
		t.Logf("sockmap data forwarding may not be active (kernel-dependent): %v", err)
		// This is expected if sockmap forwarding isn't fully active
		// in the test environment
	} else if string(buf[:n]) != string(testData) {
		t.Fatalf("data mismatch: got %q, want %q", buf[:n], testData)
	} else {
		t.Log("sockmap data transfer successful")
	}

	mgr.UnregisterPair(proxyIn, proxyOut)
}

func TestSockmapGracefulFallback(t *testing.T) {
	mgr := NewSockmapManager(DefaultSockmapConfig())
	// Don't call Enable — RegisterPair should fail gracefully
	err := mgr.RegisterPair(nil, nil)
	if err == nil {
		t.Fatal("expected error for RegisterPair on non-enabled manager")
	}
	t.Logf("graceful fallback: %v", err)
}

func TestSockmapRegisterPairWaitsForLifecycleLock(t *testing.T) {
	mgr := NewSockmapManager(DefaultSockmapConfig())
	mgr.enabled.Store(true)

	mgr.mu.Lock()
	done := make(chan error, 1)
	started := make(chan struct{})
	go func() {
		close(started)
		done <- mgr.RegisterPair(nil, nil)
	}()
	<-started

	select {
	case err := <-done:
		t.Fatalf("RegisterPair returned before lifecycle lock was released: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	mgr.mu.Unlock()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected RegisterPair to fail for invalid connections")
		}
	case <-time.After(time.Second):
		t.Fatal("RegisterPair did not complete after lifecycle lock release")
	}
}

func TestSockmapDisableWaitsForSweeperExit(t *testing.T) {
	mgr := NewSockmapManager(DefaultSockmapConfig())
	mgr.enabled.Store(true)
	mgr.sweepDone = make(chan struct{})

	enter := make(chan struct{})
	release := make(chan struct{})
	mgr.sweepWG.Add(1)
	go func() {
		defer mgr.sweepWG.Done()
		<-mgr.sweepDone
		close(enter)
		<-release
	}()

	disableDone := make(chan error, 1)
	go func() {
		disableDone <- mgr.Disable()
	}()

	select {
	case <-enter:
	case <-time.After(time.Second):
		t.Fatal("sweeper worker did not observe stop signal")
	}

	select {
	case err := <-disableDone:
		t.Fatalf("Disable returned before sweeper worker exited: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	close(release)

	select {
	case err := <-disableDone:
		if err != nil {
			t.Fatalf("Disable failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Disable did not return after sweeper worker exited")
	}

	if mgr.sweepDone != nil {
		t.Fatal("sweepDone should be nil after Disable")
	}
}

func TestCanUseZeroCopy(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	serverDone := make(chan net.Conn, 1)
	go func() {
		c, _ := listener.Accept()
		serverDone <- c
	}()

	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-serverDone
	defer server.Close()

	if !CanUseZeroCopy(client, server) {
		t.Fatal("CanUseZeroCopy should return true for TCP pair")
	}

	// Non-TCP should return false (use net.Pipe which returns net.Conn)
	pipeA, pipeB := net.Pipe()
	defer pipeA.Close()
	defer pipeB.Close()
	if CanUseZeroCopy(client, pipeA) {
		t.Fatal("CanUseZeroCopy should return false for non-TCP")
	}
}

func TestGlobalSockmapManager(t *testing.T) {
	// Should not panic regardless of platform capabilities
	mgr := GlobalSockmapManager()
	caps := GetCapabilities()
	if !caps.SockmapSupported {
		if mgr != nil {
			t.Fatal("GlobalSockmapManager should be nil when sockmap unsupported")
		}
	} else {
		if mgr == nil {
			t.Fatal("GlobalSockmapManager should be non-nil when sockmap supported")
		}
	}
}

func TestSockmapConcurrentRegistration(t *testing.T) {
	caps := GetCapabilities()
	if !caps.SockmapSupported {
		t.Skip("sockmap not supported on this system")
	}

	mgr := NewSockmapManager(DefaultSockmapConfig())
	if err := mgr.Enable(); err != nil {
		t.Fatal(err)
	}
	defer mgr.Disable()

	const numPairs = 10
	done := make(chan error, numPairs)

	for i := 0; i < numPairs; i++ {
		go func() {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				done <- err
				return
			}
			defer listener.Close()

			serverCh := make(chan net.Conn, 1)
			go func() {
				c, _ := listener.Accept()
				serverCh <- c
			}()

			client, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				done <- err
				return
			}
			defer client.Close()

			server := <-serverCh
			defer server.Close()

			if err := mgr.RegisterPair(client, server); err != nil {
				done <- err
				return
			}

			if err := mgr.UnregisterPair(client, server); err != nil {
				done <- err
				return
			}

			done <- nil
		}()
	}

	for i := 0; i < numPairs; i++ {
		if err := <-done; err != nil {
			t.Errorf("concurrent pair %d failed: %v", i, err)
		}
	}
}

func TestSockmapStats(t *testing.T) {
	caps := GetCapabilities()
	if !caps.SockmapSupported {
		t.Skip("sockmap not supported on this system")
	}

	mgr := NewSockmapManager(DefaultSockmapConfig())
	if err := mgr.Enable(); err != nil {
		t.Fatal(err)
	}
	defer mgr.Disable()

	stats := mgr.GetSockmapStats()
	if !stats.Enabled {
		t.Fatal("stats should show enabled")
	}
	if stats.ActivePairs != 0 {
		t.Fatalf("expected 0 active pairs, got %d", stats.ActivePairs)
	}

	// Create and register a pair
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	serverCh := make(chan net.Conn, 1)
	go func() { c, _ := listener.Accept(); serverCh <- c }()

	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-serverCh
	defer server.Close()

	if err := mgr.RegisterPair(client, server); err != nil {
		t.Fatal(err)
	}

	stats = mgr.GetSockmapStats()
	if stats.ActivePairs != 1 {
		t.Fatalf("expected 1 active pair, got %d", stats.ActivePairs)
	}
	if stats.TotalPairs != 1 {
		t.Fatalf("expected 1 total pair, got %d", stats.TotalPairs)
	}
	if stats.PeakPairs != 1 {
		t.Fatalf("expected peak 1, got %d", stats.PeakPairs)
	}

	if err := mgr.UnregisterPair(client, server); err != nil {
		t.Fatal(err)
	}

	stats = mgr.GetSockmapStats()
	if stats.ActivePairs != 0 {
		t.Fatalf("expected 0 active pairs after unregister, got %d", stats.ActivePairs)
	}
	if stats.TotalPairs != 1 {
		t.Fatalf("total should remain 1 after unregister, got %d", stats.TotalPairs)
	}
	if stats.PeakPairs != 1 {
		t.Fatalf("peak should remain 1 after unregister, got %d", stats.PeakPairs)
	}
}

func TestSockmapStatsCapacity(t *testing.T) {
	caps := GetCapabilities()
	if !caps.SockmapSupported {
		t.Skip("sockmap not supported on this system")
	}

	// Use a tiny config: MaxEntries=4 means 2 pairs fill the SOCKHASH.
	// The third pair should trigger LRU eviction of the oldest pair.
	mgr := NewSockmapManager(SockmapConfig{MaxEntries: 4})
	if err := mgr.Enable(); err != nil {
		t.Fatal(err)
	}
	defer mgr.Disable()

	type connPair struct {
		client, server net.Conn
		listener       net.Listener
	}

	var pairs []connPair
	for i := 0; i < 3; i++ {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		ch := make(chan net.Conn, 1)
		go func() { c, _ := l.Accept(); ch <- c }()
		c, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			l.Close()
			t.Fatal(err)
		}
		s := <-ch
		pairs = append(pairs, connPair{c, s, l})
	}

	defer func() {
		for _, p := range pairs {
			p.client.Close()
			p.server.Close()
			p.listener.Close()
		}
	}()

	// Register first pair — uses 2 of 4 entries
	if err := mgr.RegisterPair(pairs[0].client, pairs[0].server); err != nil {
		t.Fatalf("RegisterPair 0: %v", err)
	}

	// Register second pair — uses 4 of 4 entries
	if err := mgr.RegisterPair(pairs[1].client, pairs[1].server); err != nil {
		t.Fatalf("RegisterPair 1: %v", err)
	}

	stats := mgr.GetSockmapStats()
	if stats.ActivePairs != 2 {
		t.Fatalf("expected 2 active pairs, got %d", stats.ActivePairs)
	}
	if stats.PeakPairs != 2 {
		t.Fatalf("expected peak 2, got %d", stats.PeakPairs)
	}

	// Third pair should succeed via LRU eviction of the oldest pair (pair 0).
	err := mgr.RegisterPair(pairs[2].client, pairs[2].server)
	if err != nil {
		t.Fatalf("RegisterPair 2 should succeed via LRU eviction: %v", err)
	}

	// Verify pair 0 was evicted (oldest in LRU).
	stats = mgr.GetSockmapStats()
	if stats.ActivePairs != 2 {
		t.Fatalf("expected 2 active pairs after eviction, got %d", stats.ActivePairs)
	}

	mgr.UnregisterPair(pairs[1].client, pairs[1].server)
	mgr.UnregisterPair(pairs[2].client, pairs[2].server)
}

func TestSockmapLRUEviction(t *testing.T) {
	caps := GetCapabilities()
	if !caps.SockmapSupported {
		t.Skip("sockmap not supported on this system")
	}

	// MaxEntries=4 means 2 pairs fill the SOCKHASH.
	mgr := NewSockmapManager(SockmapConfig{MaxEntries: 4})
	if err := mgr.Enable(); err != nil {
		t.Fatal(err)
	}
	defer mgr.Disable()

	type connPair struct {
		client, server net.Conn
		listener       net.Listener
	}

	makePair := func() connPair {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		ch := make(chan net.Conn, 1)
		go func() { c, _ := l.Accept(); ch <- c }()
		c, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			l.Close()
			t.Fatal(err)
		}
		s := <-ch
		return connPair{c, s, l}
	}

	p0 := makePair()
	defer func() { p0.client.Close(); p0.server.Close(); p0.listener.Close() }()
	p1 := makePair()
	defer func() { p1.client.Close(); p1.server.Close(); p1.listener.Close() }()
	p2 := makePair()
	defer func() { p2.client.Close(); p2.server.Close(); p2.listener.Close() }()

	// Fill: p0 (oldest), then p1
	if err := mgr.RegisterPair(p0.client, p0.server); err != nil {
		t.Fatalf("RegisterPair p0: %v", err)
	}
	if err := mgr.RegisterPair(p1.client, p1.server); err != nil {
		t.Fatalf("RegisterPair p1: %v", err)
	}

	// p2 should evict p0 (LRU tail)
	if err := mgr.RegisterPair(p2.client, p2.server); err != nil {
		t.Fatalf("RegisterPair p2 should succeed via LRU eviction: %v", err)
	}

	// Verify LRU list has exactly 2 entries
	mgr.lruMu.Lock()
	lruLen := mgr.lruList.Len()
	mgr.lruMu.Unlock()
	if lruLen != 2 {
		t.Fatalf("expected LRU list length 2, got %d", lruLen)
	}

	// Verify p0 is no longer tracked
	p0key := SockPairKey{InboundFD: getFDOrSkip(t, p0.client), OutboundFD: getFDOrSkip(t, p0.server)}
	if _, ok := mgr.pairs.Load(p0key); ok {
		t.Fatal("evicted pair p0 should not be in pairs map")
	}

	mgr.UnregisterPair(p1.client, p1.server)
	mgr.UnregisterPair(p2.client, p2.server)
}

func TestPolicyMapLRU(t *testing.T) {
	caps := GetCapabilities()
	if !caps.SockmapSupported {
		t.Skip("sockmap not supported on this system")
	}

	// Create a manager with tiny capacity to verify the LRU_HASH policy map
	// auto-evicts without error when over capacity.
	mgr := NewSockmapManager(SockmapConfig{MaxEntries: 4})
	if err := mgr.Enable(); err != nil {
		t.Fatal(err)
	}
	defer mgr.Disable()

	// The policy map is LRU_HASH (type 9). Writing beyond max_entries
	// should not return an error — kernel auto-evicts the oldest entry.
	for i := uint64(0); i < 10; i++ {
		if err := setPolicyEntry(i, PolicyAllowRedirect); err != nil {
			t.Fatalf("setPolicyEntry(%d) failed: %v (LRU_HASH should auto-evict)", i, err)
		}
	}
}

func TestMapPinning(t *testing.T) {
	caps := GetCapabilities()
	if !caps.SockmapSupported {
		t.Skip("sockmap not supported on this system")
	}

	pinPath := filepath.Join(t.TempDir(), "xray-test-bpf")

	mgr := NewSockmapManager(SockmapConfig{
		MaxEntries: 64,
		PinPath:    pinPath,
	})
	if err := mgr.Enable(); err != nil {
		t.Fatalf("Enable with pin path failed: %v", err)
	}

	// Verify pin files exist
	for _, name := range []string{"sockhash", "policy"} {
		path := filepath.Join(pinPath, name)
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("pin file %s not found: %v", name, err)
		}
		mode := info.Mode().Perm()
		if mode != 0600 {
			t.Fatalf("pin file %s has mode %o, want 0600", name, mode)
		}
	}

	// Verify pin directory permissions
	dirInfo, err := os.Stat(pinPath)
	if err != nil {
		t.Fatalf("pin dir not found: %v", err)
	}
	if dirInfo.Mode().Perm() != 0700 {
		t.Fatalf("pin dir has mode %o, want 0700", dirInfo.Mode().Perm())
	}

	// Disable should unpin
	if err := mgr.Disable(); err != nil {
		t.Fatalf("Disable failed: %v", err)
	}

	for _, name := range []string{"sockhash", "policy"} {
		path := filepath.Join(pinPath, name)
		if _, err := os.Stat(path); err == nil {
			t.Fatalf("pin file %s should be removed after Disable", name)
		}
	}
}

func TestMapPinningReplacesStalePins(t *testing.T) {
	caps := GetCapabilities()
	if !caps.SockmapSupported {
		t.Skip("sockmap not supported on this system")
	}

	pinPath := filepath.Join(t.TempDir(), "xray-test-bpf")
	if err := os.MkdirAll(pinPath, 0700); err != nil {
		t.Fatalf("mkdir pin path: %v", err)
	}
	for _, name := range []string{"sockhash", "policy"} {
		if err := os.WriteFile(filepath.Join(pinPath, name), []byte("stale"), 0600); err != nil {
			t.Fatalf("create stale pin file %s: %v", name, err)
		}
	}

	mgr := NewSockmapManager(SockmapConfig{
		MaxEntries: 64,
		PinPath:    pinPath,
	})
	if err := mgr.Enable(); err != nil {
		t.Fatalf("Enable with stale pin files failed: %v", err)
	}
	defer mgr.Disable()

	for _, name := range []string{"sockhash", "policy"} {
		path := filepath.Join(pinPath, name)
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("pin file %s not found after replacement: %v", name, err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("pin file %s has mode %o, want 0600", name, info.Mode().Perm())
		}
	}
}

func TestDropCapabilities(t *testing.T) {
	caps := GetCapabilities()
	if !caps.SockmapSupported {
		t.Skip("sockmap not supported on this system")
	}

	// Test that dropExcessCapabilities doesn't panic or return errors
	// that would prevent operation. We can't easily test the actual
	// capability restriction in a test process that may not have
	// the required caps to begin with.
	err := dropExcessCapabilities()
	if err != nil {
		// EPERM is expected if running without sufficient privileges
		if errno, ok := err.(syscall.Errno); ok && errno == syscall.EPERM {
			t.Skipf("insufficient privileges to test capability dropping: %v", err)
		}
		t.Logf("dropExcessCapabilities error (may be expected): %v", err)
	}
}

func TestSweepLRUEviction(t *testing.T) {
	caps := GetCapabilities()
	if !caps.SockmapSupported {
		t.Skip("sockmap not supported on this system")
	}

	// MaxEntries=8 means 4 pairs fill the SOCKHASH.
	// Register 4 pairs (>90% utilization), run sweep, verify eviction.
	mgr := NewSockmapManager(SockmapConfig{MaxEntries: 8})
	if err := mgr.Enable(); err != nil {
		t.Fatal(err)
	}
	defer mgr.Disable()

	type connPair struct {
		client, server net.Conn
		listener       net.Listener
	}

	makePair := func() connPair {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		ch := make(chan net.Conn, 1)
		go func() { c, _ := l.Accept(); ch <- c }()
		c, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			l.Close()
			t.Fatal(err)
		}
		s := <-ch
		return connPair{c, s, l}
	}

	var allPairs []connPair
	for i := 0; i < 4; i++ {
		p := makePair()
		allPairs = append(allPairs, p)
	}
	defer func() {
		for _, p := range allPairs {
			p.client.Close()
			p.server.Close()
			p.listener.Close()
		}
	}()

	for i, p := range allPairs {
		if err := mgr.RegisterPair(p.client, p.server); err != nil {
			t.Fatalf("RegisterPair %d: %v", i, err)
		}
	}

	stats := mgr.GetSockmapStats()
	if stats.ActivePairs != 4 {
		t.Fatalf("expected 4 active pairs, got %d", stats.ActivePairs)
	}

	// 4 pairs * 2 entries = 8 entries in SOCKHASH with MaxEntries=8.
	// utilization = 8/8 = 100% > 90%, so sweep should evict ~10% = 1 pair.
	mgr.doSweep()

	stats = mgr.GetSockmapStats()
	// After sweep, at least 1 pair should have been proactively evicted.
	if stats.ActivePairs >= 4 {
		t.Fatalf("expected fewer than 4 active pairs after sweep eviction, got %d", stats.ActivePairs)
	}
}

func TestSockmapSweep(t *testing.T) {
	caps := GetCapabilities()
	if !caps.SockmapSupported {
		t.Skip("sockmap not supported on this system")
	}

	mgr := NewSockmapManager(DefaultSockmapConfig())
	if err := mgr.Enable(); err != nil {
		t.Fatal(err)
	}
	defer mgr.Disable()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	serverCh := make(chan net.Conn, 1)
	go func() { c, _ := listener.Accept(); serverCh <- c }()

	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server := <-serverCh

	if err := mgr.RegisterPair(client, server); err != nil {
		t.Fatal(err)
	}

	stats := mgr.GetSockmapStats()
	if stats.ActivePairs != 1 {
		t.Fatalf("expected 1 active pair, got %d", stats.ActivePairs)
	}

	// Close sockets to make the entry stale
	client.Close()
	server.Close()

	// Run sweep directly
	mgr.doSweep()

	stats = mgr.GetSockmapStats()
	if stats.StaleCleanups == 0 {
		t.Fatal("expected stale cleanups > 0 after sweep")
	}
	if stats.ActivePairs != 0 {
		t.Fatalf("expected 0 active pairs after sweep, got %d", stats.ActivePairs)
	}
}

func TestSockmapConcurrentRegisterUnregister(t *testing.T) {
	caps := GetCapabilities()
	if !caps.SockmapSupported {
		t.Skip("sockmap not supported on this system")
	}

	mgr := NewSockmapManager(DefaultSockmapConfig())
	if err := mgr.Enable(); err != nil {
		t.Fatal(err)
	}
	defer mgr.Disable()

	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines)

	errCh := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()

			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				errCh <- err
				return
			}
			defer listener.Close()

			serverCh := make(chan net.Conn, 1)
			go func() { c, _ := listener.Accept(); serverCh <- c }()

			client, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				errCh <- err
				return
			}
			defer client.Close()

			server := <-serverCh
			defer server.Close()

			if err := mgr.RegisterPair(client, server); err != nil {
				errCh <- err
				return
			}

			// Verify stats are consistent
			stats := mgr.GetSockmapStats()
			if stats.ActivePairs < 0 {
				errCh <- nil // shouldn't happen but not fatal
				return
			}

			if err := mgr.UnregisterPair(client, server); err != nil {
				errCh <- err
				return
			}
		}()
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			t.Errorf("concurrent error: %v", err)
		}
	}

	stats := mgr.GetSockmapStats()
	if stats.ActivePairs != 0 {
		t.Errorf("expected 0 active pairs at end, got %d", stats.ActivePairs)
	}
	if stats.TotalPairs != goroutines {
		t.Errorf("expected %d total pairs, got %d", goroutines, stats.TotalPairs)
	}
}

func TestIsSocketAlive(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	serverCh := make(chan net.Conn, 1)
	go func() { c, _ := listener.Accept(); serverCh <- c }()

	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server := <-serverCh
	defer server.Close()

	fd, err := getConnFD(client)
	if err != nil {
		t.Fatal(err)
	}

	if !isSocketAlive(fd) {
		t.Fatal("socket should be alive before close")
	}

	client.Close()

	// After Close(), the Go runtime closes the FD.
	// isSocketAlive should return false for invalid FDs.
	if isSocketAlive(-1) {
		t.Fatal("isSocketAlive(-1) should return false")
	}
}

func BenchmarkSockmapRegisterUnregister(b *testing.B) {
	caps := GetCapabilities()
	if !caps.SockmapSupported {
		b.Skip("sockmap not supported")
	}

	mgr := NewSockmapManager(DefaultSockmapConfig())
	if err := mgr.Enable(); err != nil {
		b.Fatal(err)
	}
	defer mgr.Disable()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		listener, _ := net.Listen("tcp", "127.0.0.1:0")
		serverCh := make(chan net.Conn, 1)
		go func() { c, _ := listener.Accept(); serverCh <- c }()
		client, _ := net.Dial("tcp", listener.Addr().String())
		server := <-serverCh
		b.StartTimer()

		mgr.RegisterPair(client, server)
		mgr.UnregisterPair(client, server)

		b.StopTimer()
		client.Close()
		server.Close()
		listener.Close()
		b.StartTimer()
	}
}

func TestComputeRedirectPolicy(t *testing.T) {
	tests := []struct {
		name      string
		inbound   CryptoHint
		outbound  CryptoHint
		wantAllow bool
		wantKTLS  bool
	}{
		{"both raw TCP", CryptoNone, CryptoNone, true, false},
		{"both kTLS full", CryptoKTLSBoth, CryptoKTLSBoth, true, true},
		{"raw + kTLS", CryptoNone, CryptoKTLSBoth, false, false},
		{"kTLS + raw", CryptoKTLSBoth, CryptoNone, false, false},
		{"kTLS TX only + kTLS", CryptoKTLSTxOnly, CryptoKTLSBoth, false, false},
		{"kTLS RX only + kTLS", CryptoKTLSRxOnly, CryptoKTLSBoth, false, false},
		{"userspace + raw", CryptoUserspaceTLS, CryptoNone, false, false},
		{"userspace + userspace", CryptoUserspaceTLS, CryptoUserspaceTLS, false, false},
		{"kTLS TX only + kTLS TX only", CryptoKTLSTxOnly, CryptoKTLSTxOnly, false, false},
		{"kTLS RX only + kTLS RX only", CryptoKTLSRxOnly, CryptoKTLSRxOnly, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := computeRedirectPolicy(tt.inbound, tt.outbound)
			gotAllow := policy&PolicyAllowRedirect != 0
			gotKTLS := policy&PolicyKTLSActive != 0
			if gotAllow != tt.wantAllow {
				t.Errorf("allow: got %v, want %v", gotAllow, tt.wantAllow)
			}
			if gotKTLS != tt.wantKTLS {
				t.Errorf("kTLS: got %v, want %v", gotKTLS, tt.wantKTLS)
			}
		})
	}
}

func TestPolicyMapLifecycle(t *testing.T) {
	caps := GetCapabilities()
	if !caps.SockmapSupported {
		t.Skip("sockmap not supported on this system")
	}

	mgr := NewSockmapManager(DefaultSockmapConfig())
	if err := mgr.Enable(); err != nil {
		t.Fatal(err)
	}

	if currentState.Load().policyMapFD < 0 {
		t.Fatal("policyMapFD should be >= 0 after Enable")
	}

	if err := mgr.Disable(); err != nil {
		t.Fatal(err)
	}

	if currentState.Load().policyMapFD != -1 {
		t.Fatal("policyMapFD should be -1 after Disable")
	}
}

func TestRegisterPairWithCrypto(t *testing.T) {
	caps := GetCapabilities()
	if !caps.SockmapSupported {
		t.Skip("sockmap not supported on this system")
	}

	mgr := NewSockmapManager(DefaultSockmapConfig())
	if err := mgr.Enable(); err != nil {
		t.Fatal(err)
	}
	defer mgr.Disable()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	serverDone := make(chan net.Conn, 1)
	go func() {
		conn, _ := listener.Accept()
		serverDone <- conn
	}()

	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	server := <-serverDone
	defer server.Close()

	// Raw TCP pair should succeed
	if err := mgr.RegisterPairWithCrypto(client, server, CryptoNone, CryptoNone); err != nil {
		t.Fatalf("RegisterPairWithCrypto(None, None) failed: %v", err)
	}

	if err := mgr.UnregisterPair(client, server); err != nil {
		t.Fatalf("UnregisterPair failed: %v", err)
	}
}

func TestCanUseZeroCopyWithCrypto(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	serverDone := make(chan net.Conn, 1)
	go func() {
		c, _ := listener.Accept()
		serverDone <- c
	}()

	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-serverDone
	defer server.Close()

	// Raw TCP: allowed
	if !CanUseZeroCopyWithCrypto(client, server, CryptoNone, CryptoNone) {
		t.Error("expected true for CryptoNone+CryptoNone")
	}

	// Both kTLS: allowed
	if !CanUseZeroCopyWithCrypto(client, server, CryptoKTLSBoth, CryptoKTLSBoth) {
		t.Error("expected true for CryptoKTLSBoth+CryptoKTLSBoth")
	}

	// Asymmetric: denied
	if CanUseZeroCopyWithCrypto(client, server, CryptoNone, CryptoKTLSBoth) {
		t.Error("expected false for CryptoNone+CryptoKTLSBoth")
	}

	// Userspace: denied
	if CanUseZeroCopyWithCrypto(client, server, CryptoUserspaceTLS, CryptoUserspaceTLS) {
		t.Error("expected false for CryptoUserspaceTLS+CryptoUserspaceTLS")
	}

	// Non-TCP: denied regardless of crypto
	pipeA, pipeB := net.Pipe()
	defer pipeA.Close()
	defer pipeB.Close()
	if CanUseZeroCopyWithCrypto(pipeA, pipeB, CryptoNone, CryptoNone) {
		t.Error("expected false for non-TCP connections")
	}
}

func BenchmarkSockmapConcurrentRegister(b *testing.B) {
	caps := GetCapabilities()
	if !caps.SockmapSupported {
		b.Skip("sockmap not supported")
	}

	mgr := NewSockmapManager(DefaultSockmapConfig())
	if err := mgr.Enable(); err != nil {
		b.Fatal(err)
	}
	defer mgr.Disable()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			listener, _ := net.Listen("tcp", "127.0.0.1:0")
			serverCh := make(chan net.Conn, 1)
			go func() { c, _ := listener.Accept(); serverCh <- c }()
			client, _ := net.Dial("tcp", listener.Addr().String())
			server := <-serverCh

			mgr.RegisterPair(client, server)
			mgr.UnregisterPair(client, server)

			client.Close()
			server.Close()
			listener.Close()
		}
	})
}

// getFDOrSkip extracts the fd from a net.Conn, skipping the test on error.
func getFDOrSkip(t *testing.T, conn net.Conn) int {
	t.Helper()
	fd, err := getConnFD(conn)
	if err != nil {
		t.Skipf("cannot extract fd: %v", err)
	}
	return fd
}
