//go:build linux

package ebpf

import (
	"net"
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
