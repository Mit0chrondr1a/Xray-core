package tcp

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/transport/internet/stat"
)

func TestVuln_CWE_911_PanicAfterHandshakeRelease(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var calls atomic.Int32
	v := &Listener{
		listener:      ln,
		connSemaphore: make(chan struct{}, 1),
		addConn: func(stat.Connection) {
			calls.Add(1)
			panic("panic in addConn")
		},
	}
	go v.keepAccepting()

	client1, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client1.Close()

	client2, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client2.Close()

	deadline := time.After(2 * time.Second)
	for calls.Load() < 2 {
		select {
		case <-deadline:
			t.Fatalf("expected panic path to release handshake slot; calls=%d", calls.Load())
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
}

func TestVuln_CWE_362_HandshakeSemaphoreExhaustion(t *testing.T) {
	sem := make(chan struct{}, maxConcurrentHandshakes)
	for i := 0; i < maxConcurrentHandshakes; i++ {
		sem <- struct{}{}
	}

	select {
	case sem <- struct{}{}:
		t.Fatal("semaphore accepted beyond maxConcurrentHandshakes")
	default:
	}

	<-sem
	select {
	case sem <- struct{}{}:
	default:
		t.Fatal("failed to reacquire after a release")
	}
}

func TestVuln_CWE_400_DeferOrderOnPanic(t *testing.T) {
	sem := make(chan struct{}, 1)
	sem <- struct{}{}

	var order []string
	var mu sync.Mutex

	var released atomic.Bool
	releaseHandshake := func() {
		if released.CompareAndSwap(false, true) {
			mu.Lock()
			order = append(order, "release")
			mu.Unlock()
			<-sem
		}
	}

	func() {
		defer releaseHandshake() // Registered first, should run second.
		defer func() {
			if r := recover(); r != nil {
				mu.Lock()
				order = append(order, "recover")
				mu.Unlock()
			}
		}()

		panic("simulated panic in handshake")
	}()

	mu.Lock()
	defer mu.Unlock()

	if len(order) != 2 || order[0] != "recover" || order[1] != "release" {
		t.Fatalf("unexpected defer order: %v (expected [recover release])", order)
	}

	select {
	case sem <- struct{}{}:
	default:
		t.Fatal("semaphore was not released after panic")
	}
}
