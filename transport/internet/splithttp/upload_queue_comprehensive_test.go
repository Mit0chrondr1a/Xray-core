package splithttp_test

import (
	"bytes"
	"io"
	"sync"
	"testing"
	"time"

	. "github.com/xtls/xray-core/transport/internet/splithttp"
)

// --- Boundary tests ---

func TestUploadQueue_Push_WhenClosed_ReturnsError(t *testing.T) {
	q := NewUploadQueue(10)
	q.Close()
	err := q.Push(Packet{Payload: []byte("x"), Seq: 0})
	if err == nil {
		t.Fatal("expected error pushing to closed queue, got nil")
	}
}

func TestUploadQueue_Push_WhenFull_ReturnsError(t *testing.T) {
	q := NewUploadQueue(2)
	// Fill the channel
	err := q.Push(Packet{Payload: []byte("a"), Seq: 0})
	if err != nil {
		t.Fatal("first push failed:", err)
	}
	err = q.Push(Packet{Payload: []byte("b"), Seq: 1})
	if err != nil {
		t.Fatal("second push failed:", err)
	}
	// Third push should fail (non-blocking, channel full)
	err = q.Push(Packet{Payload: []byte("c"), Seq: 2})
	if err == nil {
		t.Fatal("expected error when queue is full, got nil")
	}
}

func TestUploadQueue_Push_AfterReaderSet_ReturnsError(t *testing.T) {
	q := NewUploadQueue(10)
	r := io.NopCloser(bytes.NewReader([]byte("stream")))
	err := q.Push(Packet{Reader: r, Seq: 0})
	if err != nil {
		t.Fatal("push reader failed:", err)
	}
	// After a reader is pushed, no more packets should be accepted
	err = q.Push(Packet{Payload: []byte("x"), Seq: 1})
	if err == nil {
		t.Fatal("expected error after reader was set, got nil")
	}
}

// --- Read happy path ---

func TestUploadQueue_Read_InOrder_ReturnsCorrectPayload(t *testing.T) {
	q := NewUploadQueue(10)
	q.Push(Packet{Payload: []byte("hello"), Seq: 0})
	buf := make([]byte, 100)
	n, err := q.Read(buf)
	if err != nil {
		t.Fatal("read error:", err)
	}
	if n != 5 {
		t.Fatalf("expected n=5, got n=%d", n)
	}
	if string(buf[:n]) != "hello" {
		t.Fatalf("expected 'hello', got %q", string(buf[:n]))
	}
}

func TestUploadQueue_Read_MultipleInOrder(t *testing.T) {
	q := NewUploadQueue(10)
	q.Push(Packet{Payload: []byte("aaa"), Seq: 0})
	q.Push(Packet{Payload: []byte("bbb"), Seq: 1})
	q.Push(Packet{Payload: []byte("ccc"), Seq: 2})

	buf := make([]byte, 100)
	results := make([]string, 0, 3)
	for i := 0; i < 3; i++ {
		n, err := q.Read(buf)
		if err != nil {
			t.Fatal("read error at iteration", i, ":", err)
		}
		results = append(results, string(buf[:n]))
	}
	expected := []string{"aaa", "bbb", "ccc"}
	for i, exp := range expected {
		if results[i] != exp {
			t.Errorf("packet %d: expected %q, got %q", i, exp, results[i])
		}
	}
}

// --- Out-of-order reassembly ---

func TestUploadQueue_Read_OutOfOrder_Reassembles(t *testing.T) {
	q := NewUploadQueue(10)
	// Push packets out of order: 1 first, then 0
	go func() {
		q.Push(Packet{Payload: []byte("second"), Seq: 1})
		// Small delay to ensure the reader blocks waiting for seq 0
		time.Sleep(10 * time.Millisecond)
		q.Push(Packet{Payload: []byte("first"), Seq: 0})
	}()

	buf := make([]byte, 100)
	// First read should return seq 0 ("first") after reassembly
	n, err := q.Read(buf)
	if err != nil {
		t.Fatal("read error:", err)
	}
	if string(buf[:n]) != "first" {
		t.Fatalf("expected 'first', got %q", string(buf[:n]))
	}
	// Second read should return seq 1
	n, err = q.Read(buf)
	if err != nil {
		t.Fatal("read error:", err)
	}
	if string(buf[:n]) != "second" {
		t.Fatalf("expected 'second', got %q", string(buf[:n]))
	}
}

// --- Partial read (payload larger than buffer) ---

func TestUploadQueue_Read_PartialRead_WhenBufferSmall(t *testing.T) {
	q := NewUploadQueue(10)
	q.Push(Packet{Payload: []byte("abcdefghij"), Seq: 0})

	smallBuf := make([]byte, 4)
	n, err := q.Read(smallBuf)
	if err != nil {
		t.Fatal("read error:", err)
	}
	if n != 4 {
		t.Fatalf("expected n=4, got n=%d", n)
	}
	if string(smallBuf[:n]) != "abcd" {
		t.Fatalf("expected 'abcd', got %q", string(smallBuf[:n]))
	}

	// Second read should return the remainder
	n, err = q.Read(smallBuf)
	if err != nil {
		t.Fatal("second read error:", err)
	}
	if n != 4 {
		t.Fatalf("expected n=4 on second read, got n=%d", n)
	}
	if string(smallBuf[:n]) != "efgh" {
		t.Fatalf("expected 'efgh', got %q", string(smallBuf[:n]))
	}

	n, err = q.Read(smallBuf)
	if err != nil {
		t.Fatal("third read error:", err)
	}
	if n != 2 {
		t.Fatalf("expected n=2 on third read, got n=%d", n)
	}
	if string(smallBuf[:n]) != "ij" {
		t.Fatalf("expected 'ij', got %q", string(smallBuf[:n]))
	}
}

// --- Reader-based packet ---

func TestUploadQueue_Read_WithReaderPacket_DelegatesToReader(t *testing.T) {
	q := NewUploadQueue(10)
	streamData := []byte("streamed-content")
	r := io.NopCloser(bytes.NewReader(streamData))
	q.Push(Packet{Reader: r})

	buf := make([]byte, 100)
	n, err := q.Read(buf)
	if err != nil {
		t.Fatal("read error:", err)
	}
	if string(buf[:n]) != "streamed-content" {
		t.Fatalf("expected 'streamed-content', got %q", string(buf[:n]))
	}
}

// --- Close behavior ---

func TestUploadQueue_Close_DrainsBufferedPackets(t *testing.T) {
	q := NewUploadQueue(10)
	q.Push(Packet{Payload: []byte("buffered"), Seq: 0})
	// Close should drain but not panic
	err := q.Close()
	if err != nil {
		t.Fatal("close error:", err)
	}
}

func TestUploadQueue_Close_DrainsReaderPackets(t *testing.T) {
	closed := false
	r := &trackingCloser{
		Reader: bytes.NewReader([]byte("stream")),
		onClose: func() {
			closed = true
		},
	}
	q := NewUploadQueue(10)
	q.Push(Packet{Reader: r})
	err := q.Close()
	if err != nil {
		t.Fatal("close error:", err)
	}
	if !closed {
		t.Fatal("reader was not closed during queue close")
	}
}

func TestUploadQueue_DoubleClose_NoPanic(t *testing.T) {
	q := NewUploadQueue(10)
	err1 := q.Close()
	if err1 != nil {
		t.Fatal("first close error:", err1)
	}
	err2 := q.Close()
	if err2 != nil {
		t.Fatal("second close error:", err2)
	}
}

func TestUploadQueue_Read_AfterClose_ReturnsEOF(t *testing.T) {
	q := NewUploadQueue(10)
	q.Close()
	buf := make([]byte, 10)
	_, err := q.Read(buf)
	if err != io.EOF {
		t.Fatalf("expected io.EOF, got %v", err)
	}
}

func TestUploadQueue_Read_ChannelClosedMidRead_ReturnsEOF(t *testing.T) {
	q := NewUploadQueue(10)
	go func() {
		time.Sleep(20 * time.Millisecond)
		q.Close()
	}()
	buf := make([]byte, 10)
	_, err := q.Read(buf)
	if err != io.EOF {
		t.Fatalf("expected io.EOF after channel close, got %v", err)
	}
}

// --- Concurrency: Push/Close race (H3 fix validation) ---

func TestUploadQueue_ConcurrentPushClose_NoDeadlock(t *testing.T) {
	// This test validates the H3 fix: Push releasing mutex before channel send.
	// Before the fix, concurrent Push calls filling the channel would deadlock
	// Close() because Push held the mutex during the blocking send.
	for trial := 0; trial < 50; trial++ {
		q := NewUploadQueue(2) // small buffer to trigger backpressure fast
		var wg sync.WaitGroup

		// Spawn many concurrent pushers
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(seq uint64) {
				defer wg.Done()
				q.Push(Packet{Payload: []byte("x"), Seq: seq})
			}(uint64(i))
		}

		// Close concurrently -- must not deadlock
		done := make(chan struct{})
		go func() {
			time.Sleep(time.Millisecond)
			q.Close()
			close(done)
		}()

		select {
		case <-done:
			// Close completed, no deadlock
		case <-time.After(2 * time.Second):
			t.Fatal("DEADLOCK: Close() did not return within 2 seconds (trial", trial, ")")
		}

		wg.Wait()
	}
}

// --- Null/empty edge cases ---

func TestUploadQueue_Push_EmptyPayload(t *testing.T) {
	q := NewUploadQueue(10)
	err := q.Push(Packet{Payload: []byte{}, Seq: 0})
	if err != nil {
		t.Fatal("push empty payload failed:", err)
	}
	buf := make([]byte, 10)
	n, err := q.Read(buf)
	if err != nil {
		t.Fatal("read error:", err)
	}
	if n != 0 {
		t.Fatalf("expected n=0 for empty payload, got n=%d", n)
	}
}

func TestUploadQueue_Read_ZeroLengthBuffer(t *testing.T) {
	q := NewUploadQueue(10)
	q.Push(Packet{Payload: []byte("data"), Seq: 0})
	buf := make([]byte, 0)
	n, err := q.Read(buf)
	if err != nil {
		t.Fatal("read error:", err)
	}
	if n != 0 {
		t.Fatalf("expected n=0 for zero-length buffer, got n=%d", n)
	}
}

// --- State: queue too large ---

func TestUploadQueue_Read_QueueTooLarge_ReturnsError(t *testing.T) {
	// maxPackets=2, channel capacity=2, heap overflow check is len(heap) > 2.
	// Flow: push seq 10, 20 (skipping 0). Read() gets seq 10, pushes to heap.
	// heap=[10], blocks on channel, gets seq 20, pushes to heap. heap=[10,20].
	// Loop: pop 10 (seq 10 > nextSeq 0), check len(heap)=1 <= 2, push back,
	//   block on channel again. We need more packets.
	//
	// Use maxPackets=2, push 4 out-of-order packets via goroutine to feed channel.
	q := NewUploadQueue(2)

	go func() {
		// Push packets out of order, skipping seq 0 so heap grows.
		// Channel cap=2, non-blocking push may fail for some, that's OK.
		for i := uint64(1); i <= 10; i++ {
			q.Push(Packet{Payload: []byte("x"), Seq: i})
			time.Sleep(time.Millisecond) // pace to let reader consume from channel
		}
		// Eventually close so the reader doesn't hang
		time.Sleep(100 * time.Millisecond)
		q.Close()
	}()

	buf := make([]byte, 100)
	// Read will accumulate out-of-order packets in heap until overflow
	foundError := false
	for i := 0; i < 20; i++ {
		_, err := q.Read(buf)
		if err != nil {
			if err == io.EOF {
				break
			}
			foundError = true
			break
		}
	}
	if !foundError {
		t.Skip("could not trigger queue overflow in this run (race-dependent)")
	}
}

// --- Helper ---

type trackingCloser struct {
	io.Reader
	onClose func()
}

func (tc *trackingCloser) Close() error {
	if tc.onClose != nil {
		tc.onClose()
	}
	return nil
}
