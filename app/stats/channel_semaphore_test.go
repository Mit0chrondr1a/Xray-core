package stats_test

import (
	"context"
	"testing"
	"time"

	. "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common"
)

// TestChannelPublishSemaphoreLimit verifies that the non-blocking publish
// path limits the number of goroutines spawned via the publishSemaphore.
// The semaphore is hardcoded to cap(64) in NewChannel.
func TestChannelPublishSemaphoreLimit(t *testing.T) {
	// Non-blocking channel with zero buffer to force goroutine spawning
	c := NewChannel(&ChannelConfig{BufferSize: 0, Blocking: false})
	common.Must(c.Start())
	defer c.Close()

	sub, err := c.Subscribe()
	common.Must(err)
	defer c.Unsubscribe(sub)

	// Publish many messages without reading. The semaphore (cap 64) should
	// prevent unbounded goroutine growth and silently drop messages.
	for i := 0; i < 200; i++ {
		c.Publish(context.Background(), i)
	}

	// Give goroutines time to attempt delivery
	time.Sleep(50 * time.Millisecond)

	// Drain whatever made it through
	drained := 0
	for {
		select {
		case <-sub:
			drained++
		default:
			goto done
		}
	}
done:
	// The exact number is non-deterministic, but it must be less than 200
	// because we had zero buffer + semaphore limit of 64 + slow consumer.
	if drained >= 200 {
		t.Fatalf("semaphore limit ineffective: drained all %d messages (expected <200)", drained)
	}
	if drained == 0 {
		t.Fatal("no messages delivered — channel publish may be broken")
	}
}

func TestChannelSubscriberLimit(t *testing.T) {
	c := NewChannel(&ChannelConfig{SubscriberLimit: 3, Blocking: true})
	common.Must(c.Start())
	defer c.Close()

	subs := make([]chan interface{}, 0, 3)
	for i := 0; i < 3; i++ {
		s, err := c.Subscribe()
		if err != nil {
			t.Fatalf("Subscribe %d: %v", i+1, err)
		}
		subs = append(subs, s)
	}

	// Fourth should fail
	_, err := c.Subscribe()
	if err == nil {
		t.Fatal("expected error when subscriber limit reached")
	}

	// Unsubscribe one, then subscribe again should work
	common.Must(c.Unsubscribe(subs[0]))
	s, err := c.Subscribe()
	if err != nil {
		t.Fatalf("Subscribe after unsubscribe: %v", err)
	}
	defer c.Unsubscribe(s)
}

func TestChannelRunningState(t *testing.T) {
	c := NewChannel(&ChannelConfig{Blocking: true})

	if c.Running() {
		t.Fatal("channel should not be running before Start")
	}

	common.Must(c.Start())
	if !c.Running() {
		t.Fatal("channel should be running after Start")
	}

	c.Close()
	// Give the goroutine time to exit
	time.Sleep(50 * time.Millisecond)
	if c.Running() {
		t.Fatal("channel should not be running after Close")
	}
}

func TestChannelDoubleStart(t *testing.T) {
	c := NewChannel(&ChannelConfig{Blocking: true})

	common.Must(c.Start())
	// Double start should be a no-op
	common.Must(c.Start())

	if !c.Running() {
		t.Fatal("channel should still be running after double start")
	}

	c.Close()
}

func TestChannelDoubleClose(t *testing.T) {
	c := NewChannel(&ChannelConfig{Blocking: true})
	common.Must(c.Start())

	if err := c.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestChannelSubscribersSnapshot(t *testing.T) {
	c := NewChannel(&ChannelConfig{Blocking: true})
	common.Must(c.Start())
	defer c.Close()

	s1, _ := c.Subscribe()
	s2, _ := c.Subscribe()
	defer c.Unsubscribe(s1)
	defer c.Unsubscribe(s2)

	subs := c.Subscribers()
	if len(subs) != 2 {
		t.Fatalf("Subscribers() returned %d, want 2", len(subs))
	}
}

func TestChannelUnsubscribeNonexistent(t *testing.T) {
	c := NewChannel(&ChannelConfig{Blocking: true})
	common.Must(c.Start())
	defer c.Close()

	phantom := make(chan interface{})
	// Unsubscribing a channel that was never subscribed should not error
	if err := c.Unsubscribe(phantom); err != nil {
		t.Fatalf("Unsubscribe non-existent: %v", err)
	}
}

func TestChannelPublishAfterClose(t *testing.T) {
	c := NewChannel(&ChannelConfig{Blocking: true})
	common.Must(c.Start())
	c.Close()

	// Publishing after close should be a no-op (not panic)
	time.Sleep(10 * time.Millisecond)
	c.Publish(context.Background(), "should be ignored")
}

func TestChannelPublishWithCancelledContext(t *testing.T) {
	c := NewChannel(&ChannelConfig{BufferSize: 0, Blocking: true})
	common.Must(c.Start())
	defer c.Close()

	_, err := c.Subscribe()
	common.Must(err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Already cancelled

	// Should not block because context is cancelled
	done := make(chan struct{})
	go func() {
		c.Publish(ctx, "msg")
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(1 * time.Second):
		t.Fatal("Publish with cancelled context should not block")
	}
}
