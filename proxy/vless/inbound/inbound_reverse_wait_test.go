package inbound

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/transport"
)

type stubOutboundHandler struct {
	tag string
}

func (h *stubOutboundHandler) Start() error                              { return nil }
func (h *stubOutboundHandler) Close() error                              { return nil }
func (h *stubOutboundHandler) Tag() string                               { return h.tag }
func (h *stubOutboundHandler) Dispatch(context.Context, *transport.Link) {}
func (h *stubOutboundHandler) SenderSettings() *serial.TypedMessage      { return nil }
func (h *stubOutboundHandler) ProxySettings() *serial.TypedMessage       { return nil }

type stubOutboundManager struct {
	mu       sync.Mutex
	handlers map[string]outbound.Handler
	list     []outbound.Handler
}

func (m *stubOutboundManager) Type() interface{} { return outbound.ManagerType() }
func (m *stubOutboundManager) Start() error      { return nil }
func (m *stubOutboundManager) Close() error      { return nil }

func (m *stubOutboundManager) GetHandler(tag string) outbound.Handler {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.handlers[tag]
}

func (m *stubOutboundManager) GetDefaultHandler() outbound.Handler {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.list) == 0 {
		return nil
	}
	return m.list[0]
}

func (m *stubOutboundManager) AddHandler(_ context.Context, handler outbound.Handler) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.handlers == nil {
		m.handlers = make(map[string]outbound.Handler)
	}
	m.handlers[handler.Tag()] = handler
	m.list = append(m.list, handler)
	return nil
}

func (m *stubOutboundManager) RemoveHandler(_ context.Context, tag string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.handlers, tag)
	next := m.list[:0]
	for _, handler := range m.list {
		if handler.Tag() != tag {
			next = append(next, handler)
		}
	}
	m.list = next
	return nil
}

func (m *stubOutboundManager) ListHandlers(context.Context) []outbound.Handler {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]outbound.Handler, len(m.list))
	copy(out, m.list)
	return out
}

func newReverseTestHandler(t *testing.T, mgr outbound.Manager) (*Handler, *vless.MemoryAccount) {
	t.Helper()
	id := protocol.NewID(uuid.New())
	account := &vless.MemoryAccount{
		ID:      id,
		Reverse: &vless.Reverse{Tag: "reverse-tag"},
	}
	validator := new(vless.MemoryValidator)
	user := &protocol.MemoryUser{
		Email:   "reverse@example.com",
		Account: account,
	}
	if err := validator.Add(user); err != nil {
		t.Fatalf("validator.Add() failed: %v", err)
	}
	return &Handler{
		validator:              validator,
		outboundHandlerManager: mgr,
		ctx:                    context.Background(),
	}, account
}

func TestGetReverseTimesOutQuicklyWhenNoOutboundHandlers(t *testing.T) {
	origTimeout := reverseOutboundWaitTimeout
	origPoll := reverseOutboundPollInterval
	reverseOutboundWaitTimeout = 40 * time.Millisecond
	reverseOutboundPollInterval = 5 * time.Millisecond
	defer func() {
		reverseOutboundWaitTimeout = origTimeout
		reverseOutboundPollInterval = origPoll
	}()

	handler, account := newReverseTestHandler(t, &stubOutboundManager{})

	start := time.Now()
	_, err := handler.GetReverse(account)
	if err == nil {
		t.Fatal("GetReverse succeeded, want timeout")
	}
	if !strings.Contains(err.Error(), "timed out waiting for outbound handlers") {
		t.Fatalf("GetReverse error = %v", err)
	}
	if elapsed := time.Since(start); elapsed > 250*time.Millisecond {
		t.Fatalf("GetReverse timeout took too long: %v", elapsed)
	}
}

func TestGetReverseRespondsSoonAfterOutboundAppears(t *testing.T) {
	origTimeout := reverseOutboundWaitTimeout
	origPoll := reverseOutboundPollInterval
	reverseOutboundWaitTimeout = 200 * time.Millisecond
	reverseOutboundPollInterval = 5 * time.Millisecond
	defer func() {
		reverseOutboundWaitTimeout = origTimeout
		reverseOutboundPollInterval = origPoll
	}()

	manager := &stubOutboundManager{}
	handler, account := newReverseTestHandler(t, manager)

	go func() {
		time.Sleep(20 * time.Millisecond)
		_ = manager.AddHandler(context.Background(), &stubOutboundHandler{tag: "uplink"})
	}()

	start := time.Now()
	reverseHandler, err := handler.GetReverse(account)
	if err != nil {
		t.Fatalf("GetReverse() failed: %v", err)
	}
	if reverseHandler == nil {
		t.Fatal("GetReverse() returned nil reverse handler")
	}
	if elapsed := time.Since(start); elapsed >= reverseOutboundWaitTimeout {
		t.Fatalf("GetReverse waited until timeout budget: %v", elapsed)
	}
}
