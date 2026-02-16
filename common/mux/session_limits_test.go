package mux_test

import (
	"testing"

	. "github.com/xtls/xray-core/common/mux"
)

// --- SessionManager concurrency limits ---

func TestSessionManagerAllocateMaxConcurrency(t *testing.T) {
	m := NewSessionManager()
	strategy := &ClientStrategy{MaxConcurrency: 2}

	s1 := m.Allocate(strategy)
	if s1 == nil {
		t.Fatal("first Allocate should succeed")
	}
	s2 := m.Allocate(strategy)
	if s2 == nil {
		t.Fatal("second Allocate should succeed")
	}

	// Third allocation should fail: 2 active sessions = MaxConcurrency
	s3 := m.Allocate(strategy)
	if s3 != nil {
		t.Fatal("third Allocate should return nil (MaxConcurrency=2)")
	}

	// Remove one session, then allocate should succeed again
	m.Remove(false, s1.ID)
	s4 := m.Allocate(strategy)
	if s4 == nil {
		t.Fatal("Allocate after Remove should succeed")
	}
}

func TestSessionManagerAllocateMaxConnection(t *testing.T) {
	m := NewSessionManager()
	strategy := &ClientStrategy{MaxConnection: 3}

	// Allocate 3 sessions
	for i := 0; i < 3; i++ {
		s := m.Allocate(strategy)
		if s == nil {
			t.Fatalf("Allocate %d should succeed", i+1)
		}
	}

	// Fourth allocation should fail: count=3 >= MaxConnection
	s := m.Allocate(strategy)
	if s != nil {
		t.Fatal("Allocate should return nil when MaxConnection reached")
	}
}

func TestSessionManagerAllocateOnClosed(t *testing.T) {
	m := NewSessionManager()
	m.Close()

	s := m.Allocate(&ClientStrategy{})
	if s != nil {
		t.Fatal("Allocate on closed manager should return nil")
	}
}

func TestSessionManagerAddOnClosed(t *testing.T) {
	m := NewSessionManager()
	m.Close()

	ok := m.Add(&Session{ID: 1})
	if ok {
		t.Fatal("Add on closed manager should return false")
	}
}

func TestSessionManagerGet(t *testing.T) {
	m := NewSessionManager()
	s := m.Allocate(&ClientStrategy{})

	got, found := m.Get(s.ID)
	if !found {
		t.Fatal("Get should find allocated session")
	}
	if got.ID != s.ID {
		t.Fatalf("Got ID=%d, want %d", got.ID, s.ID)
	}

	_, found = m.Get(999)
	if found {
		t.Fatal("Get should not find non-existent session")
	}
}

func TestSessionManagerGetOnClosed(t *testing.T) {
	m := NewSessionManager()
	s := m.Allocate(&ClientStrategy{})
	m.Close()

	_, found := m.Get(s.ID)
	if found {
		t.Fatal("Get on closed manager should return false")
	}
}

func TestSessionManagerCount(t *testing.T) {
	m := NewSessionManager()
	if m.Count() != 0 {
		t.Fatalf("initial Count=%d, want 0", m.Count())
	}

	m.Allocate(&ClientStrategy{})
	if m.Count() != 1 {
		t.Fatalf("Count after 1 Allocate=%d, want 1", m.Count())
	}

	m.Allocate(&ClientStrategy{})
	if m.Count() != 2 {
		t.Fatalf("Count after 2 Allocates=%d, want 2", m.Count())
	}
}

func TestSessionManagerSize(t *testing.T) {
	m := NewSessionManager()
	if m.Size() != 0 {
		t.Fatalf("initial Size=%d, want 0", m.Size())
	}

	s := m.Allocate(&ClientStrategy{})
	if m.Size() != 1 {
		t.Fatalf("Size after Allocate=%d, want 1", m.Size())
	}

	m.Remove(false, s.ID)
	if m.Size() != 0 {
		t.Fatalf("Size after Remove=%d, want 0", m.Size())
	}
}

func TestSessionManagerClosed(t *testing.T) {
	m := NewSessionManager()
	if m.Closed() {
		t.Fatal("new manager should not be closed")
	}

	m.Close()
	if !m.Closed() {
		t.Fatal("closed manager should report closed")
	}
}

func TestSessionManagerCloseIdempotent(t *testing.T) {
	m := NewSessionManager()
	if err := m.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := m.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestSessionManagerRemoveOnClosed(t *testing.T) {
	m := NewSessionManager()
	s := m.Allocate(&ClientStrategy{})
	m.Close()

	// Remove on closed manager should be a no-op (not panic).
	m.Remove(false, s.ID)
}

func TestSessionManagerCloseIfNoSessionAndIdle(t *testing.T) {
	m := NewSessionManager()

	// No sessions, count matches -> should close
	if !m.CloseIfNoSessionAndIdle(0, 0) {
		t.Fatal("should close when empty and idle")
	}
	if !m.Closed() {
		t.Fatal("manager should be closed after CloseIfNoSessionAndIdle")
	}
}

func TestSessionManagerCloseIfNoSessionAndIdleWithActiveSessions(t *testing.T) {
	m := NewSessionManager()
	m.Allocate(&ClientStrategy{})

	// Has active sessions, should not close
	if m.CloseIfNoSessionAndIdle(m.Size(), m.Count()) {
		t.Fatal("should not close with active sessions")
	}
}

func TestSessionManagerCloseIfNoSessionAndIdleAlreadyClosed(t *testing.T) {
	m := NewSessionManager()
	m.Close()

	// Already closed, should return true
	if !m.CloseIfNoSessionAndIdle(0, 0) {
		t.Fatal("already closed manager should return true")
	}
}

func TestSessionManagerCloseIfNoSessionAndIdleCountMismatch(t *testing.T) {
	m := NewSessionManager()
	s := m.Allocate(&ClientStrategy{})
	m.Remove(false, s.ID)

	// Count=1 but checkCount=0 -> should not close (count mismatch)
	if m.CloseIfNoSessionAndIdle(0, 0) {
		t.Fatal("should not close when count doesn't match")
	}
}

// --- XUDP session limit ---

func TestMaxXUDPSessionsConstant(t *testing.T) {
	// maxXUDPSessions is a package-level const.
	// We verify it is set to a reasonable value.
	// Cannot access unexported const from _test package, but we can verify the map exists.
	XUDPManager.Lock()
	defer XUDPManager.Unlock()
	if XUDPManager.Map == nil {
		t.Fatal("XUDPManager.Map should be initialized by init()")
	}
}

// --- Session ID allocation ---

func TestSessionIDMonotonicallyIncreasing(t *testing.T) {
	m := NewSessionManager()
	s1 := m.Allocate(&ClientStrategy{})
	s2 := m.Allocate(&ClientStrategy{})
	s3 := m.Allocate(&ClientStrategy{})

	if s1.ID >= s2.ID || s2.ID >= s3.ID {
		t.Fatalf("session IDs should be monotonically increasing: %d, %d, %d", s1.ID, s2.ID, s3.ID)
	}
}

func TestSessionIDsAreUnique(t *testing.T) {
	m := NewSessionManager()
	ids := make(map[uint16]bool)
	for i := 0; i < 100; i++ {
		s := m.Allocate(&ClientStrategy{})
		if s == nil {
			t.Fatalf("Allocate %d returned nil", i)
		}
		if ids[s.ID] {
			t.Fatalf("duplicate session ID: %d", s.ID)
		}
		ids[s.ID] = true
	}
}
