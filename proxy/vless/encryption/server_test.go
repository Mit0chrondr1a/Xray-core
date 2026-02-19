package encryption

import "testing"

func TestStoreSessionUsesEncodedTicketLifetime(t *testing.T) {
	i := &ServerInstance{
		Lasts:    make(map[int64][][16]byte),
		Sessions: make(map[[16]byte]*ServerSession),
	}

	rawSeconds := 90000
	ticket := [16]byte{}
	copy(ticket[:], EncodeLength(rawSeconds))
	pfsKey := []byte{1, 2, 3, 4}
	nowUnix := int64(1_700_000_000)

	if ok := i.storeSession(ticket, pfsKey, nowUnix); !ok {
		t.Fatal("storeSession should keep a ticket with positive encoded lifetime")
	}

	encodedSeconds := int64(DecodeLength(ticket[:2]))
	wantMinute := (nowUnix+encodedSeconds)/60 + 2
	got := i.Lasts[wantMinute]
	if len(got) != 1 || got[0] != ticket {
		t.Fatalf("Lasts[%d] = %x, want [%x]", wantMinute, got, ticket)
	}

	legacyMinute := (nowUnix+86400)/60 + 2
	if legacyMinute != wantMinute {
		if got := i.Lasts[legacyMinute]; len(got) > 0 {
			t.Fatalf("ticket retained at legacy capped minute %d; expected encoded lifetime minute %d", legacyMinute, wantMinute)
		}
	}
	if s := i.Sessions[ticket]; s == nil {
		t.Fatal("session was not stored")
	}
}

func TestStoreSessionRejectsZeroEncodedLifetime(t *testing.T) {
	i := &ServerInstance{
		Lasts:    make(map[int64][][16]byte),
		Sessions: make(map[[16]byte]*ServerSession),
	}

	ticket := [16]byte{}
	copy(ticket[:], EncodeLength(1<<16))
	pfsKey := []byte{9, 8, 7, 6}

	if ok := i.storeSession(ticket, pfsKey, 0); ok {
		t.Fatal("storeSession should reject a ticket with zero encoded lifetime")
	}
	if len(i.Lasts) != 0 {
		t.Fatalf("Lasts should be empty, got %d entries", len(i.Lasts))
	}
	if len(i.Sessions) != 0 {
		t.Fatalf("Sessions should be empty, got %d entries", len(i.Sessions))
	}
	for idx, b := range pfsKey {
		if b != 0 {
			t.Fatalf("pfsKey[%d] = %d, want 0 after clear()", idx, b)
		}
	}
}

func TestEvictionUsesExpiryOrderWithMixedTicketLifetimes(t *testing.T) {
	i := &ServerInstance{
		Lasts:    make(map[int64][][16]byte),
		Sessions: make(map[[16]byte]*ServerSession),
	}

	nowUnix := int64(1_700_000_000)
	longTicket := [16]byte{}
	shortTicket := [16]byte{}
	copy(longTicket[:], EncodeLength(180))
	copy(shortTicket[:], EncodeLength(60))

	if ok := i.storeSession(longTicket, []byte{1}, nowUnix); !ok {
		t.Fatal("failed to store long ticket")
	}
	if ok := i.storeSession(shortTicket, []byte{2}, nowUnix); !ok {
		t.Fatal("failed to store short ticket")
	}

	shortMinute := (nowUnix+int64(DecodeLength(shortTicket[:2])))/60 + 2
	longMinute := (nowUnix+int64(DecodeLength(longTicket[:2])))/60 + 2
	if shortMinute >= longMinute {
		t.Fatalf("expected short expiry minute < long expiry minute, got short=%d long=%d", shortMinute, longMinute)
	}

	i.RWLock.Lock()
	i.evictExpiredSessionsLocked(shortMinute)
	i.RWLock.Unlock()
	if i.Sessions[shortTicket] != nil {
		t.Fatal("short-lived ticket should be evicted at its expiry minute")
	}
	if i.Sessions[longTicket] == nil {
		t.Fatal("long-lived ticket was evicted too early")
	}

	i.RWLock.Lock()
	i.evictExpiredSessionsLocked(longMinute)
	i.RWLock.Unlock()
	if i.Sessions[longTicket] != nil {
		t.Fatal("long-lived ticket should be evicted at its expiry minute")
	}
}
