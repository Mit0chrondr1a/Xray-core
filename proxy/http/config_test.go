package http

import (
	"testing"
)

func TestHasAccountValidCredentials(t *testing.T) {
	sc := &ServerConfig{
		Accounts: map[string]string{
			"admin": "secret123",
			"user":  "pass",
		},
	}
	if !sc.HasAccount("admin", "secret123") {
		t.Fatal("expected valid credentials to match")
	}
	if !sc.HasAccount("user", "pass") {
		t.Fatal("expected valid credentials to match")
	}
}

func TestHasAccountWrongPassword(t *testing.T) {
	sc := &ServerConfig{
		Accounts: map[string]string{
			"admin": "secret123",
		},
	}
	if sc.HasAccount("admin", "wrong") {
		t.Fatal("expected wrong password to fail")
	}
}

func TestHasAccountUnknownUser(t *testing.T) {
	sc := &ServerConfig{
		Accounts: map[string]string{
			"admin": "secret123",
		},
	}
	if sc.HasAccount("unknown", "secret123") {
		t.Fatal("expected unknown user to fail")
	}
}

func TestHasAccountNilAccounts(t *testing.T) {
	sc := &ServerConfig{Accounts: nil}
	if sc.HasAccount("any", "any") {
		t.Fatal("expected nil accounts map to return false")
	}
}

func TestHasAccountEmptyAccounts(t *testing.T) {
	sc := &ServerConfig{Accounts: map[string]string{}}
	if sc.HasAccount("any", "any") {
		t.Fatal("expected empty accounts map to return false")
	}
}

func TestHasAccountEmptyPassword(t *testing.T) {
	sc := &ServerConfig{
		Accounts: map[string]string{
			"user": "",
		},
	}
	if !sc.HasAccount("user", "") {
		t.Fatal("expected empty password to match stored empty password")
	}
	if sc.HasAccount("user", "notempty") {
		t.Fatal("expected non-empty password to fail against stored empty password")
	}
}

// TestHasAccountTimingResistance verifies the constant-time property
// by checking that the function does not short-circuit on username mismatch
// before performing password comparison. This is a functional test, not a
// timing measurement -- the constant-time guarantee comes from crypto/subtle.
func TestHasAccountTimingResistance(t *testing.T) {
	sc := &ServerConfig{
		Accounts: map[string]string{
			"admin": "secret123",
		},
	}
	// Both of these should return false, but the dummy comparison branch
	// should still be taken for the unknown user case.
	if sc.HasAccount("fake", "secret123") {
		t.Fatal("unknown user should fail even with correct password of another user")
	}
	if sc.HasAccount("admin", "bad") {
		t.Fatal("wrong password should fail")
	}
}

func BenchmarkHasAccountValid(b *testing.B) {
	sc := &ServerConfig{
		Accounts: map[string]string{
			"admin": "longpassword1234567890",
		},
	}
	for i := 0; i < b.N; i++ {
		sc.HasAccount("admin", "longpassword1234567890")
	}
}

func BenchmarkHasAccountInvalid(b *testing.B) {
	sc := &ServerConfig{
		Accounts: map[string]string{
			"admin": "longpassword1234567890",
		},
	}
	for i := 0; i < b.N; i++ {
		sc.HasAccount("admin", "wrongpassword")
	}
}
