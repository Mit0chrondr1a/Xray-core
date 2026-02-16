package trojan

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestHexSha224Deterministic(t *testing.T) {
	a := hexSha224("test-password")
	b := hexSha224("test-password")
	if string(a) != string(b) {
		t.Fatal("hexSha224 is not deterministic")
	}
}

func TestHexSha224MatchesManual(t *testing.T) {
	password := "mypassword123"
	h := sha256.New224()
	h.Write([]byte(password))
	expected := hex.EncodeToString(h.Sum(nil))

	got := string(hexSha224(password))
	if got != expected {
		t.Fatalf("hexSha224(%q) = %q, want %q", password, got, expected)
	}
}

func TestHexSha224Length(t *testing.T) {
	key := hexSha224("any-password")
	// SHA-224 = 28 bytes = 56 hex chars
	if len(key) != 56 {
		t.Fatalf("hexSha224 key length=%d, want 56", len(key))
	}
}

func TestHexSha224DifferentPasswords(t *testing.T) {
	a := hexSha224("password-a")
	b := hexSha224("password-b")
	if string(a) == string(b) {
		t.Fatal("different passwords should produce different keys")
	}
}

func TestHexSha224Empty(t *testing.T) {
	key := hexSha224("")
	if len(key) != 56 {
		t.Fatalf("hexSha224(\"\") key length=%d, want 56", len(key))
	}
}

func TestHexString(t *testing.T) {
	data := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	got := hexString(data)
	if got != "deadbeef" {
		t.Fatalf("hexString(deadbeef) = %q, want 'deadbeef'", got)
	}
}

func TestHexStringEmpty(t *testing.T) {
	got := hexString(nil)
	if got != "" {
		t.Fatalf("hexString(nil) = %q, want empty", got)
	}
}

func TestAccountAsAccount(t *testing.T) {
	a := &Account{Password: "trojan-pass"}
	acct, err := a.AsAccount()
	if err != nil {
		t.Fatalf("AsAccount: %v", err)
	}
	ma := acct.(*MemoryAccount)
	if ma.Password != "trojan-pass" {
		t.Fatalf("Password=%q, want 'trojan-pass'", ma.Password)
	}
	if len(ma.Key) != 56 {
		t.Fatalf("Key length=%d, want 56", len(ma.Key))
	}
}

func TestMemoryAccountEquals(t *testing.T) {
	a := &MemoryAccount{Password: "same"}
	b := &MemoryAccount{Password: "same"}
	c := &MemoryAccount{Password: "different"}
	if !a.Equals(b) {
		t.Fatal("same passwords should be equal")
	}
	if a.Equals(c) {
		t.Fatal("different passwords should not be equal")
	}
}

func TestMemoryAccountToProto(t *testing.T) {
	a := &MemoryAccount{Password: "test"}
	msg := a.ToProto()
	if msg == nil {
		t.Fatal("ToProto returned nil")
	}
	acctPB, ok := msg.(*Account)
	if !ok {
		t.Fatal("ToProto did not return *Account")
	}
	if acctPB.Password != "test" {
		t.Fatalf("Password=%q, want 'test'", acctPB.Password)
	}
}

func BenchmarkHexSha224(b *testing.B) {
	for i := 0; i < b.N; i++ {
		hexSha224("benchmark-password-string")
	}
}
