package reality

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"testing"
	"time"
)

func TestKeyRotatorNoRotation(t *testing.T) {
	privKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
	kr := NewKeyRotator(privKey.Bytes(), 0, 0)
	if kr == nil {
		t.Fatal("NewKeyRotator returned nil")
	}
	defer kr.Stop()

	kp := kr.CurrentKey()
	if kp == nil {
		t.Fatal("CurrentKey returned nil")
	}
	if len(kp.PrivateKey) != 32 || len(kp.PublicKey) != 32 {
		t.Fatalf("unexpected key lengths: priv=%d pub=%d", len(kp.PrivateKey), len(kp.PublicKey))
	}
}

func TestKeyRotatorRotates(t *testing.T) {
	privKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
	kr := NewKeyRotator(privKey.Bytes(), 100*time.Millisecond, 50*time.Millisecond)
	if kr == nil {
		t.Fatal("NewKeyRotator returned nil")
	}
	defer kr.Stop()

	originalPub := append([]byte(nil), kr.CurrentKey().PublicKey...)
	time.Sleep(200 * time.Millisecond)

	newPub := kr.CurrentKey().PublicKey
	if bytes.Equal(originalPub, newPub) {
		t.Fatal("key did not rotate after interval")
	}
}

func TestKeyRotatorTryAuth(t *testing.T) {
	serverPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	kr := NewKeyRotator(serverPriv.Bytes(), 0, 0)
	if kr == nil {
		t.Fatal("NewKeyRotator returned nil")
	}
	defer kr.Stop()

	// Client generates ephemeral key and computes ECDH
	clientPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	serverPubBytes := append([]byte(nil), kr.CurrentKey().PublicKey...)
	shared, ok := kr.TryAuth(clientPriv.PublicKey().Bytes(), serverPubBytes)
	if !ok {
		t.Fatal("TryAuth failed")
	}

	// Verify shared secret matches direct ECDH
	serverPub, _ := ecdh.X25519().NewPublicKey(serverPubBytes)
	expected, _ := clientPriv.ECDH(serverPub)
	if !bytes.Equal(shared, expected) {
		t.Fatal("shared secret mismatch")
	}
}

func TestKeyRotatorGracePeriod(t *testing.T) {
	serverPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	kr := NewKeyRotator(serverPriv.Bytes(), 0, 150*time.Millisecond)
	if kr == nil {
		t.Fatal("NewKeyRotator returned nil")
	}
	defer kr.Stop()

	// Capture old key, then rotate once so old key is in grace-period fallback.
	oldServerPub := append([]byte(nil), kr.CurrentKey().PublicKey...)
	kr.rotate()
	newServerPub := append([]byte(nil), kr.CurrentKey().PublicKey...)
	if bytes.Equal(oldServerPub, newServerPub) {
		t.Fatal("rotation did not change current key")
	}

	// Old client path: must authenticate against old server public key via previous.
	oldClientPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	oldPubObj, _ := ecdh.X25519().NewPublicKey(oldServerPub)
	oldExpected, _ := oldClientPriv.ECDH(oldPubObj)
	oldShared, ok := kr.TryAuth(oldClientPriv.PublicKey().Bytes(), oldServerPub)
	if !ok {
		t.Fatal("TryAuth should succeed for previous key during grace period")
	}
	if !bytes.Equal(oldShared, oldExpected) {
		t.Fatal("shared secret mismatch for previous key during grace period")
	}

	// New client path: must authenticate against current server public key.
	newClientPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	newPubObj, _ := ecdh.X25519().NewPublicKey(newServerPub)
	newExpected, _ := newClientPriv.ECDH(newPubObj)
	newShared, ok := kr.TryAuth(newClientPriv.PublicKey().Bytes(), newServerPub)
	if !ok {
		t.Fatal("TryAuth should succeed for current key during grace period")
	}
	if !bytes.Equal(newShared, newExpected) {
		t.Fatal("shared secret mismatch for current key during grace period")
	}

	// After grace, old key must no longer be accepted.
	time.Sleep(220 * time.Millisecond)
	if _, ok := kr.TryAuth(oldClientPriv.PublicKey().Bytes(), oldServerPub); ok {
		t.Fatal("old key should not be accepted after grace period")
	}
}

func TestKeyRotatorGraceCleanupBindsToRotatedOutKey(t *testing.T) {
	serverPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	kr := NewKeyRotator(serverPriv.Bytes(), 0, 200*time.Millisecond)
	if kr == nil {
		t.Fatal("NewKeyRotator returned nil")
	}
	defer kr.Stop()

	// Rotate twice within one grace window.
	kr.rotate()
	time.Sleep(50 * time.Millisecond)
	kr.rotate()

	kr.mu.RLock()
	if kr.previous == nil {
		kr.mu.RUnlock()
		t.Fatal("expected previous key after second rotation")
	}
	expectedPreviousPub := append([]byte(nil), kr.previous.PublicKey...)
	kr.mu.RUnlock()

	// First rotation's cleanup should not clear the newer previous key.
	time.Sleep(170 * time.Millisecond)
	kr.mu.RLock()
	if kr.previous == nil {
		kr.mu.RUnlock()
		t.Fatal("previous key cleared too early by older grace timer")
	}
	if !bytes.Equal(kr.previous.PublicKey, expectedPreviousPub) {
		kr.mu.RUnlock()
		t.Fatal("unexpected previous key changed during overlapping grace timers")
	}
	kr.mu.RUnlock()

	// Second rotation's cleanup should eventually clear it.
	time.Sleep(80 * time.Millisecond)
	kr.mu.RLock()
	defer kr.mu.RUnlock()
	if kr.previous != nil {
		t.Fatal("previous key should be cleared after its own grace period")
	}
}
