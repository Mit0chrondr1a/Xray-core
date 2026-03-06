package tls

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/native"
)

func TestDeferredKTLSPromotionDisabledAt(t *testing.T) {
	old := deferredKTLSPromotionDisabledUntilUnixNano.Load()
	t.Cleanup(func() {
		deferredKTLSPromotionDisabledUntilUnixNano.Store(old)
	})

	now := time.Unix(1700000000, 0)
	deferredKTLSPromotionDisabledUntilUnixNano.Store(now.Add(2 * time.Minute).UnixNano())

	if !deferredKTLSPromotionDisabledAt(now) {
		t.Fatal("expected deferred promotion to be disabled before cooldown expiry")
	}
	if deferredKTLSPromotionDisabledAt(now.Add(3 * time.Minute)) {
		t.Fatal("expected deferred promotion to be enabled after cooldown expiry")
	}
}

func TestDeferKTLSPromotionForCooldown(t *testing.T) {
	old := deferredKTLSPromotionDisabledUntilUnixNano.Load()
	t.Cleanup(func() {
		deferredKTLSPromotionDisabledUntilUnixNano.Store(old)
	})

	deferredKTLSPromotionDisabledUntilUnixNano.Store(0)
	deferKTLSPromotionForCooldown()
	until := deferredKTLSPromotionDisabledUntilUnixNano.Load()
	if until <= time.Now().UnixNano() {
		t.Fatal("expected cooldown deadline to be set in the future")
	}
}

func TestEnableKTLSOutcome_ConsumedFailureClosesConn(t *testing.T) {
	oldEnable := deferredEnableKTLSFn
	oldAlive := deferredHandleAliveFn
	oldSupported := nativeFullKTLSSupportedFn
	oldCooldown := deferredKTLSPromotionDisabledUntilUnixNano.Load()
	const scope = "test-consumed-failure"
	t.Cleanup(func() {
		deferredEnableKTLSFn = oldEnable
		deferredHandleAliveFn = oldAlive
		nativeFullKTLSSupportedFn = oldSupported
		deferredKTLSPromotionDisabledUntilUnixNano.Store(oldCooldown)
		deferredKTLSPromotionScopes.Delete(scope)
		deferredKTLSPromotionScopeMetrics.Delete(scope)
	})

	deferredEnableKTLSFn = func(*native.DeferredSessionHandle) (*native.TlsResult, error) {
		return nil, errors.New("boom")
	}
	deferredHandleAliveFn = func(*native.DeferredSessionHandle) bool { return false }
	nativeFullKTLSSupportedFn = func() bool { return true }
	deferredKTLSPromotionDisabledUntilUnixNano.Store(0)

	server, client := net.Pipe()
	defer server.Close()

	dc := &DeferredRustConn{
		rawConn:   client,
		handle:    &native.DeferredSessionHandle{},
		ktlsScope: scope,
	}
	out, err := dc.EnableKTLSOutcome()
	if err == nil {
		t.Fatal("expected consumed promotion failure to return error")
	}
	if out.Status != KTLSPromotionFailed {
		t.Fatalf("status=%v, want %v", out.Status, KTLSPromotionFailed)
	}
	if !dc.closed.Load() {
		t.Fatal("consumed promotion failure should close the connection")
	}
	if dc.handle != nil {
		t.Fatal("consumed promotion failure should clear the deferred handle")
	}
	if _, err := dc.Write([]byte("x")); err == nil {
		t.Fatal("write should fail after fail-closed promotion cleanup")
	}
}
