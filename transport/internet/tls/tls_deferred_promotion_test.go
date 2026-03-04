package tls

import (
	"testing"
	"time"
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
