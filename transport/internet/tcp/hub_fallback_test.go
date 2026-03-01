package tcp

import (
	"errors"
	"fmt"
	"testing"

	"github.com/xtls/xray-core/common/native"
)

func TestIsDeferredRealityPeekTimeout(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "peek header receive timeout",
			err:  errors.New("native REALITY deferred: peek header: peek_exact: receive timeout"),
			want: true,
		},
		{
			name: "peek record handshake timeout",
			err:  errors.New("native REALITY deferred: peek record: peek_exact: handshake timeout exceeded"),
			want: true,
		},
		{
			name: "peek short read timeout",
			err:  errors.New("native REALITY deferred: peek record: peek_exact: short read after 5 retries (17/517 bytes)"),
			want: true,
		},
		{
			name: "sentinel timeout wraps",
			err:  fmt.Errorf("%w: simulated", native.ErrRealityDeferredPeekTimeout),
			want: true,
		},
		{
			name: "auth failure should not match",
			err:  errors.New("REALITY auth failed: needs fallback"),
			want: false,
		},
		{
			name: "non-timeout deferred error should not match",
			err:  errors.New("native REALITY deferred: handshake: bad certificate"),
			want: false,
		},
		{
			name: "nil",
			err:  nil,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isDeferredRealityPeekTimeout(tt.err); got != tt.want {
				t.Fatalf("isDeferredRealityPeekTimeout() = %v, want %v", got, tt.want)
			}
		})
	}
}
