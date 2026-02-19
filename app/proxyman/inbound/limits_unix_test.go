//go:build unix

package inbound

import "testing"

func TestAutoTuneMaxConnections(t *testing.T) {
	tests := []struct {
		name string
		cur  uint64
		want int
	}{
		{name: "zero", cur: 0, want: 1},
		{name: "one", cur: 1, want: 1},
		{name: "tiny", cur: 16, want: 1},
		{name: "low_ulimit", cur: 256, want: 224},
		{name: "one_k", cur: 1024, want: 896},
		{name: "medium", cur: 2048, want: 1792},
		{name: "large", cur: 65536, want: 64512},
		{name: "cap", cur: uint64(maxConnectionsCap) + 1000, want: 261120},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := autoTuneMaxConnections(tc.cur)
			if got != tc.want {
				t.Fatalf("autoTuneMaxConnections(%d) = %d, want %d", tc.cur, got, tc.want)
			}

			maxAllowed := maxConnectionsCap
			if tc.cur < uint64(maxConnectionsCap) {
				maxAllowed = int(tc.cur)
			}
			if maxAllowed > 0 && got > maxAllowed {
				t.Fatalf("computed max connections (%d) exceeds fd limit (%d)", got, maxAllowed)
			}
			if maxAllowed > 1 && got >= maxAllowed {
				t.Fatalf("computed max connections (%d) must leave headroom below fd limit (%d)", got, maxAllowed)
			}
		})
	}
}
