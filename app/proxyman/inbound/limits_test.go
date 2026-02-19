package inbound

import (
	"testing"
	"time"
)

func TestAutoTuneUDPSessions(t *testing.T) {
	tests := []struct {
		name           string
		maxConnections int
		want           int
	}{
		{name: "zero_connections", maxConnections: 0, want: defaultUDPSessionsFloor},
		{name: "negative_connections", maxConnections: -1, want: defaultUDPSessionsFloor},
		{name: "small_limit_floor", maxConnections: 1024, want: defaultUDPSessionsFloor},
		{name: "normal_limit", maxConnections: 8192, want: 2048},
		{name: "large_limit_capped", maxConnections: 200000, want: defaultUDPSessionsCap},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := autoTuneUDPSessions(tc.maxConnections); got != tc.want {
				t.Fatalf("autoTuneUDPSessions(%d) = %d, want %d", tc.maxConnections, got, tc.want)
			}
		})
	}
}

func TestParseMaxUDPSessions(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want int
	}{
		{name: "empty", raw: "", want: 0},
		{name: "invalid", raw: "abc", want: 0},
		{name: "zero", raw: "0", want: 0},
		{name: "negative", raw: "-1", want: 0},
		{name: "valid", raw: "2048", want: 2048},
		{name: "too_large_clamped", raw: "9999999", want: maxUDPSessionsConfigCap},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseMaxUDPSessions(tc.raw); got != tc.want {
				t.Fatalf("parseMaxUDPSessions(%q) = %d, want %d", tc.raw, got, tc.want)
			}
		})
	}
}

func TestParseQueueTimeoutMS(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want time.Duration
	}{
		{name: "empty", raw: "", want: defaultQueueTimeout},
		{name: "invalid", raw: "abc", want: defaultQueueTimeout},
		{name: "zero", raw: "0", want: defaultQueueTimeout},
		{name: "negative", raw: "-1", want: defaultQueueTimeout},
		{name: "valid", raw: "1500", want: 1500 * time.Millisecond},
		{name: "too_large_clamped", raw: "999999", want: maxQueueTimeout},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseQueueTimeoutMS(tc.raw); got != tc.want {
				t.Fatalf("parseQueueTimeoutMS(%q) = %v, want %v", tc.raw, got, tc.want)
			}
		})
	}
}
