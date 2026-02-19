package splithttp

import "testing"

func TestParseMaxConcurrentSessions(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want int64
	}{
		{name: "empty", raw: "", want: 0},
		{name: "invalid", raw: "abc", want: 0},
		{name: "zero", raw: "0", want: 0},
		{name: "negative", raw: "-1", want: 0},
		{name: "valid", raw: "32768", want: 32768},
		{name: "too_large_clamped", raw: "9999999", want: maxConcurrentSessionsCap},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseMaxConcurrentSessions(tc.raw); got != tc.want {
				t.Fatalf("parseMaxConcurrentSessions(%q) = %d, want %d", tc.raw, got, tc.want)
			}
		})
	}
}
