package tcp

import (
	"bytes"
	"testing"
)

func TestEncodeRealityServerNames(t *testing.T) {
	got := encodeRealityServerNames([]string{"www.example.com", "cdn.example.net"})
	want := []byte("www.example.com\x00cdn.example.net\x00")
	if !bytes.Equal(got, want) {
		t.Fatalf("unexpected server names encoding: got %q want %q", got, want)
	}
}

func TestEncodeRealityServerNamesSkipsEmpty(t *testing.T) {
	got := encodeRealityServerNames([]string{"", "www.example.com", ""})
	want := []byte("www.example.com\x00")
	if !bytes.Equal(got, want) {
		t.Fatalf("unexpected server names encoding with empty entries: got %q want %q", got, want)
	}
}

func TestRealityVersionRange(t *testing.T) {
	tests := []struct {
		name    string
		min     []byte
		max     []byte
		wantSet bool
		wantMin [3]uint8
		wantMax [3]uint8
	}{
		{
			name:    "unset",
			wantSet: false,
			wantMin: [3]uint8{0, 0, 0},
			wantMax: [3]uint8{255, 255, 255},
		},
		{
			name:    "min only",
			min:     []byte{1, 8, 0},
			wantSet: true,
			wantMin: [3]uint8{1, 8, 0},
			wantMax: [3]uint8{255, 255, 255},
		},
		{
			name:    "max only",
			max:     []byte{1, 9, 2},
			wantSet: true,
			wantMin: [3]uint8{0, 0, 0},
			wantMax: [3]uint8{1, 9, 2},
		},
		{
			name:    "partial versions padded",
			min:     []byte{1},
			max:     []byte{2, 3},
			wantSet: true,
			wantMin: [3]uint8{1, 0, 0},
			wantMax: [3]uint8{2, 3, 255},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSet, gotMin, gotMax := realityVersionRange(tt.min, tt.max)
			if gotSet != tt.wantSet {
				t.Fatalf("set mismatch: got %v want %v", gotSet, tt.wantSet)
			}
			if gotMin != tt.wantMin {
				t.Fatalf("min mismatch: got %v want %v", gotMin, tt.wantMin)
			}
			if gotMax != tt.wantMax {
				t.Fatalf("max mismatch: got %v want %v", gotMax, tt.wantMax)
			}
		})
	}
}
