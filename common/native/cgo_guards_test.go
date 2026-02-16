//go:build cgo && linux

package native

import (
	"strings"
	"testing"
)

// TestVisionPad_EmptyOutputBuffer_CGO verifies the new empty-output guard
// in VisionPad returns an error before reaching FFI.
func TestVisionPad_EmptyOutputBuffer_CGO(t *testing.T) {
	_, err := VisionPad([]byte("hello"), 0x01, []byte("0123456789abcdef"), false, [4]uint32{}, nil)
	if err == nil {
		t.Fatal("VisionPad with empty output should return error")
	}
	if !strings.Contains(err.Error(), "empty output buffer") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

// TestVisionPad_EmptySliceOutputBuffer_CGO verifies empty (non-nil) slice.
func TestVisionPad_EmptySliceOutputBuffer_CGO(t *testing.T) {
	_, err := VisionPad([]byte("hello"), 0x01, []byte("0123456789abcdef"), false, [4]uint32{}, []byte{})
	if err == nil {
		t.Fatal("VisionPad with zero-length output should return error")
	}
	if !strings.Contains(err.Error(), "empty output buffer") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

// TestVisionUnpad_EmptyOutputBuffer_CGO verifies the new empty-output guard
// in VisionUnpad returns an error before reaching FFI.
func TestVisionUnpad_EmptyOutputBuffer_CGO(t *testing.T) {
	state := NewVisionUnpadState()
	_, err := VisionUnpad([]byte("data"), state, nil, nil)
	if err == nil {
		t.Fatal("VisionUnpad with nil output should return error")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

// TestVisionUnpad_NilState_CGO verifies nil state guard.
func TestVisionUnpad_NilState_CGO(t *testing.T) {
	_, err := VisionUnpad([]byte("data"), nil, nil, make([]byte, 64))
	if err == nil {
		t.Fatal("VisionUnpad with nil state should return error")
	}
	if !strings.Contains(err.Error(), "nil state") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

// TestVisionUnpad_EmptyData_CGO verifies empty data guard.
func TestVisionUnpad_EmptyData_CGO(t *testing.T) {
	state := NewVisionUnpadState()
	_, err := VisionUnpad(nil, state, nil, make([]byte, 64))
	if err == nil {
		t.Fatal("VisionUnpad with nil data should return error")
	}
}

// TestTlsConfigSetServerName_EmptyName_CGO verifies empty server name is a no-op.
func TestTlsConfigSetServerName_EmptyName_CGO(t *testing.T) {
	// Calling with nil handle and empty name should not panic.
	TlsConfigSetServerName(nil, "")
	// The function should return silently for nil handle.
	TlsConfigSetServerName(nil, "example.com")
}

// TestGeoIPLoad_EmptyPath_CGO verifies the empty path guard.
func TestGeoIPLoad_EmptyPath_CGO(t *testing.T) {
	_, err := GeoIPLoad("", []string{"US"})
	if err == nil {
		t.Fatal("GeoIPLoad with empty path should return error")
	}
	if !strings.Contains(err.Error(), "empty file path") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

// TestGeoSiteLoad_EmptyPath_CGO verifies the empty path guard.
func TestGeoSiteLoad_EmptyPath_CGO(t *testing.T) {
	_, err := GeoSiteLoad("", []string{"CN"})
	if err == nil {
		t.Fatal("GeoSiteLoad with empty path should return error")
	}
	if !strings.Contains(err.Error(), "empty file path") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

// TestGeoIPLoad_EmptyCodes_CGO verifies empty codes returns nil, nil.
func TestGeoIPLoad_EmptyCodes_CGO(t *testing.T) {
	result, err := GeoIPLoad("/some/path.dat", nil)
	if err != nil {
		t.Fatalf("GeoIPLoad with nil codes should return nil error, got: %v", err)
	}
	if result != nil {
		t.Fatal("GeoIPLoad with nil codes should return nil result")
	}
}

// TestGeoSiteLoad_EmptyCodes_CGO verifies empty codes returns nil, nil.
func TestGeoSiteLoad_EmptyCodes_CGO(t *testing.T) {
	result, err := GeoSiteLoad("/some/path.dat", nil)
	if err != nil {
		t.Fatalf("GeoSiteLoad with nil codes should return nil error, got: %v", err)
	}
	if result != nil {
		t.Fatal("GeoSiteLoad with nil codes should return nil result")
	}
}

// TestAeadSealTo_NilHandle_CGO verifies nil handle guard.
func TestAeadSealTo_NilHandle_CGO(t *testing.T) {
	_, err := AeadSealTo(nil, nil, nil, nil, nil)
	if err == nil {
		t.Fatal("AeadSealTo with nil handle should return error")
	}
}

// TestAeadOpenTo_NilHandle_CGO verifies nil handle guard.
func TestAeadOpenTo_NilHandle_CGO(t *testing.T) {
	_, err := AeadOpenTo(nil, nil, nil, nil, nil)
	if err == nil {
		t.Fatal("AeadOpenTo with nil handle should return error")
	}
}
