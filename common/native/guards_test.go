package native

import (
	"testing"
)

// TestNewVisionUnpadState_Initialization verifies the initial state values.
func TestNewVisionUnpadState_Initialization(t *testing.T) {
	s := NewVisionUnpadState()
	if s == nil {
		t.Fatal("NewVisionUnpadState returned nil")
	}
	if s.RemainingCommand != -1 {
		t.Errorf("RemainingCommand = %d, want -1", s.RemainingCommand)
	}
	if s.RemainingContent != -1 {
		t.Errorf("RemainingContent = %d, want -1", s.RemainingContent)
	}
	if s.RemainingPadding != -1 {
		t.Errorf("RemainingPadding = %d, want -1", s.RemainingPadding)
	}
	if s.CurrentCommand != 0 {
		t.Errorf("CurrentCommand = %d, want 0", s.CurrentCommand)
	}
}

// TestVisionPad_PureGoFallback_ReturnsError verifies that VisionPad returns
// an error when native is not available (pure Go build).
func TestVisionPad_PureGoFallback_ReturnsError(t *testing.T) {
	if Available() {
		t.Skip("native library is available; this test is for pure-Go fallback only")
	}

	out := make([]byte, 1024)
	_, err := VisionPad([]byte("hello"), 0x01, []byte("uuid-bytes"), false, [4]uint32{}, out)
	if err == nil {
		t.Fatal("VisionPad should return error when native is not available")
	}
}

// TestVisionUnpad_PureGoFallback_ReturnsError verifies that VisionUnpad returns
// an error when native is not available (pure Go build).
func TestVisionUnpad_PureGoFallback_ReturnsError(t *testing.T) {
	if Available() {
		t.Skip("native library is available; this test is for pure-Go fallback only")
	}

	state := NewVisionUnpadState()
	out := make([]byte, 1024)
	_, err := VisionUnpad([]byte("data"), state, []byte("uuid"), out)
	if err == nil {
		t.Fatal("VisionUnpad should return error when native is not available")
	}
}

// TestVisionUnpad_NilState verifies that VisionUnpad with nil state returns
// an error regardless of build mode. In CGO mode the guard is:
//
//	if state == nil || len(data) == 0 || len(out) == 0
//
// In pure-Go mode, the stub always returns errNotAvailable.
func TestVisionUnpad_NilState(t *testing.T) {
	out := make([]byte, 1024)
	_, err := VisionUnpad([]byte("data"), nil, nil, out)
	if err == nil {
		t.Fatal("VisionUnpad(nil state) should return error")
	}
}

// TestVisionUnpad_EmptyData verifies that VisionUnpad with empty data returns
// an error.
func TestVisionUnpad_EmptyData(t *testing.T) {
	state := NewVisionUnpadState()
	out := make([]byte, 1024)
	_, err := VisionUnpad(nil, state, nil, out)
	if err == nil {
		t.Fatal("VisionUnpad(empty data) should return error")
	}
}

// TestVisionUnpad_EmptyOutput verifies that VisionUnpad with empty output
// returns an error. This is the new guard added in the diff.
func TestVisionUnpad_EmptyOutput(t *testing.T) {
	state := NewVisionUnpadState()
	_, err := VisionUnpad([]byte("data"), state, nil, nil)
	if err == nil {
		t.Fatal("VisionUnpad(empty output) should return error")
	}
}

// TestGeoIPLoad_PureGoFallback verifies GeoIPLoad returns error in pure-Go mode.
func TestGeoIPLoad_PureGoFallback(t *testing.T) {
	if Available() {
		t.Skip("native library is available; this test is for pure-Go fallback only")
	}

	// Empty path
	_, err := GeoIPLoad("", []string{"US"})
	if err == nil {
		t.Fatal("GeoIPLoad with empty path should return error")
	}

	// Non-empty path, still should fail in pure-Go mode
	_, err = GeoIPLoad("/nonexistent/geoip.dat", []string{"US"})
	if err == nil {
		t.Fatal("GeoIPLoad should return error when native is not available")
	}
}

// TestGeoSiteLoad_PureGoFallback verifies GeoSiteLoad returns error in pure-Go mode.
func TestGeoSiteLoad_PureGoFallback(t *testing.T) {
	if Available() {
		t.Skip("native library is available; this test is for pure-Go fallback only")
	}

	_, err := GeoSiteLoad("", []string{"CN"})
	if err == nil {
		t.Fatal("GeoSiteLoad with empty path should return error")
	}

	_, err = GeoSiteLoad("/nonexistent/geosite.dat", []string{"CN"})
	if err == nil {
		t.Fatal("GeoSiteLoad should return error when native is not available")
	}
}

// TestGeoIPLoad_EmptyCodes verifies GeoIPLoad with no codes.
// In CGO mode, the early-return returns (nil, nil).
// In pure-Go mode, the stub returns (nil, errNotAvailable).
func TestGeoIPLoad_EmptyCodes(t *testing.T) {
	result, err := GeoIPLoad("/some/path", nil)
	if Available() {
		// CGO path has early-return for empty codes
		if err != nil {
			t.Fatalf("GeoIPLoad with empty codes should return nil error in CGO mode, got: %v", err)
		}
		if result != nil {
			t.Fatalf("GeoIPLoad with empty codes should return nil result in CGO mode, got: %v", result)
		}
	} else {
		// Pure-Go stub always returns errNotAvailable
		if err == nil {
			t.Fatal("GeoIPLoad should return error when native is not available")
		}
	}
}

// TestGeoSiteLoad_EmptyCodes verifies GeoSiteLoad with no codes.
// Same behavior split as GeoIPLoad.
func TestGeoSiteLoad_EmptyCodes(t *testing.T) {
	result, err := GeoSiteLoad("/some/path", nil)
	if Available() {
		if err != nil {
			t.Fatalf("GeoSiteLoad with empty codes should return nil error in CGO mode, got: %v", err)
		}
		if result != nil {
			t.Fatalf("GeoSiteLoad with empty codes should return nil result in CGO mode, got: %v", result)
		}
	} else {
		if err == nil {
			t.Fatal("GeoSiteLoad should return error when native is not available")
		}
	}
}

// TestEbpfSetup_PureGoFallback verifies EbpfSetup returns error in pure-Go mode.
func TestEbpfSetup_PureGoFallback(t *testing.T) {
	if Available() {
		t.Skip("native library is available; this test is for pure-Go fallback only")
	}
	err := EbpfSetup("/tmp/test", 1024, 0)
	if err == nil {
		t.Fatal("EbpfSetup should return error when native is not available")
	}
}

// TestAvailable_Consistent verifies Available() returns a consistent value.
func TestAvailable_Consistent(t *testing.T) {
	a := Available()
	b := Available()
	if a != b {
		t.Fatal("Available() returned inconsistent values across two calls")
	}
}

// TestTlsResult_ZeroSecrets verifies ZeroSecrets clears and nils the slices.
func TestTlsResult_ZeroSecrets(t *testing.T) {
	r := &TlsResult{
		TxSecret: []byte{0x01, 0x02, 0x03},
		RxSecret: []byte{0x04, 0x05, 0x06},
	}
	r.ZeroSecrets()
	if r.TxSecret != nil {
		t.Error("TxSecret should be nil after ZeroSecrets")
	}
	if r.RxSecret != nil {
		t.Error("RxSecret should be nil after ZeroSecrets")
	}
}

// TestTlsResult_ZeroSecrets_EmptySlices verifies ZeroSecrets handles empty slices.
func TestTlsResult_ZeroSecrets_EmptySlices(t *testing.T) {
	r := &TlsResult{
		TxSecret: []byte{},
		RxSecret: []byte{},
	}
	r.ZeroSecrets() // should not panic
	if r.TxSecret != nil {
		t.Error("TxSecret should be nil after ZeroSecrets")
	}
}

// TestTlsResult_ZeroSecrets_NilSlices verifies ZeroSecrets handles nil slices.
func TestTlsResult_ZeroSecrets_NilSlices(t *testing.T) {
	r := &TlsResult{}
	r.ZeroSecrets() // should not panic
	if r.TxSecret != nil {
		t.Error("TxSecret should be nil after ZeroSecrets")
	}
}
