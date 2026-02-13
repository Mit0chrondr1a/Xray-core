//go:build linux

package tls

import (
	"bytes"
	gotls "crypto/tls"
	"testing"
)

func TestSetupKeyCaptureClonesConfig(t *testing.T) {
	var original bytes.Buffer
	config := &gotls.Config{
		KeyLogWriter: &original,
	}
	originalWriter := config.KeyLogWriter

	cloned, capture := setupKeyCapture(config)
	if cloned == nil {
		t.Fatal("expected cloned config")
	}
	if capture == nil {
		t.Fatal("expected key capture")
	}
	if cloned == config {
		t.Fatal("expected setupKeyCapture to clone tls.Config")
	}
	if config.KeyLogWriter != originalWriter {
		t.Fatal("expected original tls.Config.KeyLogWriter to stay unchanged")
	}
	if capture.originalWriter != originalWriter {
		t.Fatal("expected capture to chain original writer")
	}
	if _, ok := cloned.KeyLogWriter.(*keyCapture); !ok {
		t.Fatal("expected cloned config KeyLogWriter to be keyCapture")
	}
}
