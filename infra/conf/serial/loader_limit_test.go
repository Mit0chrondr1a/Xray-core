package serial

import (
	"strings"
	"testing"
)

func TestDecodeConfigSizeLimit(t *testing.T) {
	previousLimit := maxSerializedConfigBytes
	maxSerializedConfigBytes = 32
	defer func() { maxSerializedConfigBytes = previousLimit }()

	tomlInput := "loglevel = \"info\""
	if _, err := DecodeTOMLConfig(strings.NewReader(tomlInput)); err != nil {
		t.Fatalf("expected small TOML input to pass: %v", err)
	}

	yamlInput := "log:\n  loglevel: info\n"
	if _, err := DecodeYAMLConfig(strings.NewReader(yamlInput)); err != nil {
		t.Fatalf("expected small YAML input to pass: %v", err)
	}
	jsonInput := "{\"log\": {\"loglevel\": \"info\"}}"
	if _, err := DecodeJSONConfig(strings.NewReader(jsonInput)); err != nil {
		t.Fatalf("expected small JSON input to pass: %v", err)
	}

	oversized := strings.Repeat("a", 256)
	if _, err := DecodeTOMLConfig(strings.NewReader(oversized)); err == nil {
		t.Fatal("expected oversized TOML input to fail")
	}
	if _, err := DecodeYAMLConfig(strings.NewReader(oversized)); err == nil {
		t.Fatal("expected oversized YAML input to fail")
	}
	if _, err := DecodeJSONConfig(strings.NewReader(oversized)); err == nil {
		t.Fatal("expected oversized JSON input to fail")
	}
}
