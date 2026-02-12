package core

import (
	"bytes"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
)

func TestLoadConfigProtobufSizeLimit(t *testing.T) {
	previousLimit := maxProtobufConfigBytes
	maxProtobufConfigBytes = 32
	defer func() { maxProtobufConfigBytes = previousLimit }()

	valid, err := proto.Marshal(&Config{})
	if err != nil {
		t.Fatalf("failed to marshal protobuf config: %v", err)
	}
	if _, err := LoadConfig("protobuf", bytes.NewReader(valid)); err != nil {
		t.Fatalf("expected small protobuf config to pass: %v", err)
	}

	tooLarge := strings.Repeat("A", 256)
	if _, err := LoadConfig("protobuf", bytes.NewReader([]byte(tooLarge))); err == nil {
		t.Fatal("expected oversized protobuf config error")
	}
}
