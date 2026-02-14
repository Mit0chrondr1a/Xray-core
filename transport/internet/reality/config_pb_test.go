package reality

import (
	"testing"

	"google.golang.org/protobuf/proto"
)

func TestConfigKeyRotationHoursRoundTrip(t *testing.T) {
	input := &Config{KeyRotationHours: 1}

	wire, err := proto.Marshal(input)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	if len(wire) == 0 {
		t.Fatal("marshal produced empty wire data")
	}

	var output Config
	if err := proto.Unmarshal(wire, &output); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if output.GetKeyRotationHours() != input.GetKeyRotationHours() {
		t.Fatalf("key_rotation_hours mismatch: got %d, want %d", output.GetKeyRotationHours(), input.GetKeyRotationHours())
	}
}
