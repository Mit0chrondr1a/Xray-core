package reality

import (
	"fmt"
	"strings"
	"testing"
)

func TestReadSpiderBodyLimit(t *testing.T) {
	previousLimit := maxRealitySpiderResponseBytes
	maxRealitySpiderResponseBytes = 16
	defer func() { maxRealitySpiderResponseBytes = previousLimit }()

	body, err := readSpiderBody(strings.NewReader("short"))
	if err != nil {
		t.Fatalf("expected short body to pass: %v", err)
	}
	if string(body) != "short" {
		t.Fatalf("unexpected body: %q", string(body))
	}

	if _, err := readSpiderBody(strings.NewReader(strings.Repeat("A", 64))); err == nil {
		t.Fatal("expected oversized spider body to fail")
	}
}

func TestAddSpiderPathsCap(t *testing.T) {
	previousCap := maxRealitySpiderPaths
	maxRealitySpiderPaths = 3
	defer func() { maxRealitySpiderPaths = previousCap }()

	paths := map[string]struct{}{
		"/seed": {},
	}
	var html strings.Builder
	for i := 0; i < 10; i++ {
		html.WriteString(fmt.Sprintf(`href="/p%d" `, i))
	}
	addSpiderPaths(paths, []byte(html.String()), []byte("https://example.com"))

	if len(paths) != 3 {
		t.Fatalf("expected path cap enforcement, got %d", len(paths))
	}
}
