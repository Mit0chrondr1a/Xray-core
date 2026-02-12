package external

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFetchHTTPContentSizeLimit(t *testing.T) {
	previousLimit := maxExternalConfigBytes
	maxExternalConfigBytes = 32
	defer func() { maxExternalConfigBytes = previousLimit }()

	smallServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"log":{"loglevel":"info"}}`))
	}))
	defer smallServer.Close()

	content, err := FetchHTTPContent(smallServer.URL)
	if err != nil {
		t.Fatalf("expected small payload to pass: %v", err)
	}
	if len(content) == 0 {
		t.Fatal("expected non-empty content")
	}

	largeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("A", 256)))
	}))
	defer largeServer.Close()

	if _, err := FetchHTTPContent(largeServer.URL); err == nil {
		t.Fatal("expected oversized payload to fail")
	}
}

func TestConfigLoaderFileSizeLimit(t *testing.T) {
	previousLimit := maxExternalConfigBytes
	maxExternalConfigBytes = 32
	defer func() { maxExternalConfigBytes = previousLimit }()

	tmpDir := t.TempDir()
	smallPath := filepath.Join(tmpDir, "small.json")
	if err := os.WriteFile(smallPath, []byte(`{"log":{"loglevel":"info"}}`), 0o600); err != nil {
		t.Fatalf("failed to write small test file: %v", err)
	}
	reader, err := ConfigLoader(smallPath)
	if err != nil {
		t.Fatalf("expected small config file to pass: %v", err)
	}
	content, err := io.ReadAll(reader)
	if err != nil || len(content) == 0 {
		t.Fatalf("expected readable content from small file, err=%v", err)
	}

	largePath := filepath.Join(tmpDir, "large.json")
	if err := os.WriteFile(largePath, []byte(strings.Repeat("A", 256)), 0o600); err != nil {
		t.Fatalf("failed to write large test file: %v", err)
	}
	if _, err := ConfigLoader(largePath); err == nil {
		t.Fatal("expected oversized file to fail")
	}
}
