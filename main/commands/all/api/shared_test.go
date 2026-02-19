package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestReadAllWithLimitRejectsOversizedInput(t *testing.T) {
	_, err := readAllWithLimit(bytes.NewReader([]byte("abcdef")), 5, "stdin input")
	if err == nil {
		t.Fatal("expected error for oversized input")
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestReadAllWithLimitAllowsInputAtLimit(t *testing.T) {
	content, err := readAllWithLimit(bytes.NewReader([]byte("abcde")), 5, "stdin input")
	if err != nil {
		t.Fatalf("readAllWithLimit failed: %v", err)
	}
	if string(content) != "abcde" {
		t.Fatalf("unexpected content: %q", content)
	}
}

func TestFetchHTTPContentRejectsOversizedResponse(t *testing.T) {
	payload := bytes.Repeat([]byte("a"), int(maxAPIInputSize)+1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(payload)
	}))
	defer server.Close()

	_, err := fetchHTTPContent(server.URL)
	if err == nil {
		t.Fatal("expected error for oversized HTTP response")
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Fatalf("unexpected error: %v", err)
	}
}
