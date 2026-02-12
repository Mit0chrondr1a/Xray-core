package dns

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDoHHTTPSContextSizeLimit(t *testing.T) {
	previousLimit := maxDoHResponseBytes
	maxDoHResponseBytes = 64
	defer func() { maxDoHResponseBytes = previousLimit }()

	smallServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("unexpected method: %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("small"))
	}))
	defer smallServer.Close()

	server := &DoHNameServer{
		httpClient: smallServer.Client(),
		dohURL:     smallServer.URL,
	}
	body, err := server.dohHTTPSContext(context.Background(), []byte("request"))
	if err != nil {
		t.Fatalf("expected small response to pass: %v", err)
	}
	if string(body) != "small" {
		t.Fatalf("unexpected response body: %q", string(body))
	}

	largeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(strings.Repeat("A", 256)))
	}))
	defer largeServer.Close()

	server = &DoHNameServer{
		httpClient: largeServer.Client(),
		dohURL:     largeServer.URL,
	}
	if _, err := server.dohHTTPSContext(context.Background(), []byte("request")); err == nil {
		t.Fatal("expected oversized DoH response to fail")
	}
}
