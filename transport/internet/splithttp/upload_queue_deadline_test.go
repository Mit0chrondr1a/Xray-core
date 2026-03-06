package splithttp

import (
	stderrors "errors"
	"os"
	"testing"
	"time"
)

func TestUploadQueueReadHonorsDeadline(t *testing.T) {
	q := NewUploadQueue(1)
	if err := q.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline failed: %v", err)
	}

	start := time.Now()
	_, err := q.Read(make([]byte, 1))
	if !stderrors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Read error = %v, want deadline exceeded", err)
	}
	if time.Since(start) < 15*time.Millisecond {
		t.Fatal("Read returned before deadline elapsed")
	}
}
