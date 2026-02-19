package splithttp

import (
	"testing"

	"github.com/xtls/xray-core/common/buf"
)

func TestNewUploadPipeBatchesWritesIntoSingleRead(t *testing.T) {
	maxUploadSize := int32(buf.Size * 4)
	reader, writer := newUploadPipe(maxUploadSize)

	payload := make([]byte, buf.Size/4)
	writes := 3
	expectedLen := len(payload) * writes

	for i := 0; i < writes; i++ {
		n, err := writer.Write(payload)
		if err != nil {
			t.Fatalf("write %d failed: %v", i, err)
		}
		if n != len(payload) {
			t.Fatalf("write %d returned %d bytes, want %d", i, n, len(payload))
		}
	}

	mb, err := reader.ReadMultiBuffer()
	if err != nil {
		t.Fatalf("ReadMultiBuffer failed: %v", err)
	}
	defer buf.ReleaseMulti(mb)

	if got := mb.Len(); got != int32(expectedLen) {
		t.Fatalf("unexpected first read length: got %d, want %d", got, expectedLen)
	}
	if mb.Len() <= int32(len(payload)) {
		t.Fatalf("expected batched read > %d bytes, got %d", len(payload), mb.Len())
	}

	if err := writer.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}
}
