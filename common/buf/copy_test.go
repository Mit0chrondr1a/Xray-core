package buf_test

import (
	"crypto/rand"
	"io"
	"testing"

	"go.uber.org/mock/gomock"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/testing/mocks"
)

func TestReadError(t *testing.T) {
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	mockReader := mocks.NewReader(mockCtl)
	mockReader.EXPECT().Read(gomock.Any()).Return(0, errors.New("error"))

	err := buf.Copy(buf.NewReader(mockReader), buf.Discard)
	if err == nil {
		t.Fatal("expected error, but nil")
	}

	if !buf.IsReadError(err) {
		t.Error("expected to be ReadError, but not")
	}

	if err.Error() != "common/buf_test: error" {
		t.Fatal("unexpected error message: ", err.Error())
	}
}

func TestWriteError(t *testing.T) {
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	mockWriter := mocks.NewWriter(mockCtl)
	mockWriter.EXPECT().Write(gomock.Any()).Return(0, errors.New("error"))

	err := buf.Copy(buf.NewReader(rand.Reader), buf.NewWriter(mockWriter))
	if err == nil {
		t.Fatal("expected error, but nil")
	}

	if !buf.IsWriteError(err) {
		t.Error("expected to be WriteError, but not")
	}

	if err.Error() != "common/buf_test: error" {
		t.Fatal("unexpected error message: ", err.Error())
	}
}

type testCounter struct {
	value    int64
	addCalls int
}

func (c *testCounter) Value() int64 {
	return c.value
}

func (c *testCounter) Set(v int64) int64 {
	prev := c.value
	c.value = v
	return prev
}

func (c *testCounter) Add(v int64) int64 {
	prev := c.value
	c.value += v
	c.addCalls++
	return prev
}

func TestAddToStatCounterFlushOnEOF(t *testing.T) {
	const payloadSize = int64(10 * 1024)

	reader := buf.NewReader(io.LimitReader(TestReader{}, payloadSize))
	writer := buf.Discard
	counter := &testCounter{}

	if err := buf.Copy(reader, writer, buf.AddToStatCounter(counter)); err != nil {
		t.Fatal("unexpected error:", err)
	}

	if counter.Value() != payloadSize {
		t.Fatalf("unexpected counter value: got %d, want %d", counter.Value(), payloadSize)
	}
	if counter.addCalls != 1 {
		t.Fatalf("unexpected add calls: got %d, want 1", counter.addCalls)
	}
}

type TestReader struct{}

func (TestReader) Read(b []byte) (int, error) {
	return len(b), nil
}

func BenchmarkCopy(b *testing.B) {
	reader := buf.NewReader(io.LimitReader(TestReader{}, 10240))
	writer := buf.Discard

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = buf.Copy(reader, writer)
	}
}
