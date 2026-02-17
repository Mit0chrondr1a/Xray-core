package pipe_test

import (
	"io"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	. "github.com/xtls/xray-core/transport/pipe"
)

func TestSPSCPipeBasicWriteRead(t *testing.T) {
	reader, writer := NewSPSC(16)

	b := buf.New()
	b.WriteString("hello spsc pipe")
	if err := writer.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
		t.Fatalf("WriteMultiBuffer: %v", err)
	}

	mb, err := reader.ReadMultiBuffer()
	if err != nil {
		t.Fatalf("ReadMultiBuffer: %v", err)
	}
	if s := mb.String(); s != "hello spsc pipe" {
		t.Fatalf("read data mismatch: got %q, want %q", s, "hello spsc pipe")
	}
	buf.ReleaseMulti(mb)

	writer.Close()
}

func TestSPSCPipeCloseWriterCausesEOF(t *testing.T) {
	reader, writer := NewSPSC(16)

	writer.Close()

	_, err := reader.ReadMultiBuffer()
	if err != io.EOF {
		t.Fatalf("expected io.EOF after writer close, got %v", err)
	}
}

func TestSPSCPipeInterrupt(t *testing.T) {
	reader, writer := NewSPSC(16)

	// Write some data.
	b := buf.New()
	b.WriteString("data before interrupt")
	writer.WriteMultiBuffer(buf.MultiBuffer{b})

	writer.Interrupt()

	// After interrupt, read may return buffered data first, then EOF.
	mb, err := reader.ReadMultiBuffer()
	if err == io.EOF {
		// No buffered data returned — interrupt took effect immediately.
		return
	}
	if err != nil {
		t.Fatalf("unexpected error after interrupt: %v", err)
	}
	buf.ReleaseMulti(mb)

	// Second read must return EOF.
	_, err = reader.ReadMultiBuffer()
	if err != io.EOF {
		t.Fatalf("expected EOF after interrupt drain, got %v", err)
	}
}

func TestSPSCPipeWriteAfterClose(t *testing.T) {
	_, writer := NewSPSC(16)
	writer.Close()

	b := buf.New()
	b.WriteString("too late")
	err := writer.WriteMultiBuffer(buf.MultiBuffer{b})
	if err != io.ErrClosedPipe {
		t.Fatalf("expected io.ErrClosedPipe, got %v", err)
	}
}

func TestSPSCPipeEmptyWrite(t *testing.T) {
	_, writer := NewSPSC(16)
	// Writing empty MultiBuffer should be a no-op.
	err := writer.WriteMultiBuffer(buf.MultiBuffer{})
	if err != nil {
		t.Fatalf("empty write returned error: %v", err)
	}
	writer.Close()
}

func TestSPSCPipeTimeout(t *testing.T) {
	reader, _ := NewSPSC(16)
	_, err := reader.ReadMultiBufferTimeout(50 * time.Millisecond)
	if err != buf.ErrReadTimeout {
		t.Fatalf("expected ErrReadTimeout, got %v", err)
	}
}

func TestSPSCPipeLargeTransfer(t *testing.T) {
	reader, writer := NewSPSC(8) // small ring

	const numBufs = 100
	done := make(chan int64, 1)

	go func() {
		var total int64
		for {
			mb, err := reader.ReadMultiBuffer()
			if err == io.EOF {
				done <- total
				return
			}
			if err != nil {
				t.Errorf("ReadMultiBuffer: %v", err)
				done <- total
				return
			}
			total += int64(mb.Len())
			buf.ReleaseMulti(mb)
		}
	}()

	var written int64
	for i := 0; i < numBufs; i++ {
		b := buf.New()
		b.WriteString("test data for large transfer test 1234567890")
		size := int64(b.Len())
		if err := writer.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
			t.Fatalf("WriteMultiBuffer %d: %v", i, err)
		}
		written += size
	}
	writer.Close()

	select {
	case totalRead := <-done:
		if totalRead != written {
			t.Fatalf("read %d bytes, wrote %d bytes", totalRead, written)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("large transfer timed out")
	}
}

func TestSPSCPipeLen(t *testing.T) {
	_, writer := NewSPSC(16)

	b := buf.New()
	b.WriteString("12345")
	writer.WriteMultiBuffer(buf.MultiBuffer{b})

	// Writer.Len() reports buffered bytes.
	l := writer.Len()
	if l != 5 {
		t.Fatalf("Len()=%d, want 5", l)
	}

	writer.Close()
}

func TestSPSCPipeWithSPSCOption(t *testing.T) {
	reader, writer := New(WithSizeLimit(8192), WithSPSC())

	b := buf.New()
	b.WriteString("via WithSPSC option")
	if err := writer.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
		t.Fatalf("WriteMultiBuffer: %v", err)
	}

	mb, err := reader.ReadMultiBuffer()
	if err != nil {
		t.Fatalf("ReadMultiBuffer: %v", err)
	}
	if s := mb.String(); s != "via WithSPSC option" {
		t.Fatalf("read data mismatch: got %q", s)
	}
	buf.ReleaseMulti(mb)

	writer.Close()
}
