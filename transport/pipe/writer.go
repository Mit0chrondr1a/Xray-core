package pipe

import (
	"github.com/xtls/xray-core/common/buf"
)

// Writer is a buf.Writer that writes data into a pipe.
type Writer struct {
	impl pipeImpl
}

// WriteMultiBuffer implements buf.Writer.
func (w *Writer) WriteMultiBuffer(mb buf.MultiBuffer) error {
	return w.impl.WriteMultiBuffer(mb)
}

// Close implements io.Closer. After the pipe is closed, writing to the pipe will return io.ErrClosedPipe, while reading will return io.EOF.
func (w *Writer) Close() error {
	return w.impl.Close()
}

func (w *Writer) Len() int32 {
	return w.impl.Len()
}

// Interrupt implements common.Interruptible.
func (w *Writer) Interrupt() {
	w.impl.Interrupt()
}
