package pipe

import (
	"io"
	"math"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/signal/done"
)

// spscPipe is a pipe implementation backed by a lock-free SPSC slot ring.
// It transfers buf.MultiBuffer values directly without byte serialization.
// Suitable for flows with exactly one writer goroutine and one reader goroutine.
type spscPipe struct {
	ring        *SPSCSlotRing
	readSignal  *signal.Notifier
	writeSignal *signal.Notifier
	done        *done.Instance
	errChan     chan error
	state       atomic.Int32 // spscOpen, spscClosed, spscErrord
	bufferedLen atomic.Int64 // approximate total bytes in ring
	writing     atomic.Bool  // true while writer is between state-check and TryWrite commit
}

const (
	spscOpen   int32 = 0
	spscClosed int32 = 1
	spscErrord int32 = 2
)

func (p *spscPipe) readMultiBufferInternal() (buf.MultiBuffer, error) {
	mb, ok := p.ring.TryRead()
	if ok {
		p.bufferedLen.Add(-int64(mb.Len()))
		return mb, nil
	}
	s := p.state.Load()
	if s == spscClosed || s == spscErrord {
		// Drain any remaining data before returning EOF.
		// This is the ONLY place ring data is drained on close/interrupt,
		// ensuring only one goroutine (the reader) ever calls TryRead.
		// Spin while the writer has an in-flight commit (writing flag set).
		// Since SPSC has exactly one writer, the flag is cleared within a
		// few instructions (no I/O between flag set and clear). Once
		// writing is false and the ring is empty, no more data is coming.
		for {
			if mb, ok := p.ring.TryRead(); ok {
				p.bufferedLen.Add(-int64(mb.Len()))
				return mb, nil
			}
			if !p.writing.Load() {
				break
			}
			runtime.Gosched()
		}
		return nil, io.EOF
	}
	return nil, nil
}

func (p *spscPipe) ReadMultiBuffer() (buf.MultiBuffer, error) {
	for {
		mb, err := p.readMultiBufferInternal()
		if mb != nil || err != nil {
			p.writeSignal.Signal()
			return mb, err
		}

		select {
		case <-p.readSignal.Wait():
		case <-p.done.Wait():
		case err = <-p.errChan:
			return nil, err
		}
	}
}

func (p *spscPipe) ReadMultiBufferTimeout(d time.Duration) (buf.MultiBuffer, error) {
	timer := time.NewTimer(d)
	defer timer.Stop()

	for {
		mb, err := p.readMultiBufferInternal()
		if mb != nil || err != nil {
			p.writeSignal.Signal()
			return mb, err
		}

		select {
		case <-p.readSignal.Wait():
		case <-p.done.Wait():
		case <-timer.C:
			return nil, buf.ErrReadTimeout
		}
	}
}

func (p *spscPipe) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if mb.IsEmpty() {
		return nil
	}

	s := p.state.Load()
	if s == spscClosed || s == spscErrord {
		buf.ReleaseMulti(mb)
		return io.ErrClosedPipe
	}

	// Signal that a write is in flight so the reader's drain loop waits
	// for us to either commit or bail before declaring the ring empty.
	p.writing.Store(true)

	// Double-check: if state changed between the check above and setting
	// the flag, bail out. This ensures: if the reader sees writing==false
	// AND state is closed, no writer will commit new data.
	if s := p.state.Load(); s == spscClosed || s == spscErrord {
		p.writing.Store(false)
		buf.ReleaseMulti(mb)
		return io.ErrClosedPipe
	}

	// Capture length before TryWrite — after the write, the reader may
	// immediately drain and ReleaseMulti the buffers, making mb.Len()
	// a data race on the released Buffer.start/end fields.
	mbLen := int64(mb.Len())

	// Try non-blocking first.
	if p.ring.TryWrite(mb) {
		p.writing.Store(false)
		// Update bufferedLen immediately — data is already in the ring and
		// the reader may drain it at any time. Must happen before state
		// re-check to avoid bufferedLen going negative on drain.
		p.bufferedLen.Add(mbLen)
		p.readSignal.Signal()
		// The write committed — data is in the ring and the reader will
		// deliver it. Always return nil to avoid the caller thinking the
		// write failed and retrying (which would cause duplicate delivery).
		// The caller discovers the closed pipe on its next WriteMultiBuffer.
		return nil
	}

	// Ring full, block until space available.
	p.writing.Store(false)
	for {
		p.readSignal.Signal()
		select {
		case <-p.writeSignal.Wait():
		case <-p.done.Wait():
			buf.ReleaseMulti(mb)
			return io.ErrClosedPipe
		}

		s = p.state.Load()
		if s == spscClosed || s == spscErrord {
			buf.ReleaseMulti(mb)
			return io.ErrClosedPipe
		}

		p.writing.Store(true)
		if s := p.state.Load(); s == spscClosed || s == spscErrord {
			p.writing.Store(false)
			buf.ReleaseMulti(mb)
			return io.ErrClosedPipe
		}
		if p.ring.TryWrite(mb) {
			p.writing.Store(false)
			p.bufferedLen.Add(mbLen)
			p.readSignal.Signal()
			return nil
		}
		p.writing.Store(false)
	}
}

func (p *spscPipe) Close() error {
	if !p.state.CompareAndSwap(spscOpen, spscClosed) {
		return nil
	}
	common.Must(p.done.Close())
	return nil
}

func (p *spscPipe) Interrupt() {
	if p.state.CompareAndSwap(spscOpen, spscErrord) {
		common.Must(p.done.Close())
	} else {
		p.state.CompareAndSwap(spscClosed, spscErrord)
	}
	// Signal the reader so it wakes up, sees the errored state,
	// and drains any remaining ring data before returning EOF.
	// We do NOT drain here because that would create a second reader
	// on the SPSC ring, racing with the actual reader goroutine.
	p.readSignal.Signal()
}

func (p *spscPipe) Len() int32 {
	v := p.bufferedLen.Load()
	if v > math.MaxInt32 {
		return math.MaxInt32
	}
	if v < 0 {
		return 0
	}
	return int32(v)
}
