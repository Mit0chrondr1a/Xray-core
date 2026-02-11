package pipe

import (
	"io"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/signal/done"
)

// spscPipe is a pipe implementation backed by a lock-free SPSC ring buffer.
// It is suitable for flows with exactly one writer goroutine and one reader goroutine.
type spscPipe struct {
	ring        *SPSCRingBuffer
	readSignal  *signal.Notifier
	writeSignal *signal.Notifier
	done        *done.Instance
	errChan     chan error
	state       atomic.Int32 // spscOpen, spscClosed, spscErrord
}

const (
	spscOpen   int32 = 0
	spscClosed int32 = 1
	spscErrord int32 = 2
)

func (p *spscPipe) readMultiBufferInternal() (buf.MultiBuffer, error) {
	avail := p.ring.AvailableRead()
	if avail == 0 {
		s := p.state.Load()
		if s == spscClosed || s == spscErrord {
			return nil, io.EOF
		}
		return nil, nil
	}

	// Read available bytes into a new buffer (up to buf.Size).
	b := buf.New()
	toRead := avail
	if toRead > buf.Size {
		toRead = buf.Size
	}
	space := b.Extend(int32(toRead))
	n := p.ring.read(space)
	if n < toRead {
		// Shrink if we read less than expected (shouldn't happen, but be safe).
		b.Resize(0, int32(n))
	}

	return buf.MultiBuffer{b}, nil
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

	for len(mb) > 0 {
		s := p.state.Load()
		if s == spscClosed || s == spscErrord {
			buf.ReleaseMulti(mb)
			return io.ErrClosedPipe
		}

		b := mb[0]
		data := b.Bytes()
		written := 0
		for written < len(data) {
			n := p.ring.write(data[written:])
			written += n
			if written < len(data) {
				// Ring full, signal reader and wait for space.
				p.readSignal.Signal()
				select {
				case <-p.writeSignal.Wait():
				case <-p.done.Wait():
					b.Release()
					mb[0] = nil
					mb = mb[1:]
					buf.ReleaseMulti(mb)
					return io.ErrClosedPipe
				}
			}
		}
		b.Release()
		mb[0] = nil
		mb = mb[1:]
	}

	p.readSignal.Signal()
	return nil
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
}

func (p *spscPipe) Len() int32 {
	return int32(p.ring.AvailableRead())
}
