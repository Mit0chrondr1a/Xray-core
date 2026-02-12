package pipe

import (
	"io"
	"sync"
	"sync/atomic"
)

// SPSCRingBuffer is a lock-free single-producer single-consumer ring buffer.
// It provides high-throughput byte transfer between exactly one writer goroutine
// and one reader goroutine without mutex contention. For general-purpose pipes
// that transfer buf.MultiBuffer, use pipe.New instead.
type SPSCRingBuffer struct {
	buffer   []byte
	capacity uint64
	mask     uint64
	writePos atomic.Uint64
	_pad1    [56]byte // cache line padding
	readPos  atomic.Uint64
	_pad2    [56]byte // cache line padding

	mu             sync.Mutex
	cond           *sync.Cond
	closed         atomic.Bool
	readerWaiting  atomic.Bool
	writerWaiting  atomic.Bool
}

// NewSPSCRingBuffer creates a new lock-free SPSC ring buffer with the given
// capacity (rounded up to the next power of 2, minimum 16 bytes).
// The returned buffer implements io.ReadWriteCloser.
func NewSPSCRingBuffer(capacity int) *SPSCRingBuffer {
	cap := nextPowerOf2(uint64(capacity))
	if cap < 16 {
		cap = 16
	}
	r := &SPSCRingBuffer{
		buffer:   make([]byte, cap),
		capacity: cap,
		mask:     cap - 1,
	}
	r.cond = sync.NewCond(&r.mu)
	return r
}

// write copies data into the ring buffer without blocking.
// Returns the number of bytes written (may be less than len(data) if the buffer is full).
func (r *SPSCRingBuffer) write(data []byte) int {
	wp := r.writePos.Load()
	rp := r.readPos.Load()

	available := r.capacity - (wp - rp)
	toWrite := uint64(len(data))
	if toWrite > available {
		toWrite = available
	}
	if toWrite == 0 {
		return 0
	}

	start := wp & r.mask
	firstChunk := r.capacity - start
	if firstChunk > toWrite {
		firstChunk = toWrite
	}

	copy(r.buffer[start:start+firstChunk], data[:firstChunk])
	if secondChunk := toWrite - firstChunk; secondChunk > 0 {
		copy(r.buffer[:secondChunk], data[firstChunk:firstChunk+secondChunk])
	}

	r.writePos.Store(wp + toWrite)
	return int(toWrite)
}

// read copies data from the ring buffer without blocking.
// Returns the number of bytes read (may be less than len(buf) if the buffer is empty).
func (r *SPSCRingBuffer) read(buf []byte) int {
	rp := r.readPos.Load()
	wp := r.writePos.Load()

	available := wp - rp
	toRead := uint64(len(buf))
	if toRead > available {
		toRead = available
	}
	if toRead == 0 {
		return 0
	}

	start := rp & r.mask
	firstChunk := r.capacity - start
	if firstChunk > toRead {
		firstChunk = toRead
	}

	copy(buf[:firstChunk], r.buffer[start:start+firstChunk])
	if secondChunk := toRead - firstChunk; secondChunk > 0 {
		copy(buf[firstChunk:firstChunk+secondChunk], r.buffer[:secondChunk])
	}

	r.readPos.Store(rp + toRead)
	return int(toRead)
}

// Write implements io.Writer. It blocks until all data is written or the
// buffer is closed. Only one goroutine should call Write at a time.
func (r *SPSCRingBuffer) Write(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}

	written := 0
	for written < len(data) {
		if r.closed.Load() {
			return written, io.ErrClosedPipe
		}

		n := r.write(data[written:])
		written += n

		if written < len(data) {
			// Buffer full, wake reader and wait for drain.
			r.mu.Lock()
			r.cond.Signal()
			if !r.closed.Load() && r.AvailableWrite() == 0 {
				r.writerWaiting.Store(true)
				r.cond.Wait()
				r.writerWaiting.Store(false)
			}
			r.mu.Unlock()
		}
	}

	// Signal reader only if it is actually waiting.
	if r.readerWaiting.Load() {
		r.mu.Lock()
		r.cond.Signal()
		r.mu.Unlock()
	}

	return written, nil
}

// Read implements io.Reader. It blocks until data is available or the buffer
// is closed. Only one goroutine should call Read at a time.
func (r *SPSCRingBuffer) Read(buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}

	for {
		n := r.read(buf)
		if n > 0 {
			// Signal writer only if it is actually waiting.
			if r.writerWaiting.Load() {
				r.mu.Lock()
				r.cond.Signal()
				r.mu.Unlock()
			}
			return n, nil
		}

		if r.closed.Load() {
			return 0, io.EOF
		}

		// No data, wait for writer.
		r.mu.Lock()
		if r.AvailableRead() == 0 && !r.closed.Load() {
			r.readerWaiting.Store(true)
			r.cond.Wait()
			r.readerWaiting.Store(false)
		}
		r.mu.Unlock()
	}
}

// AvailableRead returns the number of bytes available to read.
func (r *SPSCRingBuffer) AvailableRead() int {
	wp := r.writePos.Load()
	rp := r.readPos.Load()
	return int(wp - rp)
}

// AvailableWrite returns the number of bytes available to write.
func (r *SPSCRingBuffer) AvailableWrite() int {
	wp := r.writePos.Load()
	rp := r.readPos.Load()
	return int(r.capacity - (wp - rp))
}

// Close marks the buffer as closed. Subsequent writes return io.ErrClosedPipe.
// Subsequent reads return any buffered data, then io.EOF.
func (r *SPSCRingBuffer) Close() error {
	r.closed.Store(true)
	r.mu.Lock()
	r.cond.Broadcast()
	r.mu.Unlock()
	return nil
}

func nextPowerOf2(v uint64) uint64 {
	v--
	v |= v >> 1
	v |= v >> 2
	v |= v >> 4
	v |= v >> 8
	v |= v >> 16
	v |= v >> 32
	v++
	return v
}
