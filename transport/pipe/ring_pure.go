//go:build !cgo || !zig

package pipe

import (
	"sync/atomic"
)

// ZigRingBuffer is a pure Go fallback for the Zig SPSC ring buffer.
// Uses atomic operations for lock-free single-producer single-consumer access.
type ZigRingBuffer struct {
	buffer   []byte
	capacity uint64
	mask     uint64
	writePos atomic.Uint64
	_pad1    [56]byte // cache line padding
	readPos  atomic.Uint64
	_pad2    [56]byte // cache line padding
}

// NewZigRingBuffer creates a new lock-free SPSC ring buffer.
func NewZigRingBuffer(capacity int) *ZigRingBuffer {
	// Round up to next power of 2
	cap := nextPowerOf2(uint64(capacity))
	if cap < 16 {
		cap = 16
	}
	return &ZigRingBuffer{
		buffer:   make([]byte, cap),
		capacity: cap,
		mask:     cap - 1,
	}
}

// Write writes data to the ring buffer. Returns the number of bytes written.
func (r *ZigRingBuffer) Write(data []byte) int {
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

// Read reads data from the ring buffer. Returns the number of bytes read.
func (r *ZigRingBuffer) Read(buf []byte) int {
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

// AvailableRead returns the number of bytes available to read.
func (r *ZigRingBuffer) AvailableRead() int {
	wp := r.writePos.Load()
	rp := r.readPos.Load()
	return int(wp - rp)
}

// AvailableWrite returns the number of bytes available to write.
func (r *ZigRingBuffer) AvailableWrite() int {
	wp := r.writePos.Load()
	rp := r.readPos.Load()
	return int(r.capacity - (wp - rp))
}

// Close releases the ring buffer resources.
func (r *ZigRingBuffer) Close() {
	// Pure Go - nothing to free
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
