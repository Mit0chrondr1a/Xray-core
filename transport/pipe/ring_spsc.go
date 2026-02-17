package pipe

import (
	"sync"
	"sync/atomic"

	"github.com/xtls/xray-core/common/buf"
)

// SPSCSlotRing is a lock-free single-producer single-consumer ring buffer
// that stores buf.MultiBuffer values directly in slots, achieving zero-copy
// transfer between exactly one writer goroutine and one reader goroutine.
type SPSCSlotRing struct {
	slots    []buf.MultiBuffer
	writePos atomic.Uint64
	_pad1    [56]byte // cache line isolation
	readPos  atomic.Uint64
	_pad2    [56]byte // cache line isolation
	capacity uint64
	mask     uint64

	mu            sync.Mutex
	cond          *sync.Cond
	closed        atomic.Bool
	readerWaiting atomic.Bool
	writerWaiting atomic.Bool
}

// NewSPSCSlotRing creates a new lock-free SPSC slot ring with the given
// number of slots (rounded up to the next power of 2, minimum 4).
func NewSPSCSlotRing(slots int) *SPSCSlotRing {
	if slots < 4 {
		slots = 4
	}
	cap := nextPowerOf2(uint64(slots))
	r := &SPSCSlotRing{
		slots:    make([]buf.MultiBuffer, cap),
		capacity: cap,
		mask:     cap - 1,
	}
	r.cond = sync.NewCond(&r.mu)
	return r
}

// TryWrite stores a MultiBuffer in the next slot. Returns false if full.
// Only one goroutine should call TryWrite at a time.
func (r *SPSCSlotRing) TryWrite(mb buf.MultiBuffer) bool {
	wp := r.writePos.Load()
	rp := r.readPos.Load()
	if wp-rp >= r.capacity {
		return false
	}
	r.slots[wp&r.mask] = mb
	r.writePos.Store(wp + 1)
	return true
}

// TryRead retrieves a MultiBuffer from the next slot. Returns nil, false if empty.
// Only one goroutine should call TryRead at a time.
func (r *SPSCSlotRing) TryRead() (buf.MultiBuffer, bool) {
	rp := r.readPos.Load()
	wp := r.writePos.Load()
	if rp >= wp {
		return nil, false
	}
	idx := rp & r.mask
	mb := r.slots[idx]
	r.slots[idx] = nil // help GC
	r.readPos.Store(rp + 1)
	return mb, true
}

// Write stores a MultiBuffer, blocking until space is available or the ring is closed.
func (r *SPSCSlotRing) Write(mb buf.MultiBuffer) bool {
	for {
		if r.closed.Load() {
			return false
		}
		if r.TryWrite(mb) {
			r.mu.Lock()
			r.cond.Signal()
			r.mu.Unlock()
			return true
		}
		// Ring full, wake reader and wait.
		r.mu.Lock()
		r.cond.Signal()
		if !r.closed.Load() && r.Available() == 0 {
			r.writerWaiting.Store(true)
			r.cond.Wait()
			r.writerWaiting.Store(false)
		}
		r.mu.Unlock()
	}
}

// Read retrieves a MultiBuffer, blocking until data is available or the ring is closed.
func (r *SPSCSlotRing) Read() (buf.MultiBuffer, bool) {
	for {
		mb, ok := r.TryRead()
		if ok {
			r.mu.Lock()
			r.cond.Signal()
			r.mu.Unlock()
			return mb, true
		}
		if r.closed.Load() {
			return nil, false
		}
		r.mu.Lock()
		if r.Len() == 0 && !r.closed.Load() {
			r.readerWaiting.Store(true)
			r.cond.Wait()
			r.readerWaiting.Store(false)
		}
		r.mu.Unlock()
	}
}

// Len returns the number of slots currently occupied.
func (r *SPSCSlotRing) Len() int {
	wp := r.writePos.Load()
	rp := r.readPos.Load()
	return int(wp - rp)
}

// Available returns the number of free slots.
func (r *SPSCSlotRing) Available() int {
	return int(r.capacity) - r.Len()
}

// Close marks the ring as closed and wakes all waiters.
func (r *SPSCSlotRing) Close() error {
	r.closed.Store(true)
	r.mu.Lock()
	r.cond.Broadcast()
	r.mu.Unlock()
	return nil
}

func nextPowerOf2(v uint64) uint64 {
	if v == 0 {
		return 1
	}
	if v > 1<<63 {
		return 1 << 63
	}
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
