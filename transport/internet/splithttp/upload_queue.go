package splithttp

// upload_queue is a specialized priorityqueue with condvar-based blocking
// to reorder generic packets by a sequence number.
//
// Design inspired by SPSCSlotRing (transport/pipe/ring_spsc.go): uses
// sync.Mutex + sync.Cond + closed flag + Broadcast() on close. This avoids
// the channel-based deadlock/panic/drop pathologies of the previous design.

import (
	"container/heap"
	"io"
	"sync"

	"github.com/xtls/xray-core/common/errors"
)

type Packet struct {
	Reader  io.ReadCloser
	Payload []byte
	Seq     uint64
}

type uploadQueue struct {
	mu         sync.Mutex
	cond       *sync.Cond
	reader     io.ReadCloser
	nomore     bool
	heap       uploadHeap
	nextSeq    uint64
	closed     bool
	maxPackets int
}

func NewUploadQueue(maxPackets int) *uploadQueue {
	q := &uploadQueue{
		heap:       uploadHeap{},
		maxPackets: maxPackets,
	}
	q.cond = sync.NewCond(&q.mu)
	return q
}

func (h *uploadQueue) Push(p Packet) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	for {
		if h.closed {
			return errors.New("packet queue closed")
		}
		if h.nomore {
			return errors.New("h.reader already exists")
		}
		if p.Reader != nil {
			h.nomore = true
			h.reader = p.Reader
			h.cond.Broadcast()
			return nil
		}
		if h.heap.Len() < h.maxPackets {
			heap.Push(&h.heap, p)
			h.cond.Signal()
			return nil
		}
		// Heap full — block until reader drains or queue closes
		h.cond.Wait()
	}
}

func (h *uploadQueue) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.closed {
		return nil
	}
	h.closed = true
	h.cond.Broadcast()

	if h.reader != nil {
		return h.reader.Close()
	}
	return nil
}

// Read reassembles packets in sequence order. It is NOT goroutine-safe:
// exactly one goroutine (the GET handler) must call Read for a given session.
// This single-reader invariant is guaranteed by the XHTTP protocol design.
func (h *uploadQueue) Read(b []byte) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	for {
		// Stream-up mode: delegate to HTTP body reader
		if h.reader != nil {
			reader := h.reader
			h.mu.Unlock()
			n, err := reader.Read(b)
			h.mu.Lock()
			return n, err
		}

		// Deliver next in-order packet
		if h.heap.Len() > 0 && h.heap[0].Seq == h.nextSeq {
			pkt := heap.Pop(&h.heap).(Packet)
			n := copy(b, pkt.Payload)
			if n < len(pkt.Payload) {
				// Partial read: re-push remainder with same Seq
				pkt.Payload = pkt.Payload[n:]
				heap.Push(&h.heap, pkt)
			} else {
				// Fully consumed: advance sequence and free a slot
				h.nextSeq++
				h.cond.Signal()
			}
			return n, nil
		}

		// Discard stale packets (Seq < nextSeq)
		if h.heap.Len() > 0 && h.heap[0].Seq < h.nextSeq {
			heap.Pop(&h.heap)
			h.cond.Signal()
			continue
		}

		// Heap full of out-of-order packets with a sequence gap.
		// The pusher holding the needed sequence can't push because
		// all slots are occupied. Tear down rather than deadlock.
		if h.heap.Len() >= h.maxPackets {
			return 0, errors.New("packet queue is too large")
		}

		// Queue closed, nothing deliverable
		if h.closed {
			return 0, io.EOF
		}

		// Block waiting for new packets or close
		h.cond.Wait()
	}
}

// heap code directly taken from https://pkg.go.dev/container/heap
type uploadHeap []Packet

func (h uploadHeap) Len() int           { return len(h) }
func (h uploadHeap) Less(i, j int) bool { return h[i].Seq < h[j].Seq }
func (h uploadHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

func (h *uploadHeap) Push(x any) {
	// Push and Pop use pointer receivers because they modify the slice's length,
	// not just its contents.
	*h = append(*h, x.(Packet))
}

func (h *uploadHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}
