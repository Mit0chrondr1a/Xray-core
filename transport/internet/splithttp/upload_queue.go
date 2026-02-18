package splithttp

// upload_queue is a specialized priorityqueue + channel to reorder generic
// packets by a sequence number

import (
	"container/heap"
	"io"
	"sync"
	"sync/atomic"

	"github.com/xtls/xray-core/common/errors"
)

type Packet struct {
	Reader  io.ReadCloser
	Payload []byte
	Seq     uint64
}

type uploadQueue struct {
	reader          io.ReadCloser
	nomore          bool
	pushedPackets   chan Packet
	writeCloseMutex sync.Mutex
	heap            uploadHeap
	nextSeq         uint64
	closed          atomic.Bool
	maxPackets      int
}

func NewUploadQueue(maxPackets int) *uploadQueue {
	return &uploadQueue{
		pushedPackets: make(chan Packet, maxPackets),
		heap:          uploadHeap{},
		nextSeq:       0,
		maxPackets:    maxPackets,
	}
}

func (h *uploadQueue) Push(p Packet) error {
	h.writeCloseMutex.Lock()

	if h.closed.Load() {
		h.writeCloseMutex.Unlock()
		return errors.New("packet queue closed")
	}
	if h.nomore {
		h.writeCloseMutex.Unlock()
		return errors.New("h.reader already exists")
	}
	if p.Reader != nil {
		h.nomore = true
	}
	// Release the mutex BEFORE the channel send to prevent deadlock.
	// If the channel is full, a blocking send while holding the mutex would
	// prevent Close() from ever acquiring the mutex and draining the channel.
	h.writeCloseMutex.Unlock()

	select {
	case h.pushedPackets <- p:
		return nil
	default:
		// Channel is full -- backpressure. Non-blocking to avoid deadlock.
		return errors.New("packet queue is full")
	}
}

func (h *uploadQueue) Close() error {
	h.writeCloseMutex.Lock()
	defer h.writeCloseMutex.Unlock()

	if !h.closed.Load() {
		h.closed.Store(true)
		// Drain any buffered packets from the channel before closing it.
		// Push() releases the mutex before sending (non-blocking select), so
		// there is no deadlock risk here. We drain in a loop to collect any
		// packets that were enqueued before we set closed=true.
	drain:
		for {
			select {
			case p := <-h.pushedPackets:
				if p.Reader != nil {
					if h.reader != nil {
						h.reader.Close()
					}
					h.reader = p.Reader
				}
			default:
				break drain
			}
		}
		close(h.pushedPackets)
	}
	if h.reader != nil {
		return h.reader.Close()
	}
	return nil
}

// Read reassembles packets in sequence order. It is NOT goroutine-safe:
// exactly one goroutine (the GET handler) must call Read for a given session.
// This single-reader invariant is guaranteed by the XHTTP protocol design.
func (h *uploadQueue) Read(b []byte) (int, error) {
	if h.reader != nil {
		return h.reader.Read(b)
	}

	if h.closed.Load() {
		return 0, io.EOF
	}

	if len(h.heap) == 0 {
		packet, more := <-h.pushedPackets
		if !more {
			return 0, io.EOF
		}
		if packet.Reader != nil {
			h.reader = packet.Reader
			return h.reader.Read(b)
		}
		heap.Push(&h.heap, packet)
	}

	for len(h.heap) > 0 {
		packet := heap.Pop(&h.heap).(Packet)
		n := 0

		if packet.Seq == h.nextSeq {
			copy(b, packet.Payload)
			n = min(len(b), len(packet.Payload))

			if n < len(packet.Payload) {
				// partial read
				packet.Payload = packet.Payload[n:]
				heap.Push(&h.heap, packet)
			} else {
				h.nextSeq = packet.Seq + 1
			}

			return n, nil
		}

		// misordered packet
		if packet.Seq > h.nextSeq {
			if len(h.heap) > h.maxPackets {
				// the "reassembly buffer" is too large, and we want to
				// constrain memory usage somehow. let's tear down the
				// connection, and hope the application retries.
				return 0, errors.New("packet queue is too large")
			}
			heap.Push(&h.heap, packet)
			packet2, more := <-h.pushedPackets
			if !more {
				return 0, io.EOF
			}
			heap.Push(&h.heap, packet2)
		}
	}

	return 0, nil
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
