//go:build cgo && zig

package pipe

/*
#cgo LDFLAGS: -L${SRCDIR}/../../zig/zig-out/lib -lxray_zig
#include "../../zig/zig-out/include/xray_zig.h"
#include <stdlib.h>

typedef struct RingBuffer RingBuffer;
*/
import "C"
import "unsafe"

// ZigRingBuffer wraps the Zig SPSC ring buffer via CGO.
type ZigRingBuffer struct {
	rb *C.RingBuffer
}

// NewZigRingBuffer creates a new lock-free SPSC ring buffer.
func NewZigRingBuffer(capacity int) *ZigRingBuffer {
	rb := C.xray_ring_create(C.size_t(capacity))
	if rb == nil {
		return nil
	}
	return &ZigRingBuffer{rb: rb}
}

// Write writes data to the ring buffer. Returns the number of bytes written.
func (r *ZigRingBuffer) Write(data []byte) int {
	if len(data) == 0 {
		return 0
	}
	return int(C.xray_ring_write(r.rb, (*C.uchar)(unsafe.Pointer(&data[0])), C.size_t(len(data))))
}

// Read reads data from the ring buffer. Returns the number of bytes read.
func (r *ZigRingBuffer) Read(buf []byte) int {
	if len(buf) == 0 {
		return 0
	}
	return int(C.xray_ring_read(r.rb, (*C.uchar)(unsafe.Pointer(&buf[0])), C.size_t(len(buf))))
}

// AvailableRead returns bytes available to read.
func (r *ZigRingBuffer) AvailableRead() int {
	return int(C.xray_ring_available_read(r.rb))
}

// AvailableWrite returns bytes available to write.
func (r *ZigRingBuffer) AvailableWrite() int {
	return int(C.xray_ring_available_write(r.rb))
}

// Close releases the ring buffer.
func (r *ZigRingBuffer) Close() {
	if r.rb != nil {
		C.xray_ring_destroy(r.rb)
		r.rb = nil
	}
}
