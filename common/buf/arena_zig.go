//go:build cgo && zig

package buf

/*
#cgo LDFLAGS: -L${SRCDIR}/../../zig/zig-out/lib -lxray_zig
#include "../../zig/zig-out/include/xray_zig.h"
#include <stdlib.h>

typedef struct Arena Arena;
*/
import "C"
import "unsafe"

// ZigArena wraps the Zig arena allocator via CGO.
type ZigArena struct {
	arena *C.Arena
}

// NewZigArena creates a new arena with the given initial size.
func NewZigArena(size int) *ZigArena {
	a := C.xray_arena_create(C.size_t(size))
	if a == nil {
		return nil
	}
	return &ZigArena{arena: a}
}

// Alloc allocates a byte slice from the arena.
func (a *ZigArena) Alloc(size int) []byte {
	ptr := C.xray_arena_alloc(a.arena, C.size_t(size))
	if ptr == nil {
		return nil
	}
	return unsafe.Slice((*byte)(unsafe.Pointer(ptr)), size)
}

// Reset frees all allocations, making the arena available for reuse.
func (a *ZigArena) Reset() {
	C.xray_arena_reset(a.arena)
}

// BytesUsed returns the total bytes allocated.
func (a *ZigArena) BytesUsed() int {
	return int(C.xray_arena_bytes_used(a.arena))
}

// Close destroys the arena.
func (a *ZigArena) Close() {
	if a.arena != nil {
		C.xray_arena_destroy(a.arena)
		a.arena = nil
	}
}
