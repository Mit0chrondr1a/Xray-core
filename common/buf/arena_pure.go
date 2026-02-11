//go:build !cgo || !zig

package buf

// ZigArena is a pure Go fallback arena allocator.
// Uses a simple bump-pointer allocation strategy.
type ZigArena struct {
	buffer         []byte
	offset         int
	overflow       [][]byte
	totalAllocated int
}

// NewZigArena creates a new arena with the given initial size.
func NewZigArena(size int) *ZigArena {
	if size < 4096 {
		size = 4096
	}
	return &ZigArena{
		buffer: make([]byte, size),
	}
}

// Alloc allocates a byte slice from the arena.
func (a *ZigArena) Alloc(size int) []byte {
	aligned := (size + 7) &^ 7 // align to 8 bytes

	if a.offset+aligned <= len(a.buffer) {
		// Fast path: bump allocate
		result := a.buffer[a.offset : a.offset+size]
		a.offset += aligned
		a.totalAllocated += size
		return result
	}

	// Slow path: overflow
	chunkSize := aligned
	if chunkSize < 4096 {
		chunkSize = 4096
	}
	chunk := make([]byte, chunkSize)
	a.overflow = append(a.overflow, chunk)
	a.totalAllocated += size
	return chunk[:size]
}

// Reset frees all allocations.
func (a *ZigArena) Reset() {
	a.offset = 0
	a.overflow = a.overflow[:0]
	a.totalAllocated = 0
}

// BytesUsed returns total bytes allocated.
func (a *ZigArena) BytesUsed() int {
	return a.totalAllocated
}

// Close releases the arena.
func (a *ZigArena) Close() {
	a.buffer = nil
	a.overflow = nil
}
