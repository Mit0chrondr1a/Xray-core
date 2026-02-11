package buf

// Arena is a bump-pointer arena allocator for per-connection transient allocations.
// All memory is freed at once via Reset() or Close(); individual allocations cannot
// be freed. Allocated slices become invalid after Reset or Close.
// NOT thread-safe: designed for single-goroutine or externally synchronized use.
type Arena struct {
	buffer         []byte
	offset         int
	overflow       [][]byte
	totalAllocated int
}

// NewArena creates a new arena with the given initial size.
func NewArena(size int) *Arena {
	if size < 4096 {
		size = 4096
	}
	return &Arena{
		buffer: make([]byte, size),
	}
}

// Alloc allocates a byte slice from the arena.
func (a *Arena) Alloc(size int) []byte {
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
func (a *Arena) Reset() {
	a.offset = 0
	a.overflow = a.overflow[:0]
	a.totalAllocated = 0
}

// BytesUsed returns total bytes allocated.
func (a *Arena) BytesUsed() int {
	return a.totalAllocated
}

// NewBuffer allocates a Buffer from the arena with the standard buffer size.
// The returned buffer is unmanaged (not returned to sync.Pool on Release).
// Falls back to pool allocation if the arena cannot satisfy the request.
func (a *Arena) NewBuffer() *Buffer {
	slice := a.Alloc(Size)
	if slice == nil {
		return New()
	}
	return &Buffer{
		v:         slice[:Size],
		ownership: unmanaged,
	}
}

// Close releases the arena.
func (a *Arena) Close() {
	a.buffer = nil
	a.overflow = nil
}
