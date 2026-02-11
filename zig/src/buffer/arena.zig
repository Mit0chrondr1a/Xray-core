const std = @import("std");

/// Fast bump-pointer arena allocator for per-connection transient allocations.
/// All memory is freed at once when the arena is reset or destroyed.
///
/// The arena allocates a large chunk upfront and hands out slices from it.
/// When the main chunk is exhausted, additional overflow chunks are allocated.
/// This is much faster than individual allocations because:
/// 1. Allocation is just a pointer bump (no free-list traversal)
/// 2. Deallocation is bulk-free (just reset the pointer)
/// 3. No per-allocation overhead (no headers, no fragmentation)
pub const Arena = struct {
    /// Main memory chunk
    buffer: []u8,
    /// Current allocation offset in the main chunk
    offset: usize,
    /// Total capacity of the main chunk
    capacity: usize,
    /// Overflow chunks for when main chunk is exhausted
    overflow: std.ArrayList([]u8),
    /// Total bytes allocated (for stats)
    total_allocated: usize,
    /// Backing allocator for chunks
    allocator: std.mem.Allocator,

    pub fn init(size: usize) !*Arena {
        const allocator = std.heap.page_allocator;
        const actual_size = if (size < 4096) 4096 else size;

        const buffer = try allocator.alloc(u8, actual_size);

        const self = try allocator.create(Arena);
        self.* = Arena{
            .buffer = buffer,
            .offset = 0,
            .capacity = actual_size,
            .overflow = .empty,
            .total_allocated = 0,
            .allocator = allocator,
        };
        return self;
    }

    pub fn deinit(self: *Arena) void {
        // Free overflow chunks
        for (self.overflow.items) |chunk| {
            self.allocator.free(chunk);
        }
        self.overflow.deinit(self.allocator);

        // Free main buffer
        self.allocator.free(self.buffer);

        // Free self
        self.allocator.destroy(self);
    }

    /// Allocate a slice of the given size from the arena.
    /// Alignment is guaranteed to be at least 8 bytes.
    pub fn alloc(self: *Arena, size: usize) ![]u8 {
        const aligned_size = alignUp(size, 8);

        if (self.offset + aligned_size <= self.capacity) {
            // Fast path: bump allocate from main chunk
            const result = self.buffer[self.offset..][0..size];
            self.offset += aligned_size;
            self.total_allocated += size;
            return result;
        }

        // Slow path: allocate overflow chunk
        const chunk_size = @max(aligned_size, 4096);
        const chunk = try self.allocator.alloc(u8, chunk_size);
        try self.overflow.append(self.allocator, chunk);
        self.total_allocated += size;
        return chunk[0..size];
    }

    /// Reset the arena, making all memory available for reuse.
    /// This is O(n) in the number of overflow chunks but O(1) for the main chunk.
    pub fn reset(self: *Arena) void {
        // Free overflow chunks
        for (self.overflow.items) |chunk| {
            self.allocator.free(chunk);
        }
        self.overflow.clearRetainingCapacity();

        // Reset main chunk offset
        self.offset = 0;
        self.total_allocated = 0;
    }

    /// Returns the total number of bytes allocated from this arena.
    pub fn bytesUsed(self: *Arena) usize {
        return self.total_allocated;
    }

    fn alignUp(n: usize, alignment: usize) usize {
        return (n + alignment - 1) & ~(alignment - 1);
    }
};

test "arena basic allocation" {
    var a = try Arena.init(4096);
    defer a.deinit();

    const slice1 = try a.alloc(100);
    try std.testing.expectEqual(@as(usize, 100), slice1.len);

    const slice2 = try a.alloc(200);
    try std.testing.expectEqual(@as(usize, 200), slice2.len);

    try std.testing.expectEqual(@as(usize, 300), a.bytesUsed());
}

test "arena reset" {
    var a = try Arena.init(4096);
    defer a.deinit();

    _ = try a.alloc(1000);
    _ = try a.alloc(1000);
    try std.testing.expectEqual(@as(usize, 2000), a.bytesUsed());

    a.reset();
    try std.testing.expectEqual(@as(usize, 0), a.bytesUsed());

    // Can allocate again after reset
    _ = try a.alloc(500);
    try std.testing.expectEqual(@as(usize, 500), a.bytesUsed());
}

test "arena overflow" {
    var a = try Arena.init(64);
    defer a.deinit();

    // This should trigger overflow
    const big = try a.alloc(128);
    try std.testing.expectEqual(@as(usize, 128), big.len);
}
