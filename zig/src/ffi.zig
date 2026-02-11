const std = @import("std");
const ring = @import("buffer/ring.zig");
const arena = @import("buffer/arena.zig");

// ===== Ring Buffer FFI =====

export fn xray_ring_create(capacity: usize) ?*ring.RingBuffer {
    return ring.RingBuffer.init(capacity) catch null;
}

export fn xray_ring_destroy(rb: *ring.RingBuffer) void {
    rb.deinit();
}

export fn xray_ring_write(rb: *ring.RingBuffer, data: [*]const u8, len: usize) usize {
    return rb.write(data[0..len]);
}

export fn xray_ring_read(rb: *ring.RingBuffer, buf: [*]u8, len: usize) usize {
    return rb.read(buf[0..len]);
}

export fn xray_ring_available_read(rb: *ring.RingBuffer) usize {
    return rb.availableRead();
}

export fn xray_ring_available_write(rb: *ring.RingBuffer) usize {
    return rb.availableWrite();
}

// ===== Arena Allocator FFI =====

export fn xray_arena_create(size: usize) ?*arena.Arena {
    return arena.Arena.init(size) catch null;
}

export fn xray_arena_destroy(a: *arena.Arena) void {
    a.deinit();
}

export fn xray_arena_alloc(a: *arena.Arena, size: usize) ?[*]u8 {
    const slice = a.alloc(size) catch return null;
    return slice.ptr;
}

export fn xray_arena_reset(a: *arena.Arena) void {
    a.reset();
}

export fn xray_arena_bytes_used(a: *arena.Arena) usize {
    return a.bytesUsed();
}

test {
    std.testing.refAllDecls(@This());
    _ = ring;
    _ = arena;
}
