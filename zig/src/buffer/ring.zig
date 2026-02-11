const std = @import("std");
const atomic = std.atomic;

/// Lock-free Single-Producer Single-Consumer (SPSC) ring buffer.
/// Uses atomic operations for thread-safe communication between exactly
/// one reader and one writer without any locks.
///
/// The buffer capacity is rounded up to the next power of 2 for efficient
/// modular arithmetic using bitwise AND.
pub const RingBuffer = struct {
    buffer: []u8,
    capacity: usize, // always power of 2
    mask: usize, // capacity - 1

    // Cache-line padded to avoid false sharing between producer and consumer.
    // On x86_64, a cache line is 64 bytes.
    write_pos: std.atomic.Value(usize) align(64),
    read_pos: std.atomic.Value(usize) align(64),

    allocator: std.mem.Allocator,

    pub fn init(min_capacity: usize) !*RingBuffer {
        const allocator = std.heap.page_allocator;

        // Round up to next power of 2
        const capacity = nextPowerOf2(if (min_capacity < 16) 16 else min_capacity);

        const buffer = try allocator.alloc(u8, capacity);

        const self = try allocator.create(RingBuffer);
        self.* = RingBuffer{
            .buffer = buffer,
            .capacity = capacity,
            .mask = capacity - 1,
            .write_pos = std.atomic.Value(usize).init(0),
            .read_pos = std.atomic.Value(usize).init(0),
            .allocator = allocator,
        };
        return self;
    }

    pub fn deinit(self: *RingBuffer) void {
        self.allocator.free(self.buffer);
        self.allocator.destroy(self);
    }

    /// Write data into the ring buffer. Returns the number of bytes written.
    /// Only safe to call from a single producer thread.
    pub fn write(self: *RingBuffer, data: []const u8) usize {
        const wp = self.write_pos.load(.monotonic);
        const rp = self.read_pos.load(.acquire);

        const available = self.capacity - (wp - rp);
        const to_write = @min(data.len, available);

        if (to_write == 0) return 0;

        // Write data, handling wrap-around
        const start = wp & self.mask;
        const first_chunk = @min(to_write, self.capacity - start);
        const second_chunk = to_write - first_chunk;

        @memcpy(self.buffer[start..][0..first_chunk], data[0..first_chunk]);
        if (second_chunk > 0) {
            @memcpy(self.buffer[0..second_chunk], data[first_chunk..][0..second_chunk]);
        }

        // Publish write with release semantics
        self.write_pos.store(wp + to_write, .release);
        return to_write;
    }

    /// Read data from the ring buffer. Returns the number of bytes read.
    /// Only safe to call from a single consumer thread.
    pub fn read(self: *RingBuffer, buf: []u8) usize {
        const rp = self.read_pos.load(.monotonic);
        const wp = self.write_pos.load(.acquire);

        const available = wp - rp;
        const to_read = @min(buf.len, available);

        if (to_read == 0) return 0;

        // Read data, handling wrap-around
        const start = rp & self.mask;
        const first_chunk = @min(to_read, self.capacity - start);
        const second_chunk = to_read - first_chunk;

        @memcpy(buf[0..first_chunk], self.buffer[start..][0..first_chunk]);
        if (second_chunk > 0) {
            @memcpy(buf[first_chunk..][0..second_chunk], self.buffer[0..second_chunk]);
        }

        // Publish read with release semantics
        self.read_pos.store(rp + to_read, .release);
        return to_read;
    }

    /// Returns the number of bytes available to read.
    pub fn availableRead(self: *RingBuffer) usize {
        const wp = self.write_pos.load(.acquire);
        const rp = self.read_pos.load(.monotonic);
        return wp - rp;
    }

    /// Returns the number of bytes available to write.
    pub fn availableWrite(self: *RingBuffer) usize {
        const wp = self.write_pos.load(.monotonic);
        const rp = self.read_pos.load(.acquire);
        return self.capacity - (wp - rp);
    }

    fn nextPowerOf2(v: usize) usize {
        var n = v;
        n -= 1;
        n |= n >> 1;
        n |= n >> 2;
        n |= n >> 4;
        n |= n >> 8;
        n |= n >> 16;
        if (@sizeOf(usize) > 4) {
            n |= n >> 32;
        }
        n += 1;
        return n;
    }
};

test "ring buffer basic" {
    var rb = try RingBuffer.init(64);
    defer rb.deinit();

    const data = "Hello, World!";
    const written = rb.write(data);
    try std.testing.expectEqual(data.len, written);
    try std.testing.expectEqual(data.len, rb.availableRead());

    var buf: [64]u8 = undefined;
    const read_n = rb.read(&buf);
    try std.testing.expectEqual(data.len, read_n);
    try std.testing.expectEqualSlices(u8, data, buf[0..read_n]);
}

test "ring buffer wrap around" {
    var rb = try RingBuffer.init(16);
    defer rb.deinit();

    // Fill most of the buffer
    var data1: [12]u8 = undefined;
    for (&data1) |*b| b.* = 0xAA;
    _ = rb.write(&data1);

    // Read it back
    var buf: [12]u8 = undefined;
    _ = rb.read(&buf);

    // Write more data that wraps around
    var data2: [12]u8 = undefined;
    for (&data2, 0..) |*b, i| b.* = @intCast(i);
    _ = rb.write(&data2);

    // Read wrapped data
    var buf2: [12]u8 = undefined;
    const n = rb.read(&buf2);
    try std.testing.expectEqual(@as(usize, 12), n);
    try std.testing.expectEqualSlices(u8, &data2, buf2[0..n]);
}

test "ring buffer full" {
    var rb = try RingBuffer.init(16);
    defer rb.deinit();

    var data: [16]u8 = undefined;
    for (&data) |*b| b.* = 0xFF;

    const written = rb.write(&data);
    try std.testing.expectEqual(@as(usize, 16), written);
    try std.testing.expectEqual(@as(usize, 0), rb.availableWrite());

    // Writing to full buffer returns 0
    try std.testing.expectEqual(@as(usize, 0), rb.write("x"));
}
