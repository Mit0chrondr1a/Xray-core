const std = @import("std");
const ring = @import("buffer/ring.zig");
const arena = @import("buffer/arena.zig");

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();

    // Benchmark ring buffer
    {
        var rb = try ring.RingBuffer.init(65536);
        defer rb.deinit();

        var data: [1024]u8 = undefined;
        for (&data) |*b| b.* = 0xAA;

        var timer = try std.time.Timer.start();
        const iterations: usize = 1_000_000;
        for (0..iterations) |_| {
            _ = rb.write(&data);
            var buf: [1024]u8 = undefined;
            _ = rb.read(&buf);
        }
        const elapsed = timer.read();
        const ns_per_op = elapsed / iterations;
        try stdout.print("Ring buffer write+read (1KB): {} ns/op\n", .{ns_per_op});
    }

    // Benchmark arena allocator
    {
        var a = try arena.Arena.init(65536);
        defer a.deinit();

        var timer = try std.time.Timer.start();
        const iterations: usize = 1_000_000;
        for (0..iterations) |_| {
            _ = try a.alloc(256);
            if (a.bytesUsed() > 60000) {
                a.reset();
            }
        }
        const elapsed = timer.read();
        const ns_per_op = elapsed / iterations;
        try stdout.print("Arena alloc (256B): {} ns/op\n", .{ns_per_op});
    }
}
