const std = @import("std");

pub fn build(b: *std.Build) void {
    // Standard target options
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Build the static library for CGO linking
    const lib = b.addStaticLibrary(.{
        .name = "xray_zig",
        .root_source_file = b.path("src/ffi.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Enable SIMD optimizations
    lib.root_module.addCMacro("ZIG_ENABLE_SIMD", "1");

    // For release builds, enable all optimizations
    if (optimize != .Debug) {
        lib.root_module.strip = true;
    }

    // Install the library
    b.installArtifact(lib);

    // Generate C header for FFI
    const header = lib.getEmittedH();
    const install_header = b.addInstallFile(header, "include/xray_zig.h");
    b.getInstallStep().dependOn(&install_header.step);

    // Unit tests
    const unit_tests = b.addTest(.{
        .root_source_file = b.path("src/ffi.zig"),
        .target = target,
        .optimize = optimize,
    });

    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);

    // Benchmarks
    const bench = b.addExecutable(.{
        .name = "bench",
        .root_source_file = b.path("src/bench.zig"),
        .target = target,
        .optimize = .ReleaseFast,
    });
    b.installArtifact(bench);

    const run_bench = b.addRunArtifact(bench);
    const bench_step = b.step("bench", "Run benchmarks");
    bench_step.dependOn(&run_bench.step);
}
