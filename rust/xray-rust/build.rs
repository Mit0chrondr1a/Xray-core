fn main() {
    // When the ebpf-bytecode feature is enabled, ebpf.rs embeds the compiled
    // eBPF binary via include_bytes!. Tell cargo to rebuild whenever that
    // file changes so a stale bytecode can never be silently linked in.
    #[cfg(feature = "ebpf-bytecode")]
    println!(
        "cargo:rerun-if-changed=../xray-ebpf/target/bpfel-unknown-none/release/xray-ebpf"
    );
}
