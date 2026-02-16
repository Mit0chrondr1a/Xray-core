use std::env;
use std::path::Path;

fn main() {
    // 1. Locate the eBPF artifact from the sibling crate
    let bpf_path = Path::new("../xray-ebpf/target/bpfel-unknown-none/release/xray-ebpf");

    // 2. Force rebuild if the binary changes (Staleness Fix)
    if bpf_path.exists() {
        println!("cargo:rerun-if-changed={}", bpf_path.display());
    } else {
        // Warn if missing but feature enabled
        if env::var("CARGO_FEATURE_EBPF_BYTECODE").is_ok() {
            println!("cargo:warning=eBPF bytecode not found at {}", bpf_path.display());
        }
    }

    // 3. Track source changes for safety
    println!("cargo:rerun-if-changed=../xray-ebpf/src");
}