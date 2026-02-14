//! Stub eBPF exports when `ebpf-bytecode` is disabled.
//!
//! These symbols are always exported so CGO link succeeds, while callers can
//! probe availability and fall back to the Go eBPF path.

use std::ffi::c_char;

#[no_mangle]
pub extern "C" fn xray_ebpf_available() -> i32 {
    0
}

#[no_mangle]
pub unsafe extern "C" fn xray_ebpf_setup(
    _pin_path: *const c_char,
    _max_entries: u32,
    _cork_threshold: u32,
) -> i32 {
    -libc::ENOTSUP
}

#[no_mangle]
pub extern "C" fn xray_ebpf_teardown() -> i32 {
    -libc::ENOTSUP
}

#[no_mangle]
pub extern "C" fn xray_ebpf_register_pair(
    _inbound_fd: i32,
    _outbound_fd: i32,
    _inbound_cookie: u64,
    _outbound_cookie: u64,
    _policy_flags: u32,
) -> i32 {
    -libc::ENOTSUP
}

#[no_mangle]
pub extern "C" fn xray_ebpf_unregister_pair(_inbound_cookie: u64, _outbound_cookie: u64) -> i32 {
    -libc::ENOTSUP
}
