//! Shared pipeline contract types for REALITY/Vision handoff.
//! This module defines stable, FFI-safe enums/structs for the Go<->Rust boundary.
//! It is intentionally narrow and side-effect free to keep the data plane simple.

#![allow(non_camel_case_types)]

use crate::ebpf::xray_ebpf_available;
use crate::ktls_probe;

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum XrayState {
    INIT = 0,
    PEEK = 1,
    PAD_WAIT = 2,
    DETACH = 3,
    ZERO_COPY = 4,
    FALLBACK = 5,
    CLOSED = 6,
    FATAL = 7,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum XrayErrorClass {
    NONE = 0,
    TIMEOUT = 1,
    REFUSED = 2,
    NO_ROUTE = 3,
    FATAL = 4,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct XrayPeekResult {
    pub state: XrayState,
    pub err: XrayErrorClass,
    pub retries: u16,
    pub elapsed_ns: u64,
}

impl XrayPeekResult {
    pub fn ok(state: XrayState, retries: u16, elapsed_ns: u64) -> Self {
        Self {
            state,
            err: XrayErrorClass::NONE,
            retries,
            elapsed_ns,
        }
    }

    pub fn err(class: XrayErrorClass, retries: u16, elapsed_ns: u64) -> Self {
        Self {
            state: XrayState::FATAL,
            err: class,
            retries,
            elapsed_ns,
        }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct XrayCapabilitySummary {
    pub ktls_supported: bool,
    pub sockmap_supported: bool,
    pub splice_supported: bool,
}

impl Default for XrayCapabilitySummary {
    fn default() -> Self {
        Self {
            ktls_supported: false,
            sockmap_supported: false,
            splice_supported: true,
        }
    }
}

/// FFI entrypoint: expose a cached capability summary to Go.
///
/// The initial implementation returns a static best-effort summary to keep the
/// contract stable while the caller is wired up. Future versions should populate
/// this from a single startup probe and cached struct.
#[no_mangle]
pub extern "C" fn xray_capabilities_summary(out: *mut XrayCapabilitySummary) -> i32 {
    unsafe {
        if out.is_null() {
            return crate::ffi::FFI_ERR_NULL;
        }
        #[cfg(target_os = "linux")]
        {
            let mut summary = XrayCapabilitySummary::default();
            summary.splice_supported = true;
            summary.sockmap_supported = xray_ebpf_available() != 0;
            summary.ktls_supported = ktls_probe::probe_ktls_support();
            *out = summary;
        }
        #[cfg(not(target_os = "linux"))]
        {
            *out = XrayCapabilitySummary::default();
        }
    }
    crate::ffi::FFI_OK
}
