//! Experimental cork-only SK_MSG fallback — not attached in production.
//!
//! Retained as a future experiment only. Production does not attach it because
//! corking a short userspace write without a guaranteed follow-up can retain
//! that write indefinitely.

use aya_ebpf::{
    bindings::sk_action::SK_PASS, helpers::bpf_msg_cork_bytes, macros::sk_msg,
    programs::SkMsgContext,
};

use crate::maps::CORK_THRESHOLD;

/// Cork-only SK_MSG verdict: batch small writes, no redirect.
#[sk_msg]
pub fn xray_sk_msg_cork(ctx: SkMsgContext) -> u32 {
    let size = unsafe { (*ctx.msg).size } as u32;
    if size < CORK_THRESHOLD {
        let _ = unsafe { bpf_msg_cork_bytes(ctx.msg as *mut _, CORK_THRESHOLD) };
    }
    SK_PASS
}
