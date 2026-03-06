//! Cork-only SK_MSG fallback — batching without cookie lookup or redirect.
//!
//! This program is loaded when the kernel rejects `bpf_get_socket_cookie`
//! inside `BPF_PROG_TYPE_SK_MSG` (observed on kernel 6.18.13). It provides
//! the cork batching benefit (coalescing small writes into MTU-sized chunks)
//! without the send-path redirect that requires the cookie helper.
//!
//! Receive-path redirect via SK_SKB is unaffected — data flows normally.

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
