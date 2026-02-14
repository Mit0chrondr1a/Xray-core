//! SK_MSG verdict with cork — send-path batching for small writes.
//!
//! This program attaches to the SOCKHASH alongside SK_SKB programs.
//! They serve complementary paths:
//!   - SK_SKB: receive path — redirects incoming data between sockets
//!   - SK_MSG: send path — batches outgoing writes before they hit the wire
//!
//! When kTLS is active, SK_MSG fires AFTER kernel encryption. Cork batches
//! ciphertext TLS records into MTU-sized chunks, reducing TCP segment count
//! and verdict invocations on the remote peer.
//!
//! Flow:
//!   App sendmsg() -> SK_MSG verdict:
//!     if msg.size < CORK_THRESHOLD: cork_bytes(CORK_THRESHOLD), return SK_PASS
//!     else: look up redirect target, msg_redirect_hash() -> paired socket

use aya_ebpf::{
    bindings::SK_PASS,
    helpers::{bpf_get_socket_cookie, bpf_msg_cork_bytes},
    macros::sk_msg,
    programs::SkMsgContext,
};

use crate::maps::{POLICY_MAP, SOCKHASH, POLICY_ALLOW_REDIRECT, POLICY_USE_INGRESS};

/// Cork threshold: batch small writes into chunks of this size.
/// 1400 bytes is just under typical MTU (1500) minus TCP/IP headers,
/// ensuring batched data fits in a single TCP segment.
const CORK_THRESHOLD: u32 = 1400;

/// SK_MSG verdict: cork small writes and redirect batched data.
#[sk_msg]
pub fn xray_sk_msg(ctx: SkMsgContext) -> u32 {
    match try_sk_msg(&ctx) {
        Ok(action) => action,
        Err(_) => SK_PASS,
    }
}

#[inline(always)]
fn try_sk_msg(ctx: &SkMsgContext) -> Result<u32, ()> {
    let size = unsafe { (*ctx.msg).size } as u32;

    // Cork small writes to batch into MTU-sized chunks.
    if size < CORK_THRESHOLD {
        let ret = unsafe { bpf_msg_cork_bytes(ctx.msg as *mut _, CORK_THRESHOLD) };
        if ret == 0 {
            return Ok(SK_PASS);
        }
        // If cork fails (e.g., not supported), fall through to redirect.
    }

    // Batched data ready — look up redirect target.
    let cookie = unsafe { bpf_get_socket_cookie(ctx.msg as *mut _) };

    let policy = match unsafe { POLICY_MAP.get(&cookie) } {
        Some(flags) => *flags,
        None => POLICY_ALLOW_REDIRECT,
    };

    if policy & POLICY_ALLOW_REDIRECT == 0 {
        return Ok(SK_PASS);
    }

    let flags: u64 = if policy & POLICY_USE_INGRESS != 0 {
        1 // BPF_F_INGRESS
    } else {
        0
    };

    // Redirect the message to the paired socket.
    let _ = SOCKHASH.redirect_msg(ctx, &cookie, flags);
    Ok(SK_PASS)
}
