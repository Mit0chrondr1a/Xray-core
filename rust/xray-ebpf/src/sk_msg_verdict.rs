//! Experimental SK_MSG verdict with cork — not attached in production.
//!
//! The receive-oriented cookie map is not a valid redirect map for ordinary
//! userspace writes, which already target their correct egress socket. The Aya
//! loader therefore leaves this program unloaded and unattached.
//!
//! New admission is raw-TCP only. The legacy kTLS policy bit remains in the
//! map ABI but is never set by current userspace.
//!
//! Flow:
//!   App sendmsg() -> SK_MSG verdict:
//!     if msg.size < CORK_THRESHOLD: cork_bytes(CORK_THRESHOLD), return SK_PASS
//!     else: look up redirect target, msg_redirect_hash() -> paired socket

use aya_ebpf::{
    bindings::sk_action::SK_PASS,
    helpers::{bpf_get_socket_cookie, bpf_msg_cork_bytes},
    macros::sk_msg,
    programs::SkMsgContext,
};

use crate::maps::{
    CORK_THRESHOLD, POLICY_ALLOW_REDIRECT, POLICY_KTLS_ACTIVE, POLICY_MAP, POLICY_USE_INGRESS,
    SOCKHASH,
};

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

    // Batched data ready — look up redirect target.
    let cookie = unsafe { bpf_get_socket_cookie(ctx.msg as *mut _) };

    let policy = match unsafe { POLICY_MAP.get(&cookie) } {
        Some(flags) => *flags,
        None => 0, // fail closed: an absent policy must pass to userspace
    };

    if policy & POLICY_ALLOW_REDIRECT == 0 {
        return Ok(SK_PASS);
    }

    // Cork small writes only when kTLS is active (ciphertext path) — this avoids
    // lengthening Nagle/latency for plain TCP while preserving MTU-sized batching
    // benefits on encrypted kTLS flows.
    if policy & POLICY_KTLS_ACTIVE != 0 && size < CORK_THRESHOLD {
        let ret = unsafe { bpf_msg_cork_bytes(ctx.msg as *mut _, CORK_THRESHOLD) };
        if ret == 0 {
            return Ok(SK_PASS);
        }
        // If cork fails (e.g., not supported), fall through to redirect.
    }

    let flags: u64 = if policy & POLICY_USE_INGRESS != 0 {
        1 // BPF_F_INGRESS
    } else {
        0
    };

    // Redirect the message to the paired socket.
    let mut key = cookie;
    let _ = SOCKHASH.redirect_msg(ctx, &mut key, flags);
    Ok(SK_PASS)
}
