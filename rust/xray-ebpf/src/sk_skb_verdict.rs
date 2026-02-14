//! SK_SKB stream verdict — receive-path redirect between paired sockets.
//!
//! When data arrives on a socket in the SOCKHASH, this program fires:
//! 1. Gets the receiving socket's cookie via bpf_get_socket_cookie
//! 2. Looks up the cookie in the policy map to check redirect permission
//! 3. If denied (flags & 1 == 0), returns SK_PASS (data to userspace)
//! 4. If allowed, redirects via SOCKHASH to the paired socket

use aya_ebpf::{
    bindings::SK_PASS,
    helpers::bpf_get_socket_cookie,
    macros::sk_skb,
    programs::SkSkbContext,
};

use crate::maps::{POLICY_MAP, SOCKHASH, POLICY_ALLOW_REDIRECT, POLICY_USE_INGRESS};

/// Stream verdict: redirect incoming data to the paired socket.
#[sk_skb]
pub fn xray_skb_verdict(ctx: SkSkbContext) -> u32 {
    match try_skb_verdict(&ctx) {
        Ok(action) => action,
        Err(_) => SK_PASS,
    }
}

#[inline(always)]
fn try_skb_verdict(ctx: &SkSkbContext) -> Result<u32, ()> {
    let cookie = unsafe { bpf_get_socket_cookie(ctx.skb as *mut _) };

    // Look up policy for this socket.
    let policy = match unsafe { POLICY_MAP.get(&cookie) } {
        Some(flags) => *flags,
        // Default: allow redirect (backward compat with entries that have
        // no explicit policy — e.g. older Go code that only writes SOCKHASH).
        None => POLICY_ALLOW_REDIRECT,
    };

    // Check allow bit.
    if policy & POLICY_ALLOW_REDIRECT == 0 {
        return Ok(SK_PASS);
    }

    // Determine redirect flags (ingress vs egress).
    let flags: u64 = if policy & POLICY_USE_INGRESS != 0 {
        1 // BPF_F_INGRESS
    } else {
        0
    };

    // Redirect to paired socket via SOCKHASH lookup.
    match SOCKHASH.redirect_skb(ctx, &cookie, flags) {
        Ok(_) => Ok(SK_PASS),
        Err(_) => Ok(SK_PASS), // on redirect failure, pass to userspace
    }
}
