//! SK_SKB stream verdict — receive-path redirect between paired sockets.
//!
//! When data arrives on a socket in the SOCKHASH, this program fires:
//! 1. Gets the receiving socket's cookie via bpf_get_socket_cookie
//! 2. Looks up the cookie in the policy map to check redirect permission
//! 3. If denied (flags & 1 == 0), returns SK_PASS (data to userspace)
//! 4. If allowed, redirects via SOCKHASH to the paired socket

use aya_ebpf::{
    bindings::sk_action::SK_PASS, helpers::bpf_get_socket_cookie, macros::stream_verdict,
    programs::SkBuffContext, EbpfContext,
};

use crate::maps::{
    POLICY_ALLOW_REDIRECT, POLICY_KTLS_ACTIVE, POLICY_MAP, POLICY_USE_INGRESS, SOCKHASH,
};

/// Stream verdict: redirect incoming data to the paired socket.
#[stream_verdict]
pub fn xray_skb_verdict(ctx: SkBuffContext) -> u32 {
    match try_skb_verdict(&ctx) {
        Ok(action) => action,
        Err(_) => SK_PASS,
    }
}

#[inline(always)]
fn try_skb_verdict(ctx: &SkBuffContext) -> Result<u32, ()> {
    let cookie = unsafe { bpf_get_socket_cookie(ctx.as_ptr() as *mut _) };

    // Look up policy for this socket.
    let policy = match unsafe { POLICY_MAP.get(&cookie) } {
        Some(flags) => *flags,
        None => POLICY_ALLOW_REDIRECT, // match Go loader default (allow redirect if missing)
    };

    // Check allow bit.
    if policy & POLICY_ALLOW_REDIRECT == 0 {
        return Ok(SK_PASS);
    }

    // If policy indicates kTLS is active, there is no behavior difference for
    // SK_SKB redirects today, but consulting the bit keeps the kernel data path
    // aligned with the policy schema and allows future kTLS-specific handling
    // (e.g., stats, conditional paths) without map schema changes.
    let _ktls_active = policy & POLICY_KTLS_ACTIVE != 0;

    // Determine redirect flags (ingress vs egress).
    let flags: u64 = if policy & POLICY_USE_INGRESS != 0 {
        1 // BPF_F_INGRESS
    } else {
        0
    };

    // Redirect to paired socket via SOCKHASH lookup.
    let mut key = cookie;
    let _ = SOCKHASH.redirect_skb(ctx, &mut key, flags);
    Ok(SK_PASS)
}
