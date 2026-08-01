//! Xray eBPF programs — compiled for bpfel-unknown-none target.
//!
//! Contains four program entry points backed by a shared SOCKHASH map:
//!   - xray_skb_parse:    SK_SKB stream parser (accept all data)
//!   - xray_skb_verdict:  SK_SKB stream verdict (receive-path redirect)
//!   - xray_sk_msg:       experimental SK_MSG verdict (unattached)
//!   - xray_sk_msg_cork:  experimental SK_MSG cork fallback (unattached)
//!
//! The production Aya loader attaches only the two SK_SKB programs. The pair
//! map points from a receiving socket to its peer; using the same mapping on an
//! ordinary userspace send would reverse the intended destination.

#![no_std]
#![no_main]

mod maps;
mod sk_msg_cork_only;
mod sk_msg_verdict;
mod sk_skb_parser;
mod sk_skb_verdict;

// Re-export program entry points so Aya can discover them.
pub use sk_msg_cork_only::xray_sk_msg_cork;
pub use sk_msg_verdict::xray_sk_msg;
pub use sk_skb_parser::xray_skb_parse;
pub use sk_skb_verdict::xray_skb_verdict;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
