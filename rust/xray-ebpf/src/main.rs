//! Xray eBPF programs — compiled for bpfel-unknown-none target.
//!
//! Contains four programs attached to a shared SOCKHASH map:
//!   - xray_skb_parse:    SK_SKB stream parser (accept all data)
//!   - xray_skb_verdict:  SK_SKB stream verdict (receive-path redirect)
//!   - xray_sk_msg:       SK_MSG verdict (send-path cork + redirect)
//!   - xray_sk_msg_cork:  SK_MSG cork-only fallback (batching, no redirect)

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
