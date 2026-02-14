//! SK_SKB stream parser — accepts all available data.
//!
//! This is the receive-path parser attached to the SOCKHASH map.
//! It returns skb->len to accept all data in the buffer, telling
//! the kernel to pass the entire segment to the verdict program.

use aya_ebpf::{macros::stream_parser, programs::SkBuffContext};

/// Stream parser: return the full length of the skb to process all data.
#[stream_parser]
pub fn xray_skb_parse(ctx: SkBuffContext) -> u32 {
    ctx.len()
}
