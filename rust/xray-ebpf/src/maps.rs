//! Shared BPF map definitions used by all eBPF programs.
//!
//! These maps are pinned to /sys/fs/bpf/xray/ by the userspace Aya loader
//! for zero-downtime recovery across process restarts.

use aya_ebpf::macros::map;
use aya_ebpf::maps::{LruHashMap, SockHash};

/// SOCKHASH map: socket cookie (u64) -> socket fd.
///
/// Used by SK_SKB verdict and SK_MSG verdict to redirect data between
/// paired sockets. Both programs share this map — SK_SKB handles the
/// receive path, SK_MSG handles the send path.
#[map]
pub static SOCKHASH: SockHash<u64> = SockHash::with_max_entries(crate::maps::MAX_ENTRIES, 0);

/// Policy map: socket cookie (u64) -> policy flags (u32).
///
/// Consulted by verdict programs to decide whether to redirect or pass.
/// Flag bits:
///   bit 0 (POLICY_ALLOW_REDIRECT): allow redirect to paired socket
///   bit 1 (POLICY_USE_INGRESS):    redirect into target's ingress queue
///   bit 2 (POLICY_KTLS_ACTIVE):    at least one socket in the pair is kTLS
#[map]
pub static POLICY_MAP: LruHashMap<u64, u32> =
    LruHashMap::with_max_entries(crate::maps::MAX_ENTRIES, 0);

// Policy flag constants (must match Go's PolicyAllowRedirect etc.)
pub const POLICY_ALLOW_REDIRECT: u32 = 1 << 0;
pub const POLICY_USE_INGRESS: u32 = 1 << 1;
pub const POLICY_KTLS_ACTIVE: u32 = 1 << 2;

/// Cork threshold: batch small writes into chunks of this size.
/// 1400 bytes is just under typical MTU (1500) minus TCP/IP headers,
/// ensuring batched data fits in a single TCP segment.
///
/// Shared by both xray_sk_msg (full) and xray_sk_msg_cork (fallback).
pub const CORK_THRESHOLD: u32 = 1400;
pub const MAX_ENTRIES: u32 = 65_536;
