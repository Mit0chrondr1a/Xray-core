//! Shared BPF map definitions used by all eBPF programs.
//!
//! These maps are pinned to /sys/fs/bpf/xray/ by the userspace Aya loader
//! for zero-downtime recovery across process restarts.

use aya_ebpf::macros::map;
use aya_ebpf::maps::{HashMap, SockHash};

/// SOCKHASH map: socket cookie (u64) -> socket fd.
///
/// Used by SK_SKB verdict and SK_MSG verdict to redirect data between
/// paired sockets. Both programs share this map — SK_SKB handles the
/// receive path, SK_MSG handles the send path.
#[map]
pub static SOCKHASH: SockHash<u64> = SockHash::with_max_entries(65536, 0);

/// Policy map: socket cookie (u64) -> policy flags (u32).
///
/// Consulted by verdict programs to decide whether to redirect or pass.
/// Flag bits:
///   bit 0 (POLICY_ALLOW_REDIRECT): allow redirect to paired socket
///   bit 1 (POLICY_USE_INGRESS):    redirect into target's ingress queue
///   bit 2 (POLICY_KTLS_ACTIVE):    kTLS is active on both sockets
#[map]
pub static POLICY_MAP: HashMap<u64, u32> = HashMap::with_max_entries(65536, 0);

// Policy flag constants (must match Go's PolicyAllowRedirect etc.)
pub const POLICY_ALLOW_REDIRECT: u32 = 1 << 0;
pub const POLICY_USE_INGRESS: u32 = 1 << 1;
