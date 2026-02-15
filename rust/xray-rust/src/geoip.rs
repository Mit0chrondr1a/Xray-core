use std::slice;

const EMPTY: u32 = u32::MAX;

/// A node in the flat-array radix trie for IP prefix matching.
/// Stored contiguously in a Vec for cache-friendly traversal.
#[repr(C)]
struct FlatNode {
    children: [u32; 2], // indices into the nodes Vec, EMPTY = absent
    is_prefix: bool,
}

/// A binary trie backed by a flat array for fast IP prefix set membership testing.
/// All nodes live in a single contiguous allocation, eliminating pointer chasing
/// and improving cache locality compared to a pointer-based trie.
struct PrefixTrie {
    nodes: Vec<FlatNode>,
}

impl PrefixTrie {
    fn new() -> Self {
        let mut nodes = Vec::with_capacity(4096);
        nodes.push(FlatNode {
            children: [EMPTY, EMPTY],
            is_prefix: false,
        });
        PrefixTrie { nodes }
    }

    /// Insert a prefix (ip_bytes, prefix_bits) into the trie.
    fn insert(&mut self, ip_bytes: &[u8], prefix_bits: u8) {
        let total_bits = prefix_bits as usize;
        if total_bits > ip_bytes.len() * 8 {
            return;
        }
        let mut idx = 0u32;

        for i in 0..total_bits {
            // If current node is already a prefix, any longer prefix is redundant.
            if self.nodes[idx as usize].is_prefix {
                return;
            }

            let byte_idx = i / 8;
            let bit_idx = 7 - (i % 8);
            let bit = ((ip_bytes[byte_idx] >> bit_idx) & 1) as usize;

            let child_idx = self.nodes[idx as usize].children[bit];
            if child_idx == EMPTY {
                let new_idx = self.nodes.len() as u32;
                self.nodes.push(FlatNode {
                    children: [EMPTY, EMPTY],
                    is_prefix: false,
                });
                self.nodes[idx as usize].children[bit] = new_idx;
                idx = new_idx;
            } else {
                idx = child_idx;
            }
        }
        self.nodes[idx as usize].is_prefix = true;
        // Prune children since this node covers everything below.
        self.nodes[idx as usize].children = [EMPTY, EMPTY];
    }

    /// Check if an IP address is contained in any prefix in the trie.
    fn contains(&self, ip_bytes: &[u8], total_bits: usize) -> bool {
        let nodes = self.nodes.as_slice();
        let mut idx = 0u32;

        if nodes[0].is_prefix {
            return true;
        }

        for i in 0..total_bits {
            let byte_idx = i / 8;
            let bit_idx = 7 - (i % 8);
            let bit = ((ip_bytes[byte_idx] >> bit_idx) & 1) as usize;

            let child_idx = nodes[idx as usize].children[bit];
            if child_idx == EMPTY {
                return false;
            }
            idx = child_idx;
            if nodes[idx as usize].is_prefix {
                return true;
            }
        }

        false
    }

    /// Shrink internal storage to fit after all insertions are done.
    fn shrink_to_fit(&mut self) {
        self.nodes.shrink_to_fit();
    }
}

/// IpSet holds separate IPv4 and IPv6 prefix tries plus max prefix lengths
/// for the heuristic bucketing optimization in Go.
pub struct IpSet {
    ipv4: PrefixTrie,
    ipv6: PrefixTrie,
    max4: u8,
    max6: u8,
}

impl IpSet {
    fn new() -> Self {
        IpSet {
            ipv4: PrefixTrie::new(),
            ipv6: PrefixTrie::new(),
            max4: 0,
            max6: 0,
        }
    }

    /// Create a new IpSet (crate-visible for geodata module).
    pub(crate) fn new_internal() -> Self {
        Self::new()
    }

    /// Add a prefix (crate-visible for geodata module).
    pub(crate) fn add_prefix(&mut self, ip_bytes: &[u8], prefix_bits: u8) {
        match ip_bytes.len() {
            4 if prefix_bits <= 32 => {
                self.ipv4.insert(ip_bytes, prefix_bits);
                if prefix_bits > self.max4 {
                    self.max4 = prefix_bits;
                }
            }
            16 if prefix_bits <= 128 => {
                self.ipv6.insert(ip_bytes, prefix_bits);
                if prefix_bits > self.max6 {
                    self.max6 = prefix_bits;
                }
            }
            _ => {}
        }
    }

    /// Finalize (crate-visible for geodata module).
    pub(crate) fn build(&mut self) {
        self.ipv4.shrink_to_fit();
        self.ipv6.shrink_to_fit();
    }

    /// Check containment (crate-visible for geodata module tests).
    pub(crate) fn contains_ip(&self, ip_bytes: &[u8]) -> bool {
        match ip_bytes.len() {
            4 => self.ipv4.contains(ip_bytes, 32),
            16 => self.ipv6.contains(ip_bytes, 128),
            _ => false,
        }
    }
}

/// Create a new empty IP set.
#[no_mangle]
pub extern "C" fn xray_ipset_new() -> *mut IpSet {
    ffi_catch_ptr!({
        Box::into_raw(Box::new(IpSet::new()))
    })
}

/// Add a CIDR prefix to the IP set.
///
/// `ip_bytes`: 4 bytes for IPv4, 16 bytes for IPv6.
/// `ip_len`: 4 or 16.
/// `prefix_bits`: prefix length (0-32 for IPv4, 0-128 for IPv6).
///
/// # Safety
/// `ipset` must be valid. `ip_bytes` must point to `ip_len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn xray_ipset_add_prefix(
    ipset: *mut IpSet,
    ip_bytes: *const u8,
    ip_len: usize,
    prefix_bits: u8,
) {
    ffi_catch_void!({
        if ipset.is_null() || ip_bytes.is_null() {
            return;
        }
        let ipset = &mut *ipset;
        let ip = slice::from_raw_parts(ip_bytes, ip_len);

        match ip_len {
            4 if prefix_bits <= 32 => {
                ipset.ipv4.insert(ip, prefix_bits);
                if prefix_bits > ipset.max4 {
                    ipset.max4 = prefix_bits;
                }
            }
            16 if prefix_bits <= 128 => {
                ipset.ipv6.insert(ip, prefix_bits);
                if prefix_bits > ipset.max6 {
                    ipset.max6 = prefix_bits;
                }
            }
            _ => {}
        }
    });
}

/// Finalize the IP set after all prefixes have been added.
/// Shrinks internal storage to release excess capacity.
///
/// # Safety
/// `ipset` must be valid.
#[no_mangle]
pub unsafe extern "C" fn xray_ipset_build(ipset: *mut IpSet) {
    ffi_catch_void!({
        if ipset.is_null() {
            return;
        }
        let ipset = &mut *ipset;
        ipset.ipv4.shrink_to_fit();
        ipset.ipv6.shrink_to_fit();
    });
}

/// Check if an IP address is contained in the IP set.
///
/// `ip_bytes`: 4 bytes for IPv4, 16 bytes for IPv6.
/// `ip_len`: 4 or 16.
///
/// # Safety
/// `ipset` must be valid. `ip_bytes` must point to `ip_len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn xray_ipset_contains(
    ipset: *const IpSet,
    ip_bytes: *const u8,
    ip_len: usize,
) -> bool {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if ipset.is_null() || ip_bytes.is_null() {
            return false;
        }
        let ipset = &*ipset;
        let ip = slice::from_raw_parts(ip_bytes, ip_len);

        match ip_len {
            4 => ipset.ipv4.contains(ip, 32),
            16 => ipset.ipv6.contains(ip, 128),
            _ => false,
        }
    })) {
        Ok(v) => v,
        Err(_) => false,
    }
}

/// Get the max IPv4 prefix length in the set. Returns 0xff if empty.
///
/// # Safety
/// `ipset` must be valid.
#[no_mangle]
pub unsafe extern "C" fn xray_ipset_max4(ipset: *const IpSet) -> u8 {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if ipset.is_null() {
            return 0xff;
        }
        let ipset = &*ipset;
        if ipset.max4 == 0 {
            0xff
        } else {
            ipset.max4
        }
    })) {
        Ok(v) => v,
        Err(_) => 0xff,
    }
}

/// Get the max IPv6 prefix length in the set. Returns 0xff if empty.
///
/// # Safety
/// `ipset` must be valid.
#[no_mangle]
pub unsafe extern "C" fn xray_ipset_max6(ipset: *const IpSet) -> u8 {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if ipset.is_null() {
            return 0xff;
        }
        let ipset = &*ipset;
        if ipset.max6 == 0 {
            0xff
        } else {
            ipset.max6
        }
    })) {
        Ok(v) => v,
        Err(_) => 0xff,
    }
}

/// Free an IP set.
///
/// # Safety
/// `ipset` must be valid or null. Must not be used after freeing.
#[no_mangle]
pub unsafe extern "C" fn xray_ipset_free(ipset: *mut IpSet) {
    ffi_catch_void!({
        if !ipset.is_null() {
            drop(Box::from_raw(ipset));
        }
    });
}
