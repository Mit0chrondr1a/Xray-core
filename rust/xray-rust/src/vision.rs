//! Vision padding/unpadding — eliminates length signatures during TLS handshake.
//!
//! Ports `XtlsPadding()` and `XtlsUnpadding()` from `proxy/proxy.go` to Rust
//! so padding is computed before kTLS encryption, keeping it entirely in userspace.
//!
//! Memory strategy: Caller (Go) allocates buffers — no Rust heap allocation.
//! Vision padding adds at most ~1400 bytes to a buffer already allocated at
//! buf.Size (8192). Both functions write into the caller's buffer.
//!
//! Frame format:
//!   [UUID (16 bytes, first frame only)][command (1)][contentLen_hi (1)]
//!   [contentLen_lo (1)][padLen_hi (1)][padLen_lo (1)][content (contentLen)]
//!   [random padding (padLen)]

use std::cell::RefCell;
use std::sync::Once;

/// Maximum buffer size (matches Go buf.Size = 8192).
const BUF_SIZE: i32 = 8192;

/// Header overhead: command(1) + contentLen(2) + padLen(2) = 5 bytes.
const HEADER_SIZE: i32 = 5;

/// Maximum overhead including UUID prefix: 16 + 5 = 21 bytes.
const MAX_OVERHEAD: i32 = 21;

/// Per-thread random cache size used to amortize getrandom syscalls.
const RNG_CACHE_SIZE: usize = 4096;

struct RandomCache {
    buf: [u8; RNG_CACHE_SIZE],
    pos: usize,
    len: usize,
}

impl RandomCache {
    const fn new() -> Self {
        Self {
            buf: [0u8; RNG_CACHE_SIZE],
            pos: 0,
            len: 0,
        }
    }

    fn refill(&mut self) -> bool {
        if getrandom::fill(&mut self.buf).is_err() {
            self.pos = 0;
            self.len = 0;
            return false;
        }
        self.pos = 0;
        self.len = self.buf.len();
        true
    }

    fn take(&mut self, out: &mut [u8]) -> bool {
        let mut written = 0usize;
        while written < out.len() {
            if self.pos == self.len && !self.refill() {
                return false;
            }
            let available = self.len - self.pos;
            let n = core::cmp::min(available, out.len() - written);
            out[written..written + n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
            self.pos += n;
            written += n;
        }
        true
    }

    fn next_u64(&mut self) -> Option<u64> {
        let mut buf = [0u8; 8];
        if !self.take(&mut buf) {
            return None;
        }
        Some(u64::from_le_bytes(buf))
    }
}

thread_local! {
    static RNG_CACHE: RefCell<RandomCache> = RefCell::new(RandomCache::new());
}

static RNG_FAILURE_WARN_ONCE: Once = Once::new();

#[inline]
fn warn_rng_failure_once() {
    RNG_FAILURE_WARN_ONCE.call_once(|| {
        eprintln!("xray_vision: getrandom failed, padding fill degraded to zeros");
    });
}

// --- Padding ---

/// Pad a plaintext buffer with Vision framing.
///
/// # Arguments
/// * `data` — content bytes (may be null if data_len == 0)
/// * `data_len` — length of content
/// * `command` — padding command (0=continue, 1=end, 2=direct)
/// * `uuid` — 16-byte UUID pointer (null if already sent)
/// * `long_padding` — use long padding mode for TLS handshake hiding
/// * `testseed` — 4-element array: [threshold, range, base, small_range]
/// * `out_buf` — caller-allocated output buffer
/// * `out_cap` — capacity of output buffer
///
/// # Returns
/// Total bytes written to out_buf, or negative error code.
///
/// # Safety
/// Caller must ensure all pointers are valid and out_buf has sufficient capacity.
#[no_mangle]
pub unsafe extern "C" fn xray_vision_pad(
    data: *const u8,
    data_len: u32,
    command: u8,
    uuid: *const u8,       // 16 bytes, or null if already sent
    long_padding: bool,
    testseed: *const u32,  // 4-element array: [threshold, range, base, small_range]
    out_buf: *mut u8,
    out_cap: u32,
) -> i32 {
    ffi_catch_i32!({
    if out_buf.is_null() || testseed.is_null() {
        return -1; // FFI_ERR_NULL
    }

    let content_len = data_len as i32;
    let seeds = core::slice::from_raw_parts(testseed, 4);
    let threshold = seeds[0] as i32;
    let range = seeds[1] as i64;
    let base = seeds[2] as i32;
    let small_range = seeds[3] as i64;

    // Compute padding length using CSPRNG (matches Go's crypto/rand.Int).
    // Returns -3 on RNG failure so Go falls back to its own padding implementation
    // rather than producing zero-padded output (which is a DPI fingerprint).
    let padding_len: i32;

    if content_len < threshold && long_padding {
        let Some(random_val) = csprng_range(range) else {
            return -3; // RNG failure
        };
        padding_len = clamp_padding(random_val as i32 + base - content_len, content_len);
    } else {
        let Some(random_val) = csprng_range(small_range) else {
            return -3; // RNG failure
        };
        padding_len = clamp_padding(random_val as i32, content_len);
    }

    // Calculate total output size.
    let uuid_len: i32 = if !uuid.is_null() { 16 } else { 0 };
    let total = uuid_len + HEADER_SIZE + content_len + padding_len;

    if total > out_cap as i32 {
        return -2; // buffer too small
    }

    let out = core::slice::from_raw_parts_mut(out_buf, out_cap as usize);
    let mut pos: usize = 0;

    // Write UUID prefix (first frame only).
    if !uuid.is_null() {
        let uuid_bytes = core::slice::from_raw_parts(uuid, 16);
        out[pos..pos + 16].copy_from_slice(uuid_bytes);
        pos += 16;
    }

    // Write header: [command][contentLen_hi][contentLen_lo][padLen_hi][padLen_lo]
    out[pos] = command;
    out[pos + 1] = (content_len >> 8) as u8;
    out[pos + 2] = content_len as u8;
    out[pos + 3] = (padding_len >> 8) as u8;
    out[pos + 4] = padding_len as u8;
    pos += HEADER_SIZE as usize;

    // Write content.
    if !data.is_null() && content_len > 0 {
        let data_slice = core::slice::from_raw_parts(data, content_len as usize);
        out[pos..pos + content_len as usize].copy_from_slice(data_slice);
        pos += content_len as usize;
    }

    // Write random padding.
    if padding_len > 0 {
        let padding_slice = &mut out[pos..pos + padding_len as usize];
        if !fill_random(padding_slice) {
            return -3; // RNG failure — let Go fallback handle it
        }
        pos += padding_len as usize;
    }

    pos as i32
    })
}

/// Clamp padding to fit within buffer constraints.
#[inline]
fn clamp_padding(mut padding: i32, content_len: i32) -> i32 {
    let max_padding = BUF_SIZE - MAX_OVERHEAD - content_len;
    if padding > max_padding {
        padding = max_padding;
    }
    if padding < 0 {
        padding = 0;
    }
    padding
}

/// Generate a random value in [0, upper_bound) using CSPRNG.
/// Values are pulled from a thread-local random cache to reduce syscall overhead.
/// Returns None on RNG failure — caller must propagate the error.
fn csprng_range(upper_bound: i64) -> Option<i64> {
    if upper_bound <= 1 {
        return Some(0);
    }

    let val = RNG_CACHE.with(|cache| cache.borrow_mut().next_u64())?;

    let val = val >> 1; // ensure positive
    // Simple modulo — for our use case (small ranges) bias is negligible.
    Some((val % upper_bound as u64) as i64)
}

/// Fill buffer with random bytes from the CSPRNG cache.
/// Returns false on RNG failure — caller must propagate the error.
fn fill_random(out: &mut [u8]) -> bool {
    if out.is_empty() {
        return true;
    }

    // Large writes are uncommon and are fine to satisfy directly.
    if out.len() > RNG_CACHE_SIZE {
        if getrandom::fill(out).is_err() {
            warn_rng_failure_once();
            return false;
        }
        return true;
    }

    let ok = RNG_CACHE.with(|cache| cache.borrow_mut().take(out));
    if !ok {
        warn_rng_failure_once();
        return false;
    }
    true
}

// --- Unpadding ---

/// Stateful unpadding parser state. Must be initialized with all fields = -1
/// except current_command = 0.
///
/// Matches Go's TrafficState.Inbound/Outbound fields:
///   RemainingCommand, RemainingContent, RemainingPadding, CurrentCommand
#[repr(C)]
pub struct VisionUnpadState {
    pub remaining_command: i32, // init: -1
    pub remaining_content: i32, // init: -1
    pub remaining_padding: i32, // init: -1
    pub current_command: i32,   // init: 0
}

// Compile-time struct size assertion: Go and C sides must agree on layout.
const _: () = assert!(core::mem::size_of::<VisionUnpadState>() == 16);

/// Remove Vision padding and extract content.
///
/// # Arguments
/// * `data` — input buffer containing padded data
/// * `data_len` — length of input
/// * `state` — mutable parser state (persists across calls)
/// * `uuid` — expected UUID for initial frame detection (16 bytes)
/// * `uuid_len` — length of UUID (must be 16 or 0 to skip UUID check)
/// * `out_buf` — caller-allocated output buffer for extracted content
/// * `out_cap` — capacity of output buffer
///
/// # Returns
/// Bytes of content written to out_buf, or negative error code.
/// The state is updated in-place for streaming across multiple calls.
///
/// # Safety
/// Caller must ensure all pointers are valid.
#[no_mangle]
pub unsafe extern "C" fn xray_vision_unpad(
    data: *const u8,
    data_len: u32,
    state: *mut VisionUnpadState,
    uuid: *const u8,
    uuid_len: u32,
    out_buf: *mut u8,
    out_cap: u32,
) -> i32 {
    ffi_catch_i32!({
    if data.is_null() || state.is_null() || out_buf.is_null() {
        return -1;
    }
    if uuid.is_null() && uuid_len > 0 {
        return -1;
    }

    let input = core::slice::from_raw_parts(data, data_len as usize);
    let output = core::slice::from_raw_parts_mut(out_buf, out_cap as usize);
    let st = &mut *state;

    let mut pos: usize = 0;
    let mut out_pos: usize = 0;
    let in_len = data_len as usize;

    // Initial state detection: look for UUID prefix.
    if st.remaining_command == -1 && st.remaining_content == -1 && st.remaining_padding == -1 {
        if uuid_len == 16 && in_len >= 21 {
            let expected_uuid = core::slice::from_raw_parts(uuid, 16);
            if input[..16] == *expected_uuid {
                pos = 16;
                st.remaining_command = 5;
            } else {
                // No UUID match — pass through unchanged.
                let copy_len = core::cmp::min(in_len, out_cap as usize);
                output[..copy_len].copy_from_slice(&input[..copy_len]);
                return copy_len as i32;
            }
        } else {
            // Not enough data or no UUID — pass through.
            let copy_len = core::cmp::min(in_len, out_cap as usize);
            output[..copy_len].copy_from_slice(&input[..copy_len]);
            return copy_len as i32;
        }
    }

    // Parse padded frames.
    while pos < in_len {
        if st.remaining_command > 0 {
            let byte = input[pos];
            pos += 1;
            match st.remaining_command {
                5 => st.current_command = byte as i32,
                4 => st.remaining_content = (byte as i32) << 8,
                3 => st.remaining_content |= byte as i32,
                2 => st.remaining_padding = (byte as i32) << 8,
                1 => st.remaining_padding |= byte as i32,
                _ => {}
            }
            st.remaining_command -= 1;
        } else if st.remaining_content > 0 {
            let avail = core::cmp::min(st.remaining_content as usize, in_len - pos);
            let writable = core::cmp::min(avail, out_cap as usize - out_pos);
            if writable > 0 {
                output[out_pos..out_pos + writable].copy_from_slice(&input[pos..pos + writable]);
                out_pos += writable;
            }
            pos += avail;
            st.remaining_content -= avail as i32;
        } else if st.remaining_padding > 0 {
            // Skip padding bytes.
            let skip = core::cmp::min(st.remaining_padding as usize, in_len - pos);
            pos += skip;
            st.remaining_padding -= skip as i32;
        } else {
            // Defensive: remaining_padding <= 0 with no command/content — break to prevent infinite loop.
            break;
        }

        // Check if current block is complete.
        if st.remaining_command <= 0 && st.remaining_content <= 0 && st.remaining_padding <= 0 {
            if st.current_command == 0 {
                // CommandPaddingContinue — expect another block.
                st.remaining_command = 5;
            } else {
                // CommandPaddingEnd or CommandPaddingDirect — done with padding.
                st.remaining_command = -1;
                st.remaining_content = -1;
                st.remaining_padding = -1;
                // Copy any remaining data verbatim (shouldn't happen normally).
                if pos < in_len {
                    let remaining = in_len - pos;
                    let writable = core::cmp::min(remaining, out_cap as usize - out_pos);
                    if writable > 0 {
                        output[out_pos..out_pos + writable]
                            .copy_from_slice(&input[pos..pos + writable]);
                        out_pos += writable;
                    }
                }
                break;
            }
        }
    }

    out_pos as i32
    })
}

// --- TLS Filtering ---

/// TLS byte patterns (matches Go constants in proxy/proxy.go).
const TLS_SERVER_HANDSHAKE_START: [u8; 3] = [0x16, 0x03, 0x03];
const TLS_CLIENT_HANDSHAKE_START: [u8; 2] = [0x16, 0x03];
const TLS_HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;
const TLS_HANDSHAKE_TYPE_SERVER_HELLO: u8 = 0x02;
const TLS13_SUPPORTED_VERSIONS: [u8; 6] = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];

/// Stateful TLS filter state passed across FFI boundary.
/// Fields are ordered to minimize padding (i32s first, then u16, then bools).
#[repr(C)]
pub struct VisionFilterState {
    pub remaining_server_hello: i32,
    pub number_of_packets_to_filter: i32,
    pub cipher: u16,
    pub is_tls: bool,
    pub is_tls12_or_above: bool,
    pub enable_xtls: bool,
}

// Compile-time struct size assertion: Go and C sides must agree on layout.
const _: () = assert!(core::mem::size_of::<VisionFilterState>() == 16);

/// Filter a single buffer for TLS handshake patterns and detect TLS 1.3.
///
/// # Arguments
/// * `data` — buffer bytes to scan
/// * `data_len` — length of buffer
/// * `state` — mutable filter state (persists across calls for multi-packet)
///
/// # Returns
/// 0 = continue filtering next packet, 1 = stop filtering (determined TLS version).
///
/// # Safety
/// Caller must ensure all pointers are valid.
#[no_mangle]
pub unsafe extern "C" fn xray_vision_filter_tls(
    data: *const u8,
    data_len: u32,
    state: *mut VisionFilterState,
) -> i32 {
    ffi_catch_i32!({
    if data.is_null() || state.is_null() || data_len == 0 {
        return 0;
    }
    let buf = core::slice::from_raw_parts(data, data_len as usize);
    let st = &mut *state;
    let buf_len = buf.len() as i32;

    st.number_of_packets_to_filter -= 1;

    if buf.len() >= 6 {
        if buf[..3] == TLS_SERVER_HANDSHAKE_START
            && buf[5] == TLS_HANDSHAKE_TYPE_SERVER_HELLO
        {
            st.remaining_server_hello =
                ((buf[3] as i32) << 8 | buf[4] as i32) + 5;
            st.is_tls12_or_above = true;
            st.is_tls = true;
            if buf.len() >= 79 && st.remaining_server_hello >= 79 {
                // TLS spec: session_id is at most 32 bytes; clamp to prevent
                // a malicious value from reading cipher bytes at an arbitrary offset.
                let session_id_len = core::cmp::min(buf[43] as usize, 32);
                let cs_offset = 43 + session_id_len + 1;
                if cs_offset + 2 <= buf.len() {
                    st.cipher =
                        (buf[cs_offset] as u16) << 8 | buf[cs_offset + 1] as u16;
                }
            }
        } else if buf[..2] == TLS_CLIENT_HANDSHAKE_START
            && buf[5] == TLS_HANDSHAKE_TYPE_CLIENT_HELLO
        {
            st.is_tls = true;
        }
    }

    if st.remaining_server_hello > 0 {
        let end = core::cmp::min(st.remaining_server_hello, buf_len) as usize;
        st.remaining_server_hello -= buf_len;
        if contains_subsequence(&buf[..end], &TLS13_SUPPORTED_VERSIONS) {
            // Check cipher suite against TLS 1.3 dictionary.
            // 0x1301..0x1304 enable XTLS; 0x1305 (CCM_8) does not.
            match st.cipher {
                0x1301 | 0x1302 | 0x1303 | 0x1304 => {
                    st.enable_xtls = true;
                }
                _ => {} // 0x1305 or unknown — don't enable XTLS
            }
            st.number_of_packets_to_filter = 0;
            return 1; // stop: found TLS 1.3
        } else if st.remaining_server_hello <= 0 {
            st.number_of_packets_to_filter = 0;
            return 1; // stop: TLS 1.2 (no supported_versions extension)
        }
    }

    0 // continue filtering
    })
}

/// Search for a subsequence (needle) within a byte slice (haystack).
#[inline]
fn contains_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

// --- Complete Record Detection ---

/// Check whether a byte buffer consists entirely of well-formed TLS
/// application data records (content type 0x17, version 0x0303).
///
/// # Returns
/// 1 if the buffer is a sequence of complete records, 0 otherwise.
///
/// # Safety
/// Caller must ensure the pointer is valid for `data_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn xray_vision_is_complete_record(
    data: *const u8,
    data_len: u32,
) -> i32 {
    ffi_catch_i32!({
    if data.is_null() || data_len == 0 {
        return 0;
    }
    let buf = core::slice::from_raw_parts(data, data_len as usize);
    let total_len = buf.len();
    let mut i = 0;
    let mut header_len: i32 = 5;
    let mut record_len: i32 = 0;

    while i < total_len {
        if header_len > 0 {
            let byte_val = buf[i];
            i += 1;
            match header_len {
                5 => {
                    if byte_val != 0x17 {
                        return 0;
                    }
                }
                4 => {
                    if byte_val != 0x03 {
                        return 0;
                    }
                }
                3 => {
                    if byte_val != 0x03 {
                        return 0;
                    }
                }
                2 => record_len = (byte_val as i32) << 8,
                1 => record_len |= byte_val as i32,
                _ => {}
            }
            header_len -= 1;
        } else if record_len > 0 {
            let remaining = total_len - i;
            if remaining < record_len as usize {
                return 0;
            }
            i += record_len as usize;
            record_len = 0;
            header_len = 5;
        } else {
            return 0;
        }
    }

    if header_len == 5 && record_len == 0 {
        1
    } else {
        0
    }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pad_unpad_roundtrip() {
        let uuid: [u8; 16] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ];
        let data = b"Hello, Vision!";
        let testseed: [u32; 4] = [900, 500, 900, 256];
        let mut padded = [0u8; 8192];

        // Pad with UUID.
        let padded_len = unsafe {
            xray_vision_pad(
                data.as_ptr(),
                data.len() as u32,
                1, // CommandPaddingEnd
                uuid.as_ptr(),
                true,
                testseed.as_ptr(),
                padded.as_mut_ptr(),
                padded.len() as u32,
            )
        };
        assert!(padded_len > 0, "padding should succeed");
        assert!(
            padded_len as usize > data.len() + 16 + 5,
            "padded should be larger"
        );

        // Unpad.
        let mut state = VisionUnpadState {
            remaining_command: -1,
            remaining_content: -1,
            remaining_padding: -1,
            current_command: 0,
        };
        let mut unpadded = [0u8; 8192];

        let unpadded_len = unsafe {
            xray_vision_unpad(
                padded.as_ptr(),
                padded_len as u32,
                &mut state,
                uuid.as_ptr(),
                16,
                unpadded.as_mut_ptr(),
                unpadded.len() as u32,
            )
        };
        assert_eq!(unpadded_len, data.len() as i32);
        assert_eq!(&unpadded[..data.len()], data);
    }

    #[test]
    fn test_pad_empty_content() {
        let testseed: [u32; 4] = [900, 500, 900, 256];
        let mut padded = [0u8; 8192];

        let padded_len = unsafe {
            xray_vision_pad(
                core::ptr::null(),
                0,
                0, // CommandPaddingContinue
                core::ptr::null(),
                true,
                testseed.as_ptr(),
                padded.as_mut_ptr(),
                padded.len() as u32,
            )
        };
        assert!(padded_len >= 5, "should at least have header");
    }

    #[test]
    fn test_pad_no_uuid() {
        let data = b"test data";
        let testseed: [u32; 4] = [900, 500, 900, 256];
        let mut padded = [0u8; 8192];

        let padded_len = unsafe {
            xray_vision_pad(
                data.as_ptr(),
                data.len() as u32,
                1,
                core::ptr::null(), // no UUID
                false,
                testseed.as_ptr(),
                padded.as_mut_ptr(),
                padded.len() as u32,
            )
        };
        assert!(padded_len > 0);

        // Verify header starts immediately (no UUID prefix).
        assert_eq!(padded[0], 1); // command
        let content_len = ((padded[1] as u16) << 8 | padded[2] as u16) as usize;
        assert_eq!(content_len, data.len());
    }

    #[test]
    fn test_unpad_no_uuid_match() {
        // When UUID doesn't match, data should pass through unchanged.
        let uuid: [u8; 16] = [0xAA; 16];
        let data = [0xBB; 32]; // doesn't start with uuid
        let mut state = VisionUnpadState {
            remaining_command: -1,
            remaining_content: -1,
            remaining_padding: -1,
            current_command: 0,
        };
        let mut out = [0u8; 256];

        let n = unsafe {
            xray_vision_unpad(
                data.as_ptr(),
                data.len() as u32,
                &mut state,
                uuid.as_ptr(),
                16,
                out.as_mut_ptr(),
                out.len() as u32,
            )
        };
        assert_eq!(n, 32);
        assert_eq!(&out[..32], &data[..]);
    }

    #[test]
    fn test_pad_unpad_continue_then_end() {
        let uuid: [u8; 16] = [0x42; 16];
        let testseed: [u32; 4] = [900, 500, 900, 256];

        // First frame: continue
        let data1 = b"first chunk";
        let mut padded1 = [0u8; 8192];
        let len1 = unsafe {
            xray_vision_pad(
                data1.as_ptr(),
                data1.len() as u32,
                0, // continue
                uuid.as_ptr(),
                true,
                testseed.as_ptr(),
                padded1.as_mut_ptr(),
                padded1.len() as u32,
            )
        };
        assert!(len1 > 0);

        // Second frame: end (no UUID)
        let data2 = b"second chunk";
        let mut padded2 = [0u8; 8192];
        let len2 = unsafe {
            xray_vision_pad(
                data2.as_ptr(),
                data2.len() as u32,
                1, // end
                core::ptr::null(),
                false,
                testseed.as_ptr(),
                padded2.as_mut_ptr(),
                padded2.len() as u32,
            )
        };
        assert!(len2 > 0);

        // Concatenate both padded frames.
        let mut combined = vec![0u8; (len1 + len2) as usize];
        combined[..len1 as usize].copy_from_slice(&padded1[..len1 as usize]);
        combined[len1 as usize..].copy_from_slice(&padded2[..len2 as usize]);

        // Unpad all at once.
        let mut state = VisionUnpadState {
            remaining_command: -1,
            remaining_content: -1,
            remaining_padding: -1,
            current_command: 0,
        };
        let mut out = [0u8; 8192];

        let n = unsafe {
            xray_vision_unpad(
                combined.as_ptr(),
                combined.len() as u32,
                &mut state,
                uuid.as_ptr(),
                16,
                out.as_mut_ptr(),
                out.len() as u32,
            )
        };

        // Should extract both chunks.
        let expected_len = data1.len() + data2.len();
        assert_eq!(n, expected_len as i32);
        assert_eq!(&out[..data1.len()], data1.as_slice());
        assert_eq!(&out[data1.len()..expected_len], data2.as_slice());
    }

    // --- FilterTls tests ---

    #[test]
    fn test_filter_tls_server_hello_tls13() {
        // Construct a minimal ServerHello with TLS 1.3 supported_versions extension.
        // TLS record: 0x16 0x03 0x03 [length_hi] [length_lo] [handshake_type=0x02]
        // ServerHello body needs to be >= 79 bytes for cipher extraction.
        let mut buf = vec![0u8; 256];

        // Record header
        buf[0] = 0x16; // handshake
        buf[1] = 0x03; // version major
        buf[2] = 0x03; // version minor
        let record_len: u16 = 250; // payload length
        buf[3] = (record_len >> 8) as u8;
        buf[4] = record_len as u8;

        // Handshake header
        buf[5] = 0x02; // ServerHello

        // Fill up to byte 43 (session_id_length)
        buf[43] = 0; // session_id_length = 0

        // Cipher suite at offset 44-45 (43 + 0 + 1 = 44)
        buf[44] = 0x13; // TLS_AES_128_GCM_SHA256 = 0x1301
        buf[45] = 0x01;

        // Embed TLS 1.3 supported_versions extension somewhere in the buffer
        let sv = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
        buf[100..106].copy_from_slice(&sv);

        let mut state = VisionFilterState {
            remaining_server_hello: -1,
            number_of_packets_to_filter: 8,
            cipher: 0,
            is_tls: false,
            is_tls12_or_above: false,
            enable_xtls: false,
        };

        let rc = unsafe {
            xray_vision_filter_tls(buf.as_ptr(), buf.len() as u32, &mut state)
        };

        assert_eq!(rc, 1, "should stop filtering after finding TLS 1.3");
        assert!(state.is_tls, "should detect TLS");
        assert!(state.is_tls12_or_above, "should detect TLS 1.2+");
        assert_eq!(state.cipher, 0x1301, "should extract cipher suite");
        assert!(state.enable_xtls, "should enable XTLS for AES-128-GCM");
        assert_eq!(state.number_of_packets_to_filter, 0);
    }

    #[test]
    fn test_filter_tls_client_hello() {
        // ClientHello: 0x16 0x03 [any] [len_hi] [len_lo] 0x01
        let buf = [0x16, 0x03, 0x01, 0x00, 0x80, 0x01, 0x00, 0x00];

        let mut state = VisionFilterState {
            remaining_server_hello: -1,
            number_of_packets_to_filter: 8,
            cipher: 0,
            is_tls: false,
            is_tls12_or_above: false,
            enable_xtls: false,
        };

        let rc = unsafe {
            xray_vision_filter_tls(buf.as_ptr(), buf.len() as u32, &mut state)
        };

        assert_eq!(rc, 0, "should continue filtering");
        assert!(state.is_tls, "should detect TLS client hello");
        assert!(!state.is_tls12_or_above, "client hello alone doesn't set 1.2+");
        assert_eq!(state.number_of_packets_to_filter, 7);
    }

    #[test]
    fn test_filter_tls_ccm8_no_xtls() {
        // ServerHello with cipher 0x1305 (TLS_AES_128_CCM_8_SHA256) should NOT enable XTLS.
        let mut buf = vec![0u8; 256];
        buf[0] = 0x16;
        buf[1] = 0x03;
        buf[2] = 0x03;
        let record_len: u16 = 250;
        buf[3] = (record_len >> 8) as u8;
        buf[4] = record_len as u8;
        buf[5] = 0x02; // ServerHello
        buf[43] = 0;   // session_id_length = 0
        buf[44] = 0x13;
        buf[45] = 0x05; // TLS_AES_128_CCM_8_SHA256

        let sv = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
        buf[100..106].copy_from_slice(&sv);

        let mut state = VisionFilterState {
            remaining_server_hello: -1,
            number_of_packets_to_filter: 8,
            cipher: 0,
            is_tls: false,
            is_tls12_or_above: false,
            enable_xtls: false,
        };

        let rc = unsafe {
            xray_vision_filter_tls(buf.as_ptr(), buf.len() as u32, &mut state)
        };

        assert_eq!(rc, 1);
        assert_eq!(state.cipher, 0x1305);
        assert!(!state.enable_xtls, "CCM_8 should NOT enable XTLS");
    }

    // --- IsCompleteRecord tests ---

    #[test]
    fn test_complete_record_single() {
        // One valid TLS application data record: 0x17 0x03 0x03 [len=5] [5 bytes payload]
        let data = [0x17, 0x03, 0x03, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05];
        let rc = unsafe {
            xray_vision_is_complete_record(data.as_ptr(), data.len() as u32)
        };
        assert_eq!(rc, 1, "single complete record");
    }

    #[test]
    fn test_complete_record_multiple() {
        // Two valid records back-to-back.
        let mut data = Vec::new();
        // Record 1: 3 bytes payload
        data.extend_from_slice(&[0x17, 0x03, 0x03, 0x00, 0x03, 0xAA, 0xBB, 0xCC]);
        // Record 2: 2 bytes payload
        data.extend_from_slice(&[0x17, 0x03, 0x03, 0x00, 0x02, 0xDD, 0xEE]);

        let rc = unsafe {
            xray_vision_is_complete_record(data.as_ptr(), data.len() as u32)
        };
        assert_eq!(rc, 1, "two complete records");
    }

    #[test]
    fn test_incomplete_record() {
        // Truncated record (header says 10 bytes but only 3 available).
        let data = [0x17, 0x03, 0x03, 0x00, 0x0A, 0x01, 0x02, 0x03];
        let rc = unsafe {
            xray_vision_is_complete_record(data.as_ptr(), data.len() as u32)
        };
        assert_eq!(rc, 0, "truncated record");
    }

    #[test]
    fn test_wrong_content_type() {
        // Wrong content type (0x16 instead of 0x17).
        let data = [0x16, 0x03, 0x03, 0x00, 0x01, 0xFF];
        let rc = unsafe {
            xray_vision_is_complete_record(data.as_ptr(), data.len() as u32)
        };
        assert_eq!(rc, 0, "wrong content type");
    }

    #[test]
    fn test_empty_record() {
        let rc = unsafe {
            xray_vision_is_complete_record(core::ptr::null(), 0)
        };
        assert_eq!(rc, 0, "empty/null data");
    }

    #[test]
    fn test_filter_tls_12_detection() {
        // ServerHello without supported_versions extension → TLS 1.2.
        let mut buf = vec![0u8; 128];
        // Record header
        buf[0] = 0x16;
        buf[1] = 0x03;
        buf[2] = 0x03;
        let record_len: u16 = 122; // fits in buffer, remaining drains to 0
        buf[3] = (record_len >> 8) as u8;
        buf[4] = record_len as u8;
        buf[5] = 0x02; // ServerHello
        buf[43] = 0;   // session_id_length = 0
        buf[44] = 0x00;
        buf[45] = 0x2F; // TLS_RSA_WITH_AES_128_CBC_SHA (not a TLS 1.3 cipher)
        // No supported_versions extension anywhere.

        let mut state = VisionFilterState {
            remaining_server_hello: -1,
            number_of_packets_to_filter: 8,
            cipher: 0,
            is_tls: false,
            is_tls12_or_above: false,
            enable_xtls: false,
        };

        let rc = unsafe {
            xray_vision_filter_tls(buf.as_ptr(), buf.len() as u32, &mut state)
        };

        assert_eq!(rc, 1, "should stop after determining TLS 1.2");
        assert!(state.is_tls);
        assert!(state.is_tls12_or_above);
        assert!(!state.enable_xtls, "TLS 1.2 should not enable XTLS");
        assert_eq!(state.number_of_packets_to_filter, 0);
        assert_eq!(state.cipher, 0x002F);
    }

    #[test]
    fn test_filter_tls_multi_packet_server_hello() {
        // ServerHello split across two buffers.
        let mut buf1 = vec![0u8; 80];
        buf1[0] = 0x16;
        buf1[1] = 0x03;
        buf1[2] = 0x03;
        let record_len: u16 = 200; // longer than first buffer
        buf1[3] = (record_len >> 8) as u8;
        buf1[4] = record_len as u8;
        buf1[5] = 0x02; // ServerHello
        buf1[43] = 0;   // session_id_length = 0
        buf1[44] = 0x13;
        buf1[45] = 0x01; // TLS_AES_128_GCM_SHA256

        let mut state = VisionFilterState {
            remaining_server_hello: -1,
            number_of_packets_to_filter: 8,
            cipher: 0,
            is_tls: false,
            is_tls12_or_above: false,
            enable_xtls: false,
        };

        // First call: detect ServerHello but no supported_versions yet.
        let rc1 = unsafe {
            xray_vision_filter_tls(buf1.as_ptr(), buf1.len() as u32, &mut state)
        };
        assert_eq!(rc1, 0, "should continue after partial ServerHello");
        assert!(state.is_tls);
        assert!(state.is_tls12_or_above);
        assert_eq!(state.cipher, 0x1301);
        assert!(state.remaining_server_hello > 0);

        // Second call: contains supported_versions extension.
        let mut buf2 = vec![0u8; 200];
        let sv = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
        buf2[10..16].copy_from_slice(&sv);

        let rc2 = unsafe {
            xray_vision_filter_tls(buf2.as_ptr(), buf2.len() as u32, &mut state)
        };
        assert_eq!(rc2, 1, "should stop after finding TLS 1.3");
        assert!(state.enable_xtls);
        assert_eq!(state.number_of_packets_to_filter, 0);
    }

    #[test]
    fn test_filter_tls_short_server_hello() {
        // ServerHello with buffer < 79 bytes — cipher extraction skipped.
        let mut buf = vec![0u8; 60];
        buf[0] = 0x16;
        buf[1] = 0x03;
        buf[2] = 0x03;
        let record_len: u16 = 54;
        buf[3] = (record_len >> 8) as u8;
        buf[4] = record_len as u8;
        buf[5] = 0x02; // ServerHello

        let mut state = VisionFilterState {
            remaining_server_hello: -1,
            number_of_packets_to_filter: 8,
            cipher: 0,
            is_tls: false,
            is_tls12_or_above: false,
            enable_xtls: false,
        };

        let rc = unsafe {
            xray_vision_filter_tls(buf.as_ptr(), buf.len() as u32, &mut state)
        };

        assert!(state.is_tls);
        assert!(state.is_tls12_or_above);
        assert_eq!(state.cipher, 0, "cipher should not be extracted from short hello");
        // remaining_server_hello = 54 + 5 = 59, buf.len() = 60 → drains to -1
        assert_eq!(rc, 1, "should stop as TLS 1.2 (no supported_versions)");
        assert_eq!(state.number_of_packets_to_filter, 0);
    }

    #[test]
    fn test_filter_tls_counter_exhaustion() {
        // Non-TLS traffic: counter decrements to 0 without detecting TLS.
        let data = [0x00; 64];

        let mut state = VisionFilterState {
            remaining_server_hello: -1,
            number_of_packets_to_filter: 3,
            cipher: 0,
            is_tls: false,
            is_tls12_or_above: false,
            enable_xtls: false,
        };

        for i in 0..3 {
            let rc = unsafe {
                xray_vision_filter_tls(data.as_ptr(), data.len() as u32, &mut state)
            };
            assert_eq!(rc, 0, "should continue filtering on packet {}", i);
        }

        assert_eq!(state.number_of_packets_to_filter, 0);
        assert!(!state.is_tls);
        assert!(!state.enable_xtls);
    }
}
