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

/// Maximum buffer size (matches Go buf.Size = 8192).
const BUF_SIZE: i32 = 8192;

/// Header overhead: command(1) + contentLen(2) + padLen(2) = 5 bytes.
const HEADER_SIZE: i32 = 5;

/// Maximum overhead including UUID prefix: 16 + 5 = 21 bytes.
const MAX_OVERHEAD: i32 = 21;

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
    let padding_len: i32;

    if content_len < threshold && long_padding {
        let random_val = csprng_range(range);
        padding_len = clamp_padding(random_val as i32 + base - content_len, content_len);
    } else {
        let random_val = csprng_range(small_range);
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
        // Fill with random bytes for padding (best-effort; zeros are acceptable fallback).
        let _ = getrandom::fill(padding_slice);
        pos += padding_len as usize;
    }

    pos as i32
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
/// Matches Go's crypto/rand.Int behavior.
fn csprng_range(upper_bound: i64) -> i64 {
    if upper_bound <= 1 {
        return 0;
    }

    let mut buf = [0u8; 8];
    if getrandom::fill(&mut buf).is_err() {
        return 0;
    }
    let val = u64::from_le_bytes(buf) >> 1; // ensure positive
    // Simple modulo — for our use case (small ranges) bias is negligible.
    (val % upper_bound as u64) as i64
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
        } else {
            // remaining_padding > 0: skip padding bytes.
            let skip = core::cmp::min(st.remaining_padding as usize, in_len - pos);
            pos += skip;
            st.remaining_padding -= skip as i32;
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
}
