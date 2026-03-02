//! AEAD cipher handle for accelerated per-chunk seal/open operations.
//!
//! Provides a stateful handle wrapping `ring`'s AES-GCM / ChaCha20-Poly1305
//! implementations. The handle keeps cipher state in Rust, minimising FFI
//! overhead for the hot-path chunk encryption used by VMess and Shadowsocks.

use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use std::slice;

/// Algorithm selector passed from Go.
const ALGO_AES_128_GCM: u8 = 0;
const ALGO_AES_256_GCM: u8 = 1;
const ALGO_CHACHA20_POLY1305: u8 = 2;

pub struct AeadHandle {
    key: LessSafeKey,
    algo: &'static aead::Algorithm,
}

impl AeadHandle {
    fn new(algo_id: u8, key_bytes: &[u8]) -> Option<Self> {
        let algorithm: &'static aead::Algorithm = match algo_id {
            ALGO_AES_128_GCM => &aead::AES_128_GCM,
            ALGO_AES_256_GCM => &aead::AES_256_GCM,
            ALGO_CHACHA20_POLY1305 => &aead::CHACHA20_POLY1305,
            _ => return None,
        };
        let unbound = UnboundKey::new(algorithm, key_bytes).ok()?;
        Some(AeadHandle {
            key: LessSafeKey::new(unbound),
            algo: algorithm,
        })
    }
}

#[inline]
unsafe fn copy_bytes_maybe_overlap(src: *const u8, dst: *mut u8, len: usize) {
    if len == 0 {
        return;
    }
    let src_start = src as usize;
    let src_end = src_start.saturating_add(len);
    let dst_start = dst as usize;
    let dst_end = dst_start.saturating_add(len);
    if src_start < dst_end && dst_start < src_end {
        std::ptr::copy(src, dst, len);
    } else {
        std::ptr::copy_nonoverlapping(src, dst, len);
    }
}

/// Create a new AEAD handle.
///
/// `algo`: 0 = AES-128-GCM, 1 = AES-256-GCM, 2 = ChaCha20-Poly1305.
/// `key` / `key_len`: key material (16, 32, or 32 bytes respectively).
///
/// Returns a heap-allocated handle, or null on failure.
///
/// # Safety
/// `key` must point to `key_len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn xray_aead_new(
    algo: u8,
    key: *const u8,
    key_len: usize,
) -> *mut AeadHandle {
    ffi_catch_ptr!({
        if key.is_null() || key_len == 0 {
            return std::ptr::null_mut();
        }
        let key_bytes = slice::from_raw_parts(key, key_len);
        match AeadHandle::new(algo, key_bytes) {
            Some(h) => Box::into_raw(Box::new(h)),
            None => std::ptr::null_mut(),
        }
    })
}

/// Seal (encrypt + authenticate) plaintext in place.
///
/// Writes ciphertext + tag into `out`. `out` must have capacity >= `pt_len` + overhead (16).
/// On success, `*out_len` is set to the number of bytes written and returns 0.
/// On failure, returns a negative error code.
///
/// # Safety
/// All pointer/length pairs must be valid. `handle` must be from `xray_aead_new`.
#[no_mangle]
pub unsafe extern "C" fn xray_aead_seal(
    handle: *const AeadHandle,
    nonce_ptr: *const u8,
    nonce_len: usize,
    aad_ptr: *const u8,
    aad_len: usize,
    pt_ptr: *const u8,
    pt_len: usize,
    out_ptr: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    ffi_catch_i32!({
        if handle.is_null() || out_ptr.is_null() || out_len.is_null() {
            return crate::ffi::FFI_ERR_NULL;
        }
        let h = &*handle;
        let tag_len = h.algo.tag_len();
        let needed = pt_len + tag_len;
        if out_cap < needed {
            return crate::ffi::FFI_ERR_APP;
        }
        if nonce_len != h.algo.nonce_len() {
            return crate::ffi::FFI_ERR_APP;
        }

        // Build nonce
        if nonce_ptr.is_null() && nonce_len > 0 {
            return crate::ffi::FFI_ERR_NULL;
        }
        let nonce_bytes = if nonce_len > 0 {
            slice::from_raw_parts(nonce_ptr, nonce_len)
        } else {
            &[]
        };
        let nonce = match Nonce::try_assume_unique_for_key(nonce_bytes) {
            Ok(n) => n,
            Err(_) => return crate::ffi::FFI_ERR_CRYPTO,
        };

        // Build AAD
        let aad_slice: &[u8] = if aad_ptr.is_null() || aad_len == 0 {
            &[]
        } else {
            slice::from_raw_parts(aad_ptr, aad_len)
        };

        // Copy plaintext into output buffer, then seal in place
        let out_buf = slice::from_raw_parts_mut(out_ptr, out_cap);
        if pt_len > 0 {
            if pt_ptr.is_null() {
                return crate::ffi::FFI_ERR_NULL;
            }
            copy_bytes_maybe_overlap(pt_ptr, out_buf.as_mut_ptr(), pt_len);
        }
        let in_out = &mut out_buf[..needed];

        match h
            .key
            .seal_in_place_separate_tag(nonce, Aad::from(aad_slice), &mut in_out[..pt_len])
        {
            Ok(tag) => {
                // Append tag after plaintext
                in_out[pt_len..needed].copy_from_slice(tag.as_ref());
                *out_len = needed;
                crate::ffi::FFI_OK
            }
            Err(_) => crate::ffi::FFI_ERR_CRYPTO,
        }
    })
}

/// Open (decrypt + verify) ciphertext.
///
/// `ct_ptr`/`ct_len` is ciphertext + tag. Writes plaintext into `out`.
/// `out` must have capacity >= `ct_len` - overhead (16).
/// On success, `*out_len` is set to the plaintext length and returns 0.
///
/// # Safety
/// All pointer/length pairs must be valid. `handle` must be from `xray_aead_new`.
#[no_mangle]
pub unsafe extern "C" fn xray_aead_open(
    handle: *const AeadHandle,
    nonce_ptr: *const u8,
    nonce_len: usize,
    aad_ptr: *const u8,
    aad_len: usize,
    ct_ptr: *const u8,
    ct_len: usize,
    out_ptr: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    ffi_catch_i32!({
        if handle.is_null() || out_ptr.is_null() || out_len.is_null() {
            return crate::ffi::FFI_ERR_NULL;
        }
        let h = &*handle;
        let tag_len = h.algo.tag_len();
        if ct_len < tag_len {
            return crate::ffi::FFI_ERR_APP;
        }
        // Need full ct_len in output buffer for in-place decryption
        if out_cap < ct_len {
            return crate::ffi::FFI_ERR_APP;
        }
        if nonce_len != h.algo.nonce_len() {
            return crate::ffi::FFI_ERR_APP;
        }

        // Build nonce
        if nonce_ptr.is_null() && nonce_len > 0 {
            return crate::ffi::FFI_ERR_NULL;
        }
        let nonce_bytes = if nonce_len > 0 {
            slice::from_raw_parts(nonce_ptr, nonce_len)
        } else {
            &[]
        };
        let nonce = match Nonce::try_assume_unique_for_key(nonce_bytes) {
            Ok(n) => n,
            Err(_) => return crate::ffi::FFI_ERR_CRYPTO,
        };

        // Build AAD
        let aad_slice: &[u8] = if aad_ptr.is_null() || aad_len == 0 {
            &[]
        } else {
            slice::from_raw_parts(aad_ptr, aad_len)
        };

        // Copy ciphertext+tag into output buffer, then open in place
        if ct_ptr.is_null() && ct_len > 0 {
            return crate::ffi::FFI_ERR_NULL;
        }
        let out_buf = slice::from_raw_parts_mut(out_ptr, out_cap);
        if ct_len > 0 {
            copy_bytes_maybe_overlap(ct_ptr, out_buf.as_mut_ptr(), ct_len);
        }
        let in_out = &mut out_buf[..ct_len];

        match h.key.open_in_place(nonce, Aad::from(aad_slice), in_out) {
            Ok(plaintext) => {
                let pt_len = plaintext.len();
                *out_len = pt_len;
                // Zero residual tag bytes after plaintext
                out_buf[pt_len..ct_len].fill(0);
                crate::ffi::FFI_OK
            }
            Err(_) => crate::ffi::FFI_ERR_CRYPTO,
        }
    })
}

/// Return the tag overhead in bytes for this AEAD (always 16 for supported algos).
///
/// # Safety
/// `handle` must be from `xray_aead_new`.
#[no_mangle]
pub unsafe extern "C" fn xray_aead_overhead(handle: *const AeadHandle) -> i32 {
    ffi_catch_i32!({
        if handle.is_null() {
            return -1;
        }
        let h = &*handle;
        h.algo.tag_len() as i32
    })
}

/// Return the nonce size in bytes for this AEAD (always 12 for supported algos).
///
/// # Safety
/// `handle` must be from `xray_aead_new`.
#[no_mangle]
pub unsafe extern "C" fn xray_aead_nonce_size(handle: *const AeadHandle) -> i32 {
    ffi_catch_i32!({
        if handle.is_null() {
            return -1;
        }
        let h = &*handle;
        h.algo.nonce_len() as i32
    })
}

/// Free an AEAD handle.
///
/// # Safety
/// `handle` must be from `xray_aead_new`, or null. Must not be used after freeing.
#[no_mangle]
pub unsafe extern "C" fn xray_aead_free(handle: *mut AeadHandle) {
    ffi_catch_void!({
        if !handle.is_null() {
            drop(Box::from_raw(handle));
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_128_gcm_round_trip() {
        let key = [0x42u8; 16];
        let nonce = [0x01u8; 12];
        let aad = b"additional data";
        let plaintext = b"hello world, this is a test of AEAD encryption";

        unsafe {
            let handle = xray_aead_new(ALGO_AES_128_GCM, key.as_ptr(), key.len());
            assert!(!handle.is_null());

            // Seal
            let mut ct_buf = vec![0u8; plaintext.len() + 16];
            let mut ct_len: usize = 0;
            let rc = xray_aead_seal(
                handle,
                nonce.as_ptr(),
                nonce.len(),
                aad.as_ptr(),
                aad.len(),
                plaintext.as_ptr(),
                plaintext.len(),
                ct_buf.as_mut_ptr(),
                ct_buf.len(),
                &mut ct_len,
            );
            assert_eq!(rc, 0);
            assert_eq!(ct_len, plaintext.len() + 16);

            // Open — output buffer must be >= ct_len for in-place decryption
            let mut pt_buf = vec![0u8; ct_len];
            let mut pt_len: usize = 0;
            let rc = xray_aead_open(
                handle,
                nonce.as_ptr(),
                nonce.len(),
                aad.as_ptr(),
                aad.len(),
                ct_buf.as_ptr(),
                ct_len,
                pt_buf.as_mut_ptr(),
                pt_buf.len(),
                &mut pt_len,
            );
            assert_eq!(rc, 0);
            assert_eq!(pt_len, plaintext.len());
            assert_eq!(&pt_buf[..pt_len], &plaintext[..]);

            xray_aead_free(handle as *mut _);
        }
    }

    #[test]
    fn test_aes_256_gcm_round_trip() {
        let key = [0x42u8; 32];
        let nonce = [0x02u8; 12];
        let plaintext = b"AES-256-GCM test";

        unsafe {
            let handle = xray_aead_new(ALGO_AES_256_GCM, key.as_ptr(), key.len());
            assert!(!handle.is_null());

            let mut ct_buf = vec![0u8; plaintext.len() + 16];
            let mut ct_len: usize = 0;
            let rc = xray_aead_seal(
                handle,
                nonce.as_ptr(),
                nonce.len(),
                std::ptr::null(),
                0,
                plaintext.as_ptr(),
                plaintext.len(),
                ct_buf.as_mut_ptr(),
                ct_buf.len(),
                &mut ct_len,
            );
            assert_eq!(rc, 0);

            let mut pt_buf = vec![0u8; ct_len];
            let mut pt_len: usize = 0;
            let rc = xray_aead_open(
                handle,
                nonce.as_ptr(),
                nonce.len(),
                std::ptr::null(),
                0,
                ct_buf.as_ptr(),
                ct_len,
                pt_buf.as_mut_ptr(),
                pt_buf.len(),
                &mut pt_len,
            );
            assert_eq!(rc, 0);
            assert_eq!(&pt_buf[..pt_len], &plaintext[..]);

            xray_aead_free(handle as *mut _);
        }
    }

    #[test]
    fn test_chacha20_poly1305_round_trip() {
        let key = [0x42u8; 32];
        let nonce = [0x03u8; 12];
        let plaintext = b"ChaCha20-Poly1305 test";

        unsafe {
            let handle = xray_aead_new(ALGO_CHACHA20_POLY1305, key.as_ptr(), key.len());
            assert!(!handle.is_null());

            let mut ct_buf = vec![0u8; plaintext.len() + 16];
            let mut ct_len: usize = 0;
            let rc = xray_aead_seal(
                handle,
                nonce.as_ptr(),
                nonce.len(),
                std::ptr::null(),
                0,
                plaintext.as_ptr(),
                plaintext.len(),
                ct_buf.as_mut_ptr(),
                ct_buf.len(),
                &mut ct_len,
            );
            assert_eq!(rc, 0);

            let mut pt_buf = vec![0u8; ct_len];
            let mut pt_len: usize = 0;
            let rc = xray_aead_open(
                handle,
                nonce.as_ptr(),
                nonce.len(),
                std::ptr::null(),
                0,
                ct_buf.as_ptr(),
                ct_len,
                pt_buf.as_mut_ptr(),
                pt_buf.len(),
                &mut pt_len,
            );
            assert_eq!(rc, 0);
            assert_eq!(&pt_buf[..pt_len], &plaintext[..]);

            xray_aead_free(handle as *mut _);
        }
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = [0x42u8; 16];
        let nonce = [0x04u8; 12];
        let plaintext = b"tamper test";

        unsafe {
            let handle = xray_aead_new(ALGO_AES_128_GCM, key.as_ptr(), key.len());
            assert!(!handle.is_null());

            let mut ct_buf = vec![0u8; plaintext.len() + 16];
            let mut ct_len: usize = 0;
            xray_aead_seal(
                handle,
                nonce.as_ptr(),
                nonce.len(),
                std::ptr::null(),
                0,
                plaintext.as_ptr(),
                plaintext.len(),
                ct_buf.as_mut_ptr(),
                ct_buf.len(),
                &mut ct_len,
            );

            // Tamper with ciphertext
            ct_buf[0] ^= 0xff;

            let mut pt_buf = vec![0u8; ct_len];
            let mut pt_len: usize = 0;
            let rc = xray_aead_open(
                handle,
                nonce.as_ptr(),
                nonce.len(),
                std::ptr::null(),
                0,
                ct_buf.as_ptr(),
                ct_len,
                pt_buf.as_mut_ptr(),
                pt_buf.len(),
                &mut pt_len,
            );
            assert_ne!(rc, 0); // Should fail

            xray_aead_free(handle as *mut _);
        }
    }

    #[test]
    fn test_overhead_and_nonce_size() {
        let key = [0x42u8; 16];
        unsafe {
            let handle = xray_aead_new(ALGO_AES_128_GCM, key.as_ptr(), key.len());
            assert!(!handle.is_null());
            assert_eq!(xray_aead_overhead(handle), 16);
            assert_eq!(xray_aead_nonce_size(handle), 12);
            xray_aead_free(handle as *mut _);
        }
    }
}
