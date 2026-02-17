use std::slice;

/// Derive a key from context string and key material using BLAKE3's KDF mode.
///
/// # Safety
/// All pointer/length pairs must be valid. `out` must point to `out_len` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn xray_blake3_derive_key(
    out: *mut u8,
    out_len: usize,
    ctx: *const u8,
    ctx_len: usize,
    key: *const u8,
    key_len: usize,
) {
    ffi_catch_void!({
        if out_len == 0 || out.is_null() {
            return;
        }
        let ctx = if ctx_len == 0 {
            &[]
        } else {
            if ctx.is_null() {
                return;
            }
            slice::from_raw_parts(ctx, ctx_len)
        };
        let key = if key_len == 0 {
            &[]
        } else {
            if key.is_null() {
                return;
            }
            slice::from_raw_parts(key, key_len)
        };
        let out = slice::from_raw_parts_mut(out, out_len);
        let Ok(ctx_str) = std::str::from_utf8(ctx) else {
            out.fill(0);
            return;
        };

        let mut hasher = blake3::Hasher::new_derive_key(ctx_str);
        hasher.update(key);
        let mut output = hasher.finalize_xof();
        output.fill(out);
    })
}

/// Compute BLAKE3 hash of data, producing a 32-byte digest.
///
/// # Safety
/// `out` must point to at least 32 writable bytes. `data`/`data_len` must be valid.
#[no_mangle]
pub unsafe extern "C" fn xray_blake3_sum256(
    out: *mut u8,
    data: *const u8,
    data_len: usize,
) {
    ffi_catch_void!({
        if out.is_null() {
            return;
        }
        let data = if data_len == 0 {
            &[]
        } else {
            if data.is_null() {
                return;
            }
            slice::from_raw_parts(data, data_len)
        };
        let out = slice::from_raw_parts_mut(out, 32);

        let hash = blake3::hash(data);
        out.copy_from_slice(hash.as_bytes());
    })
}

/// Compute BLAKE3 keyed hash (MAC mode) with a 32-byte key.
///
/// # Safety
/// `key` must point to exactly 32 bytes. `out` must be `out_len` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn xray_blake3_keyed_hash(
    out: *mut u8,
    out_len: usize,
    key: *const u8,
    data: *const u8,
    data_len: usize,
) {
    ffi_catch_void!({
        if out_len == 0 || out.is_null() || key.is_null() {
            return;
        }
        let key_slice = slice::from_raw_parts(key, 32);
        let key: [u8; 32] = key_slice.try_into().unwrap();
        let data = if data_len == 0 {
            &[]
        } else {
            if data.is_null() {
                return;
            }
            slice::from_raw_parts(data, data_len)
        };
        let out = slice::from_raw_parts_mut(out, out_len);

        let mut hasher = blake3::Hasher::new_keyed(&key);
        hasher.update(data);
        let mut output = hasher.finalize_xof();
        output.fill(out);
    })
}
