//! VMess AEAD header seal/open — single FFI call.
//!
//! Collapses the KDF chain (nested HMAC-SHA256) + double AES-GCM seal/open
//! into a single FFI call, eliminating per-connection allocation overhead.

use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::rand::SecureRandom;
use std::slice;

// KDF salt constants — must match proxy/vmess/aead/consts.go exactly.
const KDF_SALT_VMESS_AEAD_KDF: &[u8] = b"VMess AEAD KDF";
const KDF_SALT_HEADER_PAYLOAD_LENGTH_AEAD_KEY: &[u8] = b"VMess Header AEAD Key_Length";
const KDF_SALT_HEADER_PAYLOAD_LENGTH_AEAD_IV: &[u8] = b"VMess Header AEAD Nonce_Length";
const KDF_SALT_HEADER_PAYLOAD_AEAD_KEY: &[u8] = b"VMess Header AEAD Key";
const KDF_SALT_HEADER_PAYLOAD_AEAD_IV: &[u8] = b"VMess Header AEAD Nonce";
const KDF_SALT_AUTH_ID_ENCRYPTION_KEY: &[u8] = b"AES Auth ID Encryption";

// SHA-256 block size and digest size
const SHA256_BLOCK: usize = 64;
const SHA256_DIGEST: usize = 32;

/// Low-level SHA-256 wrapper using ring's digest module.
fn sha256(data: &[u8]) -> [u8; SHA256_DIGEST] {
    let d = ring::digest::digest(&ring::digest::SHA256, data);
    let mut out = [0u8; SHA256_DIGEST];
    out.copy_from_slice(d.as_ref());
    out
}

/// Compute HMAC-SHA256 using raw SHA-256 operations.
/// HMAC(K, m) = SHA256((K ^ opad) || SHA256((K ^ ipad) || m))
fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; SHA256_DIGEST] {
    let mut k_padded = [0u8; SHA256_BLOCK];
    if key.len() > SHA256_BLOCK {
        let hashed = sha256(key);
        k_padded[..SHA256_DIGEST].copy_from_slice(&hashed);
    } else {
        k_padded[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0u8; SHA256_BLOCK];
    let mut opad = [0u8; SHA256_BLOCK];
    for i in 0..SHA256_BLOCK {
        ipad[i] = k_padded[i] ^ 0x36;
        opad[i] = k_padded[i] ^ 0x5c;
    }

    // Inner: SHA256(ipad || msg)
    let mut inner_data = Vec::with_capacity(SHA256_BLOCK + msg.len());
    inner_data.extend_from_slice(&ipad);
    inner_data.extend_from_slice(msg);
    let inner_hash = sha256(&inner_data);

    // Outer: SHA256(opad || inner_hash)
    let mut outer_data = [0u8; SHA256_BLOCK + SHA256_DIGEST];
    outer_data[..SHA256_BLOCK].copy_from_slice(&opad);
    outer_data[SHA256_BLOCK..].copy_from_slice(&inner_hash);
    sha256(&outer_data)
}

/// Compute HMAC-SHA256 with multiple message parts concatenated.
fn hmac_sha256_multi(key: &[u8], parts: &[&[u8]]) -> [u8; SHA256_DIGEST] {
    let mut k_padded = [0u8; SHA256_BLOCK];
    if key.len() > SHA256_BLOCK {
        let hashed = sha256(key);
        k_padded[..SHA256_DIGEST].copy_from_slice(&hashed);
    } else {
        k_padded[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0u8; SHA256_BLOCK];
    let mut opad = [0u8; SHA256_BLOCK];
    for i in 0..SHA256_BLOCK {
        ipad[i] = k_padded[i] ^ 0x36;
        opad[i] = k_padded[i] ^ 0x5c;
    }

    // Inner: SHA256(ipad || part0 || part1 || ...)
    let total: usize = parts.iter().map(|p| p.len()).sum();
    let mut inner_data = Vec::with_capacity(SHA256_BLOCK + total);
    inner_data.extend_from_slice(&ipad);
    for part in parts {
        inner_data.extend_from_slice(part);
    }
    let inner_hash = sha256(&inner_data);

    // Outer: SHA256(opad || inner_hash)
    let mut outer_data = [0u8; SHA256_BLOCK + SHA256_DIGEST];
    outer_data[..SHA256_BLOCK].copy_from_slice(&opad);
    outer_data[SHA256_BLOCK..].copy_from_slice(&inner_hash);
    sha256(&outer_data)
}

/// Compute HMAC pads for a key (returns ipad, opad as 64-byte arrays).
fn hmac_pads(key: &[u8]) -> ([u8; SHA256_BLOCK], [u8; SHA256_BLOCK]) {
    let mut k_padded = [0u8; SHA256_BLOCK];
    if key.len() > SHA256_BLOCK {
        let hashed = sha256(key);
        k_padded[..SHA256_DIGEST].copy_from_slice(&hashed);
    } else {
        k_padded[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0u8; SHA256_BLOCK];
    let mut opad = [0u8; SHA256_BLOCK];
    for i in 0..SHA256_BLOCK {
        ipad[i] = k_padded[i] ^ 0x36;
        opad[i] = k_padded[i] ^ 0x5c;
    }
    (ipad, opad)
}

/// Reimplementation of the VMess KDF.
///
/// The Go KDF uses a recursive HMAC construction where each level wraps
/// the previous level's HMAC as both inner and outer hash (shared state).
///
/// Go's `hmac.New` creates inner/outer hashes that share the same underlying
/// hash object. Calling `Sum()` on level N triggers a recursive chain:
///
/// ```text
/// sum(level, sha256_data):
///   if level == 0:
///     return SHA256(salt_opad || SHA256(sha256_data))
///   else:
///     inner = sum(level - 1, sha256_data)
///     new_data = salt_ipad || ipad[0..level-2] || opad[level-1] || inner
///     return sum(level - 1, new_data)
/// ```
///
/// Initial call: `sum(N, salt_ipad || ipad[0] || ... || ipad[N-1] || key)`
fn kdf(key: &[u8], paths: &[&[u8]]) -> [u8; SHA256_DIGEST] {
    if paths.is_empty() {
        return hmac_sha256(KDF_SALT_VMESS_AEAD_KDF, key);
    }

    let (salt_ipad, salt_opad) = hmac_pads(KDF_SALT_VMESS_AEAD_KDF);
    let pads: Vec<([u8; SHA256_BLOCK], [u8; SHA256_BLOCK])> =
        paths.iter().map(|p| hmac_pads(p)).collect();

    // Build initial SHA-256 data: salt_ipad || ipad[0] || ... || ipad[N-1] || key
    let mut initial = Vec::with_capacity(SHA256_BLOCK * (paths.len() + 1) + key.len());
    initial.extend_from_slice(&salt_ipad);
    for (ipad, _) in &pads {
        initial.extend_from_slice(ipad);
    }
    initial.extend_from_slice(key);

    recursive_sum(paths.len(), &initial, &pads, &salt_ipad, &salt_opad)
}

/// Recursive computation mirroring Go's shared-state HMAC Sum() chain.
///
/// At level 0: plain HMAC(KDFSalt, data) via raw SHA-256.
/// At level k: inner = sum(k-1, data), then wrap with opad[k-1] after reset.
fn recursive_sum(
    level: usize,
    sha256_data: &[u8],
    pads: &[([u8; SHA256_BLOCK], [u8; SHA256_BLOCK])],
    salt_ipad: &[u8; SHA256_BLOCK],
    salt_opad: &[u8; SHA256_BLOCK],
) -> [u8; SHA256_DIGEST] {
    if level == 0 {
        // Base: SHA256(salt_opad || SHA256(sha256_data))
        let inner = sha256(sha256_data);
        let mut outer = [0u8; SHA256_BLOCK + SHA256_DIGEST];
        outer[..SHA256_BLOCK].copy_from_slice(salt_opad);
        outer[SHA256_BLOCK..].copy_from_slice(&inner);
        return sha256(&outer);
    }

    // Inner computation with current data
    let inner = recursive_sum(level - 1, sha256_data, pads, salt_ipad, salt_opad);

    // After Reset at levels 0..level-1, SHA-256 state becomes:
    //   salt_ipad || ipad[0] || ... || ipad[level-2]
    // Then opad[level-1] and the inner result are appended.
    let mut new_data = Vec::with_capacity(SHA256_BLOCK * (level + 1) + SHA256_DIGEST);
    new_data.extend_from_slice(salt_ipad);
    for i in 0..level.saturating_sub(1) {
        new_data.extend_from_slice(&pads[i].0); // ipad
    }
    new_data.extend_from_slice(&pads[level - 1].1); // opad
    new_data.extend_from_slice(&inner);

    recursive_sum(level - 1, &new_data, pads, salt_ipad, salt_opad)
}

fn kdf16(key: &[u8], paths: &[&[u8]]) -> [u8; 16] {
    let full = kdf(key, paths);
    let mut result = [0u8; 16];
    result.copy_from_slice(&full[..16]);
    result
}

/// AES-128-ECB encrypt a single 16-byte block.
fn aes_ecb_encrypt(key: &[u8; 16], block: &mut [u8; 16]) {
    use aes_gcm::aes::cipher::{BlockEncrypt, KeyInit};
    use aes_gcm::aes::Aes128;

    let cipher = Aes128::new(key.into());
    let block_ref = aes_gcm::aes::Block::from_mut_slice(block);
    cipher.encrypt_block(block_ref);
}

/// Create AuthID: AES-ECB encrypt(timestamp[8] || random[4] || crc32[4])
fn create_auth_id(cmd_key: &[u8; 16]) -> Result<[u8; 16], i32> {
    let enc_key = kdf16(cmd_key, &[KDF_SALT_AUTH_ID_ENCRYPTION_KEY]);

    let mut buf = [0u8; 16];
    // Timestamp (8 bytes, big-endian)
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(std::time::Duration::ZERO)
        .as_secs() as i64;
    buf[..8].copy_from_slice(&now.to_be_bytes());

    // Random (4 bytes)
    ring::rand::SystemRandom::new()
        .fill(&mut buf[8..12])
        .map_err(|_| crate::ffi::FFI_ERR_CRYPTO)?;

    // CRC32 (IEEE) of first 12 bytes
    let crc = crc32_ieee(&buf[..12]);
    buf[12..16].copy_from_slice(&crc.to_be_bytes());

    // AES-ECB encrypt
    aes_ecb_encrypt(&enc_key, &mut buf);

    Ok(buf)
}

/// IEEE CRC32 (same as Go's crc32.ChecksumIEEE)
fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    crc ^ 0xFFFF_FFFF
}

/// Inner seal logic returning Result for clean error propagation.
fn seal_header_inner(cmd_key: &[u8; 16], header_data: &[u8], out_buf: &mut [u8]) -> Result<usize, i32> {
    let header_len = header_data.len();

    // Create AuthID
    let auth_id = create_auth_id(cmd_key)?;

    // Generate connection nonce
    let mut conn_nonce = [0u8; 8];
    ring::rand::SystemRandom::new()
        .fill(&mut conn_nonce)
        .map_err(|_| crate::ffi::FFI_ERR_CRYPTO)?;

    // Derive keys for length encryption
    let length_key = kdf16(
        cmd_key,
        &[KDF_SALT_HEADER_PAYLOAD_LENGTH_AEAD_KEY, &auth_id, &conn_nonce],
    );
    let length_nonce_full = kdf(
        cmd_key,
        &[KDF_SALT_HEADER_PAYLOAD_LENGTH_AEAD_IV, &auth_id, &conn_nonce],
    );

    // Derive keys for header encryption
    let header_key = kdf16(
        cmd_key,
        &[KDF_SALT_HEADER_PAYLOAD_AEAD_KEY, &auth_id, &conn_nonce],
    );
    let header_nonce_full = kdf(
        cmd_key,
        &[KDF_SALT_HEADER_PAYLOAD_AEAD_IV, &auth_id, &conn_nonce],
    );

    // Encrypt length (2 bytes -> 18 bytes with tag)
    let length_val = (header_len as u16).to_be_bytes();
    let length_aead_key = LessSafeKey::new(
        UnboundKey::new(&aead::AES_128_GCM, &length_key)
            .map_err(|_| crate::ffi::FFI_ERR_CRYPTO)?,
    );
    let mut length_ct = [0u8; 18]; // 2 + 16
    length_ct[..2].copy_from_slice(&length_val);
    let nonce = Nonce::try_assume_unique_for_key(&length_nonce_full[..12])
        .map_err(|_| crate::ffi::FFI_ERR_CRYPTO)?;
    let tag = length_aead_key
        .seal_in_place_separate_tag(nonce, Aad::from(&auth_id[..]), &mut length_ct[..2])
        .map_err(|_| crate::ffi::FFI_ERR_CRYPTO)?;
    length_ct[2..18].copy_from_slice(tag.as_ref());

    // Encrypt header
    let header_aead_key = LessSafeKey::new(
        UnboundKey::new(&aead::AES_128_GCM, &header_key)
            .map_err(|_| crate::ffi::FFI_ERR_CRYPTO)?,
    );
    let mut header_ct = vec![0u8; header_len + 16];
    header_ct[..header_len].copy_from_slice(header_data);
    let nonce = Nonce::try_assume_unique_for_key(&header_nonce_full[..12])
        .map_err(|_| crate::ffi::FFI_ERR_CRYPTO)?;
    let tag = header_aead_key
        .seal_in_place_separate_tag(
            nonce,
            Aad::from(&auth_id[..]),
            &mut header_ct[..header_len],
        )
        .map_err(|_| crate::ffi::FFI_ERR_CRYPTO)?;
    header_ct[header_len..].copy_from_slice(tag.as_ref());

    // Write output: authid[16] + enc_length[18] + nonce[8] + enc_header[len+16]
    let mut pos = 0;
    out_buf[pos..pos + 16].copy_from_slice(&auth_id);
    pos += 16;
    out_buf[pos..pos + 18].copy_from_slice(&length_ct);
    pos += 18;
    out_buf[pos..pos + 8].copy_from_slice(&conn_nonce);
    pos += 8;
    out_buf[pos..pos + header_ct.len()].copy_from_slice(&header_ct);
    pos += header_ct.len();

    Ok(pos)
}

/// Seal a VMess AEAD header.
///
/// Input: cmdKey[16], header data.
/// Output: authid[16] + encrypted_length[18] + nonce[8] + encrypted_header[len+16]
///
/// # Safety
/// All pointer/length pairs must be valid.
#[no_mangle]
pub unsafe extern "C" fn xray_vmess_seal_header(
    cmd_key: *const u8,
    header: *const u8,
    header_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    ffi_catch_i32!({
        if cmd_key.is_null() || out.is_null() || out_len.is_null() {
            return crate::ffi::FFI_ERR_NULL;
        }
        if header.is_null() && header_len > 0 {
            return crate::ffi::FFI_ERR_NULL;
        }

        let cmd_key_bytes: [u8; 16] = {
            let mut k = [0u8; 16];
            k.copy_from_slice(slice::from_raw_parts(cmd_key, 16));
            k
        };
        let header_data = if header_len > 0 {
            slice::from_raw_parts(header, header_len)
        } else {
            &[]
        };

        // Total output: 16 (authid) + 18 (enc length) + 8 (nonce) + header_len + 16 (tag)
        let total = 16 + 18 + 8 + header_len + 16;
        if out_cap < total {
            return crate::ffi::FFI_ERR_APP;
        }

        let out_buf = slice::from_raw_parts_mut(out, out_cap);
        match seal_header_inner(&cmd_key_bytes, header_data, out_buf) {
            Ok(n) => {
                *out_len = n;
                crate::ffi::FFI_OK
            }
            Err(code) => code,
        }
    })
}

/// Inner open logic returning Result for clean error propagation.
fn open_header_inner(cmd_key: &[u8; 16], auth_id: &[u8; 16], data_buf: &[u8], out_buf: &mut [u8]) -> Result<usize, i32> {
    // Parse: encrypted_length[18] + nonce[8] + encrypted_header[...]
    let enc_length = &data_buf[..18];
    let conn_nonce = &data_buf[18..26];
    let enc_header = &data_buf[26..];

    // Derive keys for length decryption
    let length_key = kdf16(
        cmd_key,
        &[KDF_SALT_HEADER_PAYLOAD_LENGTH_AEAD_KEY, auth_id, conn_nonce],
    );
    let length_nonce_full = kdf(
        cmd_key,
        &[KDF_SALT_HEADER_PAYLOAD_LENGTH_AEAD_IV, auth_id, conn_nonce],
    );

    // Decrypt length
    let length_aead_key = LessSafeKey::new(
        UnboundKey::new(&aead::AES_128_GCM, &length_key)
            .map_err(|_| crate::ffi::FFI_ERR_CRYPTO)?,
    );
    let mut length_buf = [0u8; 18];
    length_buf.copy_from_slice(enc_length);
    let nonce = Nonce::try_assume_unique_for_key(&length_nonce_full[..12])
        .map_err(|_| crate::ffi::FFI_ERR_CRYPTO)?;
    let plaintext_length = match length_aead_key.open_in_place(
        nonce,
        Aad::from(&auth_id[..]),
        &mut length_buf,
    ) {
        Ok(pt) => {
            if pt.len() != 2 {
                return Err(crate::ffi::FFI_ERR_CRYPTO);
            }
            u16::from_be_bytes([pt[0], pt[1]]) as usize
        }
        Err(_) => return Err(crate::ffi::FFI_ERR_CRYPTO),
    };

    // Check we have enough data for the header
    let expected_enc_header_len = plaintext_length + 16;
    if enc_header.len() < expected_enc_header_len {
        return Err(crate::ffi::FFI_ERR_APP);
    }
    if out_buf.len() < plaintext_length {
        return Err(crate::ffi::FFI_ERR_APP);
    }

    // Derive keys for header decryption
    let header_key = kdf16(
        cmd_key,
        &[KDF_SALT_HEADER_PAYLOAD_AEAD_KEY, auth_id, conn_nonce],
    );
    let header_nonce_full = kdf(
        cmd_key,
        &[KDF_SALT_HEADER_PAYLOAD_AEAD_IV, auth_id, conn_nonce],
    );

    // Decrypt header
    let header_aead_key = LessSafeKey::new(
        UnboundKey::new(&aead::AES_128_GCM, &header_key)
            .map_err(|_| crate::ffi::FFI_ERR_CRYPTO)?,
    );
    let mut header_buf = vec![0u8; expected_enc_header_len];
    header_buf.copy_from_slice(&enc_header[..expected_enc_header_len]);
    let nonce = Nonce::try_assume_unique_for_key(&header_nonce_full[..12])
        .map_err(|_| crate::ffi::FFI_ERR_CRYPTO)?;
    match header_aead_key.open_in_place(
        nonce,
        Aad::from(&auth_id[..]),
        &mut header_buf,
    ) {
        Ok(pt) => {
            out_buf[..pt.len()].copy_from_slice(pt);
            Ok(pt.len())
        }
        Err(_) => Err(crate::ffi::FFI_ERR_CRYPTO),
    }
}

/// Open a VMess AEAD header.
///
/// Input: cmdKey[16], authid[16], data (encrypted_length[18] + nonce[8] + encrypted_header[...])
/// Output: decrypted header
///
/// Returns 0 on success, FFI_ERR_CRYPTO on auth failure.
///
/// # Safety
/// All pointer/length pairs must be valid.
#[no_mangle]
pub unsafe extern "C" fn xray_vmess_open_header(
    cmd_key: *const u8,
    authid: *const u8,
    data: *const u8,
    data_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    ffi_catch_i32!({
        if cmd_key.is_null() || authid.is_null() || data.is_null() || out.is_null() || out_len.is_null() {
            return crate::ffi::FFI_ERR_NULL;
        }
        // Minimum: 18 (enc_length) + 8 (nonce) = 26 bytes
        if data_len < 26 {
            return crate::ffi::FFI_ERR_APP;
        }

        let cmd_key_bytes: [u8; 16] = {
            let mut k = [0u8; 16];
            k.copy_from_slice(slice::from_raw_parts(cmd_key, 16));
            k
        };
        let auth_id_bytes: [u8; 16] = {
            let mut a = [0u8; 16];
            a.copy_from_slice(slice::from_raw_parts(authid, 16));
            a
        };
        let data_buf = slice::from_raw_parts(data, data_len);
        let out_buf = slice::from_raw_parts_mut(out, out_cap);

        match open_header_inner(&cmd_key_bytes, &auth_id_bytes, data_buf, out_buf) {
            Ok(n) => {
                *out_len = n;
                crate::ffi::FFI_OK
            }
            Err(code) => code,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kdf_no_paths() {
        let key = b"Demo Key for KDF";
        let result = kdf(key, &[]);
        assert_eq!(
            hex::encode(result),
            "9b7c777a29c4c0a15e2ca745e097c956d075684710981479b0dbe6ac383fafb9"
        );
    }

    #[test]
    fn test_kdf_one_path() {
        let key = b"Demo Key for KDF";
        let result = kdf(key, &[b"path_one"]);
        assert_eq!(
            hex::encode(result),
            "3ead5daaac7ee08053b120d862587679c1a539f69009e9d002c71c36845371ed"
        );
    }

    #[test]
    fn test_kdf_two_paths() {
        let key = b"Demo Key for KDF";
        let result = kdf(key, &[b"path_one", b"path_two"]);
        assert_eq!(
            hex::encode(result),
            "a18094b6aa3d50019d585898abc2e5556b79da6b694d7e2787a67646a417ec86"
        );
    }

    #[test]
    fn test_kdf_three_paths() {
        let key = b"Demo Key for KDF";
        let result = kdf(
            key,
            &[
                b"VMess Header AEAD Key_Length",
                b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
                b"\x10\x11\x12\x13\x14\x15\x16\x17",
            ],
        );
        assert_eq!(
            hex::encode(result),
            "2f8e8794eeef4aa0798981e75553bbe20ec1a073b5b222597ee9e0dd92bf2b94"
        );
    }

    #[test]
    fn test_kdf16() {
        let key = b"Demo Key for KDF";
        let result = kdf16(
            key,
            &[
                b"VMess Header AEAD Key_Length",
                b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
                b"\x10\x11\x12\x13\x14\x15\x16\x17",
            ],
        );
        assert_eq!(hex::encode(result), "2f8e8794eeef4aa0798981e75553bbe2");
    }

    #[test]
    fn test_kdf_auth_key() {
        let key = b"Demo Key for KDF";
        let result = kdf16(key, &[KDF_SALT_AUTH_ID_ENCRYPTION_KEY]);
        assert_eq!(hex::encode(result), "a30e0b1a1790abaa372ca1e24f49e247");
    }

    #[test]
    fn test_kdf_derived_keys() {
        let cmd_key: [u8; 16] = [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16];
        let authid: [u8; 16] = [0xAA,0xBB,0xCC,0xDD,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0x00,0xEE,0xFF];
        let nonce: [u8; 8] = [1,2,3,4,5,6,7,8];

        let len_key = kdf16(&cmd_key, &[KDF_SALT_HEADER_PAYLOAD_LENGTH_AEAD_KEY, &authid, &nonce]);
        assert_eq!(hex::encode(len_key), "e2b8ce928a988bc8dc473f12c74bd21a");

        let len_nonce = kdf(&cmd_key, &[KDF_SALT_HEADER_PAYLOAD_LENGTH_AEAD_IV, &authid, &nonce]);
        assert_eq!(hex::encode(&len_nonce[..12]), "85fb26f7561ddac2ba960e2a");

        let hdr_key = kdf16(&cmd_key, &[KDF_SALT_HEADER_PAYLOAD_AEAD_KEY, &authid, &nonce]);
        assert_eq!(hex::encode(hdr_key), "92f57e7847f3cb97c379ccac221df8b8");

        let hdr_nonce = kdf(&cmd_key, &[KDF_SALT_HEADER_PAYLOAD_AEAD_IV, &authid, &nonce]);
        assert_eq!(hex::encode(&hdr_nonce[..12]), "94d563a3b219b6e46860143d");
    }

    #[test]
    fn test_seal_open_round_trip() {
        let cmd_key: [u8; 16] = [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16];
        let header = b"Test VMess Header Data";

        unsafe {
            let mut sealed = vec![0u8; 16 + 18 + 8 + header.len() + 16 + 64]; // extra space
            let mut sealed_len: usize = 0;

            let rc = xray_vmess_seal_header(
                cmd_key.as_ptr(), header.as_ptr(), header.len(),
                sealed.as_mut_ptr(), sealed.len(), &mut sealed_len,
            );
            assert_eq!(rc, 0);
            assert_eq!(sealed_len, 16 + 18 + 8 + header.len() + 16);

            // Extract authid and remaining data
            let authid = &sealed[..16];
            let data = &sealed[16..sealed_len];

            let mut opened = vec![0u8; header.len() + 64];
            let mut opened_len: usize = 0;

            let rc = xray_vmess_open_header(
                cmd_key.as_ptr(), authid.as_ptr(),
                data.as_ptr(), data.len(),
                opened.as_mut_ptr(), opened.len(), &mut opened_len,
            );
            assert_eq!(rc, 0, "open failed");
            assert_eq!(opened_len, header.len());
            assert_eq!(&opened[..opened_len], &header[..]);
        }
    }

    #[test]
    fn test_crc32_ieee() {
        // Known CRC32 value
        assert_eq!(crc32_ieee(b"hello"), 0x3610a686);
        assert_eq!(crc32_ieee(b""), 0x00000000);
    }

    // Need hex crate for tests
    mod hex {
        pub fn encode(data: impl AsRef<[u8]>) -> String {
            data.as_ref().iter().map(|b| format!("{:02x}", b)).collect()
        }
    }
}
