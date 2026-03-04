//! Minimal TLS 1.3 handshake completion engine.
//!
//! Accepts a pre-built ClientHello (from Go uTLS) and completes the TLS 1.3
//! handshake using raw socket I/O. Does NOT use rustls — implements the
//! minimal subset needed for REALITY integration.
//!
//! Scope: TLS 1.3 only, X25519, AES-128-GCM / AES-256-GCM / ChaCha20-Poly1305,
//! no PSK, no 0-RTT, no client auth.
//!
//! ## Security Model
//!
//! This engine is ONLY safe when used with REALITY authentication.
//! It intentionally skips CertificateVerify validation because REALITY
//! provides its own authentication via ECDH-derived HMAC on the server
//! certificate. The handshake Finished messages provide implicit binding
//! between the certificate and the ECDH shared secret.
//!
//! DO NOT use this engine for standard TLS 1.3 connections — it would
//! be vulnerable to certificate forgery without CertificateVerify.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::os::unix::io::FromRawFd;
use std::sync::atomic::{AtomicU64, Ordering};

use aes_gcm::{aead::Aead, Aes128Gcm, Aes256Gcm, KeyInit};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha384};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Policy for CertificateVerify handling during TLS 1.3 handshake.
///
/// Standard TLS 1.3 REQUIRES CertificateVerify validation (RFC 8446 §4.4.3).
/// This enum forces callers to explicitly declare their verification strategy,
/// preventing accidental use of the no-verify path outside REALITY contexts.
#[derive(Debug, Clone, Copy)]
pub(crate) enum CertVerifyPolicy {
    /// Skip CertificateVerify validation. ONLY safe when REALITY authentication
    /// is used, because REALITY provides its own certificate verification via
    /// ECDH-derived HMAC. The caller MUST perform REALITY HMAC verification
    /// on the server certificate chain after the handshake completes.
    SkipForReality,
}

#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct Tls13State {
    pub client_app_secret: Vec<u8>,
    pub server_app_secret: Vec<u8>,
    pub cipher_suite: u16,
    pub server_cert_chain: Vec<Vec<u8>>,
    pub transcript_hash: Vec<u8>,
    /// Number of server application-data records consumed after the handshake
    /// (typically NewSessionTicket records). This is the correct starting
    /// sequence number for kTLS RX on the client side.
    pub server_post_hs_records: u64,
}

#[derive(Debug)]
pub enum Tls13Error {
    Io(io::Error),
    Protocol(String),
    Crypto(String),
}

impl From<io::Error> for Tls13Error {
    fn from(e: io::Error) -> Self {
        Tls13Error::Io(e)
    }
}

impl std::fmt::Display for Tls13Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Tls13Error::Io(e) => write!(f, "io: {}", e),
            Tls13Error::Protocol(s) => write!(f, "protocol: {}", s),
            Tls13Error::Crypto(s) => write!(f, "crypto: {}", s),
        }
    }
}

// ---------------------------------------------------------------------------
// Hash algorithm abstraction
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq)]
pub enum HashAlg {
    Sha256,
    Sha384,
}

impl HashAlg {
    fn output_len(self) -> usize {
        match self {
            HashAlg::Sha256 => 32,
            HashAlg::Sha384 => 48,
        }
    }

    fn from_cipher_suite(cs: u16) -> Result<Self, Tls13Error> {
        match cs {
            0x1301 | 0x1303 => Ok(HashAlg::Sha256), // TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256
            0x1302 => Ok(HashAlg::Sha384),          // TLS_AES_256_GCM_SHA384
            _ => Err(Tls13Error::Protocol(format!(
                "unsupported cipher suite: 0x{:04x}",
                cs
            ))),
        }
    }
}

fn hash_bytes(alg: HashAlg, data: &[u8]) -> Vec<u8> {
    match alg {
        HashAlg::Sha256 => Sha256::digest(data).to_vec(),
        HashAlg::Sha384 => Sha384::digest(data).to_vec(),
    }
}

fn hash_concat(alg: HashAlg, parts: &[&[u8]]) -> Vec<u8> {
    match alg {
        HashAlg::Sha256 => {
            let mut h = Sha256::new();
            for p in parts {
                h.update(p);
            }
            h.finalize().to_vec()
        }
        HashAlg::Sha384 => {
            let mut h = Sha384::new();
            for p in parts {
                h.update(p);
            }
            h.finalize().to_vec()
        }
    }
}

// ---------------------------------------------------------------------------
// HKDF helpers (RFC 8446 Section 7.1)
// ---------------------------------------------------------------------------

fn hkdf_extract(alg: HashAlg, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    match alg {
        HashAlg::Sha256 => {
            let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), ikm);
            prk.to_vec()
        }
        HashAlg::Sha384 => {
            let (prk, _) = Hkdf::<Sha384>::extract(Some(salt), ikm);
            prk.to_vec()
        }
    }
}

fn hkdf_expand_label(
    alg: HashAlg,
    secret: &[u8],
    label: &str,
    context: &[u8],
    length: usize,
) -> Result<Vec<u8>, Tls13Error> {
    // Build HkdfLabel: length(2) + label(variable) + context(variable)
    let tls_label = format!("tls13 {}", label);
    let label_bytes = tls_label.as_bytes();

    let mut hkdf_label = Vec::with_capacity(2 + 1 + label_bytes.len() + 1 + context.len());
    hkdf_label.extend_from_slice(&(length as u16).to_be_bytes());
    hkdf_label.push(label_bytes.len() as u8);
    hkdf_label.extend_from_slice(label_bytes);
    hkdf_label.push(context.len() as u8);
    hkdf_label.extend_from_slice(context);

    let mut out = vec![0u8; length];
    match alg {
        HashAlg::Sha256 => {
            let hkdf = Hkdf::<Sha256>::from_prk(secret)
                .map_err(|e| Tls13Error::Crypto(format!("hkdf from_prk: {}", e)))?;
            hkdf.expand(&hkdf_label, &mut out)
                .map_err(|e| Tls13Error::Crypto(format!("hkdf expand: {}", e)))?;
        }
        HashAlg::Sha384 => {
            let hkdf = Hkdf::<Sha384>::from_prk(secret)
                .map_err(|e| Tls13Error::Crypto(format!("hkdf from_prk: {}", e)))?;
            hkdf.expand(&hkdf_label, &mut out)
                .map_err(|e| Tls13Error::Crypto(format!("hkdf expand: {}", e)))?;
        }
    }
    Ok(out)
}

fn derive_secret(
    alg: HashAlg,
    secret: &[u8],
    label: &str,
    transcript_hash: &[u8],
) -> Result<Vec<u8>, Tls13Error> {
    hkdf_expand_label(alg, secret, label, transcript_hash, alg.output_len())
}

// ---------------------------------------------------------------------------
// AEAD encryption/decryption
// ---------------------------------------------------------------------------

fn make_nonce(iv: &[u8], seq: u64) -> [u8; 12] {
    assert_eq!(
        iv.len(),
        12,
        "TLS 1.3 IV must be 12 bytes, got {}",
        iv.len()
    );
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(iv);
    let seq_bytes = seq.to_be_bytes();
    for i in 0..8 {
        nonce[4 + i] ^= seq_bytes[i];
    }
    nonce
}

/// Pre-constructed AEAD cipher to avoid per-record key schedule computation.
/// Constructed once per key derivation and reused across all records with that key.
enum CachedCipher {
    Aes128(Aes128Gcm),
    Aes256(Aes256Gcm),
    ChaCha(ChaCha20Poly1305),
}

impl CachedCipher {
    fn new(cipher_suite: u16, key: &[u8]) -> Result<Self, Tls13Error> {
        match cipher_suite {
            0x1301 => Ok(CachedCipher::Aes128(
                Aes128Gcm::new_from_slice(key)
                    .map_err(|e| Tls13Error::Crypto(format!("aes128gcm: {}", e)))?,
            )),
            0x1302 => Ok(CachedCipher::Aes256(
                Aes256Gcm::new_from_slice(key)
                    .map_err(|e| Tls13Error::Crypto(format!("aes256gcm: {}", e)))?,
            )),
            0x1303 => Ok(CachedCipher::ChaCha(
                ChaCha20Poly1305::new_from_slice(key)
                    .map_err(|e| Tls13Error::Crypto(format!("chacha20: {}", e)))?,
            )),
            _ => Err(Tls13Error::Protocol(format!(
                "unsupported cipher: 0x{:04x}",
                cipher_suite
            ))),
        }
    }

    fn decrypt(
        &self,
        iv: &[u8],
        seq: u64,
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, Tls13Error> {
        let nonce = make_nonce(iv, seq);
        match self {
            CachedCipher::Aes128(c) => {
                let payload = aes_gcm::aead::Payload {
                    msg: ciphertext,
                    aad,
                };
                c.decrypt(aes_gcm::Nonce::from_slice(&nonce), payload)
                    .map_err(|e| Tls13Error::Crypto(format!("aes128gcm decrypt: {}", e)))
            }
            CachedCipher::Aes256(c) => {
                let payload = aes_gcm::aead::Payload {
                    msg: ciphertext,
                    aad,
                };
                c.decrypt(aes_gcm::Nonce::from_slice(&nonce), payload)
                    .map_err(|e| Tls13Error::Crypto(format!("aes256gcm decrypt: {}", e)))
            }
            CachedCipher::ChaCha(c) => {
                let payload = chacha20poly1305::aead::Payload {
                    msg: ciphertext,
                    aad,
                };
                c.decrypt(chacha20poly1305::Nonce::from_slice(&nonce), payload)
                    .map_err(|e| Tls13Error::Crypto(format!("chacha20 decrypt: {}", e)))
            }
        }
    }

    fn encrypt(
        &self,
        iv: &[u8],
        seq: u64,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Tls13Error> {
        let nonce = make_nonce(iv, seq);
        match self {
            CachedCipher::Aes128(c) => {
                let payload = aes_gcm::aead::Payload {
                    msg: plaintext,
                    aad,
                };
                c.encrypt(aes_gcm::Nonce::from_slice(&nonce), payload)
                    .map_err(|e| Tls13Error::Crypto(format!("aes128gcm encrypt: {}", e)))
            }
            CachedCipher::Aes256(c) => {
                let payload = aes_gcm::aead::Payload {
                    msg: plaintext,
                    aad,
                };
                c.encrypt(aes_gcm::Nonce::from_slice(&nonce), payload)
                    .map_err(|e| Tls13Error::Crypto(format!("aes256gcm encrypt: {}", e)))
            }
            CachedCipher::ChaCha(c) => {
                let payload = chacha20poly1305::aead::Payload {
                    msg: plaintext,
                    aad,
                };
                c.encrypt(chacha20poly1305::Nonce::from_slice(&nonce), payload)
                    .map_err(|e| Tls13Error::Crypto(format!("chacha20 encrypt: {}", e)))
            }
        }
    }
}

fn key_length(cipher_suite: u16) -> Result<usize, Tls13Error> {
    match cipher_suite {
        0x1301 => Ok(16), // AES-128-GCM
        0x1302 => Ok(32), // AES-256-GCM
        0x1303 => Ok(32), // ChaCha20-Poly1305
        _ => Err(Tls13Error::Protocol(format!(
            "unsupported cipher suite for key derivation: 0x{:04x}",
            cipher_suite
        ))),
    }
}

// ---------------------------------------------------------------------------
// TLS record I/O
// ---------------------------------------------------------------------------

fn send_tls_record(
    stream: &mut TcpStream,
    content_type: u8,
    data: &[u8],
) -> Result<(), Tls13Error> {
    // TLS record: content_type(1) + legacy_version(2) + length(2) + data
    let mut record = Vec::with_capacity(5 + data.len());
    record.push(content_type);
    record.extend_from_slice(&[0x03, 0x01]); // legacy TLS 1.0 for compatibility
    if data.len() > 16384 {
        return Err(Tls13Error::Protocol(format!(
            "record too large: {}",
            data.len()
        )));
    }
    record.extend_from_slice(&(data.len() as u16).to_be_bytes());
    record.extend_from_slice(data);
    stream.write_all(&record)?;
    stream.flush()?;
    Ok(())
}

fn recv_tls_record(stream: &mut TcpStream) -> Result<(u8, Vec<u8>), Tls13Error> {
    let mut header = [0u8; 5];
    stream.read_exact(&mut header)?;

    let content_type = header[0];
    let length = u16::from_be_bytes([header[3], header[4]]) as usize;

    if length > 16384 + 256 {
        return Err(Tls13Error::Protocol(format!(
            "record too large: {}",
            length
        )));
    }

    let mut data = vec![0u8; length];
    stream.read_exact(&mut data)?;

    Ok((content_type, data))
}

fn encrypt_tls13_record(
    cipher: &CachedCipher,
    iv: &[u8],
    seq: u64,
    content_type: u8,
    plaintext: &[u8],
) -> Result<Vec<u8>, Tls13Error> {
    if plaintext.len() > 16384 {
        return Err(Tls13Error::Protocol(format!(
            "plaintext too large for TLS record: {}",
            plaintext.len()
        )));
    }
    // Inner plaintext: content + content_type byte
    let mut inner = Vec::with_capacity(plaintext.len() + 1);
    inner.extend_from_slice(plaintext);
    inner.push(content_type);

    // AAD is the record header with outer content type 0x17 (application data)
    let outer_len_usize = inner.len() + 16; // +16 for AEAD tag
    if outer_len_usize > u16::MAX as usize {
        return Err(Tls13Error::Protocol(format!(
            "AAD outer_len overflow: {}",
            outer_len_usize
        )));
    }
    let outer_len = outer_len_usize as u16;
    let aad = [0x17, 0x03, 0x03, (outer_len >> 8) as u8, outer_len as u8];

    cipher.encrypt(iv, seq, &aad, &inner)
}

fn decrypt_tls13_record(
    cipher: &CachedCipher,
    iv: &[u8],
    seq: u64,
    ciphertext: &[u8],
    record_header: &[u8; 5],
) -> Result<(u8, Vec<u8>), Tls13Error> {
    let plaintext = cipher.decrypt(iv, seq, record_header, ciphertext)?;

    // Find real content type (last non-zero byte)
    let mut ct_idx = plaintext.len();
    while ct_idx > 0 && plaintext[ct_idx - 1] == 0 {
        ct_idx -= 1;
    }
    if ct_idx == 0 {
        return Err(Tls13Error::Protocol("empty inner plaintext".into()));
    }
    let content_type = plaintext[ct_idx - 1];
    let content = plaintext[..ct_idx - 1].to_vec();
    Ok((content_type, content))
}

// ---------------------------------------------------------------------------
// ServerHello parsing
// ---------------------------------------------------------------------------

struct ServerHello {
    server_random: [u8; 32],
    cipher_suite: u16,
    server_x25519_pubkey: [u8; 32],
}

fn parse_server_hello(data: &[u8]) -> Result<ServerHello, Tls13Error> {
    // data is the Handshake message: type(1) + length(3) + body
    if data.len() < 4 {
        return Err(Tls13Error::Protocol("ServerHello too short".into()));
    }
    if data[0] != 0x02 {
        return Err(Tls13Error::Protocol(format!(
            "expected ServerHello (0x02), got 0x{:02x}",
            data[0]
        )));
    }

    let body_len = ((data[1] as usize) << 16) | ((data[2] as usize) << 8) | (data[3] as usize);
    let body = &data[4..4 + body_len.min(data.len() - 4)];

    // body: legacy_version(2) + random(32) + session_id_len(1) + session_id(var)
    //       + cipher_suite(2) + compression(1) + extensions_len(2) + extensions
    if body.len() < 35 {
        return Err(Tls13Error::Protocol("ServerHello body too short".into()));
    }

    let mut server_random = [0u8; 32];
    server_random.copy_from_slice(&body[2..34]);

    let session_id_len = body[34] as usize;
    let pos = 35 + session_id_len;
    if pos + 3 > body.len() {
        return Err(Tls13Error::Protocol(
            "ServerHello truncated after session_id".into(),
        ));
    }

    let cipher_suite = u16::from_be_bytes([body[pos], body[pos + 1]]);
    let _compression = body[pos + 2];

    let ext_pos = pos + 3;
    if ext_pos + 2 > body.len() {
        return Err(Tls13Error::Protocol("no extensions in ServerHello".into()));
    }

    let ext_len = u16::from_be_bytes([body[ext_pos], body[ext_pos + 1]]) as usize;
    let ext_data = &body[ext_pos + 2..];

    // Parse extensions to find key_share (0x0033) and supported_versions (0x002b)
    let mut server_pubkey = [0u8; 32];
    let mut found_key_share = false;
    let mut found_supported_version = false;
    let mut epos = 0;
    while epos + 4 <= ext_data.len().min(ext_len) {
        let etype = u16::from_be_bytes([ext_data[epos], ext_data[epos + 1]]);
        let elen = u16::from_be_bytes([ext_data[epos + 2], ext_data[epos + 3]]) as usize;
        epos += 4;
        if epos + elen > ext_data.len() {
            break;
        }

        if etype == 0x0033 {
            // key_share: group(2) + key_len(2) + key
            let ks = &ext_data[epos..epos + elen];
            if ks.len() >= 4 {
                let group = u16::from_be_bytes([ks[0], ks[1]]);
                let klen = u16::from_be_bytes([ks[2], ks[3]]) as usize;
                if group == 0x001d && klen == 32 && ks.len() >= 4 + 32 {
                    // X25519
                    server_pubkey.copy_from_slice(&ks[4..36]);
                    found_key_share = true;
                }
            }
        } else if etype == 0x002b {
            // supported_versions (RFC 8446 Section 4.2.1): selected version (2 bytes)
            if elen == 2 {
                let ver = u16::from_be_bytes([ext_data[epos], ext_data[epos + 1]]);
                if ver == 0x0304 {
                    found_supported_version = true;
                }
            }
        }

        epos += elen;
    }

    if !found_supported_version {
        return Err(Tls13Error::Protocol(
            "ServerHello missing supported_versions extension with TLS 1.3 (0x0304)".into(),
        ));
    }

    if !found_key_share {
        return Err(Tls13Error::Protocol(
            "no X25519 key_share in ServerHello".into(),
        ));
    }

    Ok(ServerHello {
        server_random,
        cipher_suite,
        server_x25519_pubkey: server_pubkey,
    })
}

// ---------------------------------------------------------------------------
// Handshake message parsing helpers
// ---------------------------------------------------------------------------

fn parse_handshake_messages(data: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut msgs = Vec::new();
    let mut pos = 0;
    while pos + 4 <= data.len() {
        let msg_type = data[pos];
        let msg_len = ((data[pos + 1] as usize) << 16)
            | ((data[pos + 2] as usize) << 8)
            | (data[pos + 3] as usize);
        pos += 4;
        if pos + msg_len > data.len() {
            break;
        }
        msgs.push((msg_type, data[pos - 4..pos + msg_len].to_vec()));
        pos += msg_len;
    }
    msgs
}

fn extract_certificates(cert_msg: &[u8]) -> Vec<Vec<u8>> {
    // Certificate message body (after type+length):
    // request_context_len(1) + request_context + cert_list_len(3) + cert_entries
    let mut certs = Vec::new();
    if cert_msg.len() < 5 {
        return certs;
    }

    // Skip handshake header (type + 3 byte length)
    let body = &cert_msg[4..];
    if body.is_empty() {
        return certs;
    }

    let ctx_len = body[0] as usize;
    let mut pos = 1 + ctx_len;
    if pos + 3 > body.len() {
        return certs;
    }

    let list_len =
        ((body[pos] as usize) << 16) | ((body[pos + 1] as usize) << 8) | (body[pos + 2] as usize);
    pos += 3;
    let end = (pos + list_len).min(body.len());

    while pos + 3 <= end {
        let cert_len = ((body[pos] as usize) << 16)
            | ((body[pos + 1] as usize) << 8)
            | (body[pos + 2] as usize);
        pos += 3;
        if pos + cert_len > end {
            break;
        }
        certs.push(body[pos..pos + cert_len].to_vec());
        pos += cert_len;

        // Skip extensions
        if pos + 2 <= end {
            let ext_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
            pos += 2 + ext_len;
        }
    }

    certs
}

fn compute_finished_verify_data(
    alg: HashAlg,
    base_key: &[u8],
    transcript_hash: &[u8],
) -> Result<Vec<u8>, Tls13Error> {
    let finished_key = hkdf_expand_label(alg, base_key, "finished", &[], alg.output_len())?;

    match alg {
        HashAlg::Sha256 => {
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&finished_key)
                .map_err(|e| Tls13Error::Crypto(format!("hmac new: {}", e)))?;
            mac.update(transcript_hash);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        HashAlg::Sha384 => {
            let mut mac = <Hmac<Sha384> as Mac>::new_from_slice(&finished_key)
                .map_err(|e| Tls13Error::Crypto(format!("hmac new: {}", e)))?;
            mac.update(transcript_hash);
            Ok(mac.finalize().into_bytes().to_vec())
        }
    }
}

/// Consume post-handshake TLS records (NewSessionTicket) from the server.
///
/// After the TLS 1.3 handshake completes, the server typically sends one or
/// more NewSessionTicket records. These are application-data records (outer
/// content type 0x17) that advance the server's TX sequence counter. The
/// client must consume them before installing kTLS RX so that the RX
/// sequence number accounts for these records.
///
/// Uses a 200ms read timeout — the NST arrives in the same TCP flight as
/// the server's Finished message, so it's either already in the receive
/// buffer or arriving within milliseconds.
fn consume_post_handshake_records_tls13(stream: &mut TcpStream) -> u64 {
    // Save current timeout
    let saved_timeout = stream.read_timeout().ok().flatten();

    // Set short timeout for NST drain
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_millis(200)));

    let mut count: u64 = 0;
    loop {
        match recv_tls_record(stream) {
            Ok((ct, _data)) => {
                if ct == 0x14 {
                    // ChangeCipherSpec (compatibility) — ignore, don't count
                    continue;
                }
                // Application data record (0x17) = likely NST
                count += 1;
            }
            Err(_) => {
                // Timeout or error — no more records pending
                break;
            }
        }
    }

    // Restore original timeout
    let _ = stream.set_read_timeout(saved_timeout);

    if count > 0 {
        eprintln!(
            "tls13: consumed {} post-handshake record(s) (rx_seq correction)",
            count
        );
    }
    count
}

// ---------------------------------------------------------------------------
// Main handshake function
// ---------------------------------------------------------------------------

pub fn complete_tls13_handshake(
    fd: i32,
    client_hello_raw: &[u8],
    ecdh_privkey: &[u8; 32],
    cert_verify_policy: CertVerifyPolicy,
) -> Result<Tls13State, Tls13Error> {
    // Dup fd so Rust can own a TcpStream without taking ownership of caller's fd
    let dup_fd = unsafe { libc::dup(fd) };
    if dup_fd < 0 {
        return Err(Tls13Error::Io(io::Error::last_os_error()));
    }
    let mut stream = unsafe { TcpStream::from_raw_fd(dup_fd) };
    let handshake_timeout = std::time::Duration::from_secs(30);
    stream.set_read_timeout(Some(handshake_timeout))?;
    stream.set_write_timeout(Some(handshake_timeout))?;
    let handshake_deadline = std::time::Instant::now() + handshake_timeout;

    // Step 1: Send ClientHello as TLS record
    send_tls_record(&mut stream, 0x16, client_hello_raw)?;

    // Step 2: Read ServerHello
    let (sh_ct, sh_data) = recv_tls_record(&mut stream)?;
    if sh_ct != 0x16 {
        return Err(Tls13Error::Protocol(format!(
            "expected handshake record, got 0x{:02x}",
            sh_ct
        )));
    }

    let server_hello = parse_server_hello(&sh_data)?;
    let cipher_suite = server_hello.cipher_suite;
    let alg = HashAlg::from_cipher_suite(cipher_suite)?;

    // Transcript so far: ClientHello + ServerHello
    const MAX_TRANSCRIPT_SIZE: usize = 256 * 1024; // 256KB — well above any legitimate TLS 1.3 handshake
    let mut transcript = Vec::with_capacity(client_hello_raw.len() + sh_data.len() + 8192);
    transcript.extend_from_slice(client_hello_raw);
    if transcript.len() + sh_data.len() > MAX_TRANSCRIPT_SIZE {
        return Err(Tls13Error::Protocol(
            "transcript size limit exceeded".into(),
        ));
    }
    transcript.extend_from_slice(&sh_data);

    // Step 3: X25519 ECDH
    let privkey = StaticSecret::from(*ecdh_privkey);
    let server_pubkey = PublicKey::from(server_hello.server_x25519_pubkey);
    let shared_secret = privkey.diffie_hellman(&server_pubkey);

    // Step 4: Key schedule
    let hash_len = alg.output_len();
    let zeros = vec![0u8; hash_len];

    // early_secret = HKDF-Extract(salt=zeros, IKM=zeros)
    let early_secret = hkdf_extract(alg, &zeros, &zeros);

    // derive "derived" secret for handshake
    let empty_hash = hash_bytes(alg, &[]);
    let derived_early = derive_secret(alg, &early_secret, "derived", &empty_hash)?;

    // handshake_secret = HKDF-Extract(salt=derived_early, IKM=shared_secret)
    let handshake_secret = hkdf_extract(alg, &derived_early, shared_secret.as_bytes());

    // Transcript hash after ClientHello + ServerHello
    let transcript_hash_ch_sh = hash_bytes(alg, &transcript);

    // Traffic secrets
    let server_hs_secret = derive_secret(
        alg,
        &handshake_secret,
        "s hs traffic",
        &transcript_hash_ch_sh,
    )?;
    let client_hs_secret = derive_secret(
        alg,
        &handshake_secret,
        "c hs traffic",
        &transcript_hash_ch_sh,
    )?;

    // Derive handshake traffic keys and pre-construct AEAD ciphers (once per key)
    let s_hs_key = hkdf_expand_label(
        alg,
        &server_hs_secret,
        "key",
        &[],
        key_length(cipher_suite)?,
    )?;
    let s_hs_iv = hkdf_expand_label(alg, &server_hs_secret, "iv", &[], 12)?;
    let c_hs_key = hkdf_expand_label(
        alg,
        &client_hs_secret,
        "key",
        &[],
        key_length(cipher_suite)?,
    )?;
    let c_hs_iv = hkdf_expand_label(alg, &client_hs_secret, "iv", &[], 12)?;
    let s_hs_cipher = CachedCipher::new(cipher_suite, &s_hs_key)?;
    let c_hs_cipher = CachedCipher::new(cipher_suite, &c_hs_key)?;

    // Step 5-6: Read encrypted handshake messages
    // Server sends: EncryptedExtensions, Certificate, CertificateVerify, Finished
    // These may come in one or multiple records (content_type 0x17 = application data)
    let mut server_hs_seq: u64 = 0;
    let mut all_hs_msgs = Vec::new();
    let mut server_cert_chain = Vec::new();

    // Read records until we've seen all handshake messages
    let mut record_count: usize = 0;
    let mut ccs_count: usize = 0;
    const MAX_HANDSHAKE_RECORDS: usize = 64;
    loop {
        let remaining = handshake_deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Err(Tls13Error::Protocol("handshake timeout exceeded".into()));
        }
        stream.set_read_timeout(Some(remaining))?;
        let (ct, record_data) = recv_tls_record(&mut stream)?;

        if ct == 0x14 {
            // ChangeCipherSpec (compatibility) -- ignore, but cap to prevent flooding
            ccs_count += 1;
            if ccs_count > 4 {
                return Err(Tls13Error::Protocol(
                    "too many ChangeCipherSpec records".into(),
                ));
            }
            continue;
        }

        record_count += 1;
        if record_count > MAX_HANDSHAKE_RECORDS {
            return Err(Tls13Error::Protocol("too many records in handshake".into()));
        }

        if ct != 0x17 {
            return Err(Tls13Error::Protocol(format!(
                "expected app data record (0x17), got 0x{:02x}",
                ct
            )));
        }

        // Reconstruct the record header for AAD
        let record_len = record_data.len() as u16;
        let record_header: [u8; 5] = [0x17, 0x03, 0x03, (record_len >> 8) as u8, record_len as u8];

        // Decrypt
        let (inner_ct, inner_data) = decrypt_tls13_record(
            &s_hs_cipher,
            &s_hs_iv,
            server_hs_seq,
            &record_data,
            &record_header,
        )?;
        server_hs_seq += 1;

        if inner_ct != 0x16 {
            return Err(Tls13Error::Protocol(format!(
                "expected handshake in encrypted record, got 0x{:02x}",
                inner_ct
            )));
        }

        // Parse handshake messages
        let msgs = parse_handshake_messages(&inner_data);
        for (msg_type, msg_data) in &msgs {
            if transcript.len() + msg_data.len() > MAX_TRANSCRIPT_SIZE {
                return Err(Tls13Error::Protocol(
                    "transcript size limit exceeded".into(),
                ));
            }
            match *msg_type {
                0x08 => {
                    // EncryptedExtensions
                    transcript.extend_from_slice(msg_data);
                }
                0x0b => {
                    // Certificate
                    server_cert_chain = extract_certificates(msg_data);
                    transcript.extend_from_slice(msg_data);
                }
                0x0f => {
                    // CertificateVerify handling depends on the caller's policy.
                    match cert_verify_policy {
                        CertVerifyPolicy::SkipForReality => {
                            // Intentionally NOT validated — see module-level Security Model.
                            //
                            // In standard TLS 1.3 (RFC 8446 §4.4.3), CertificateVerify
                            // proves the server holds the private key for the certificate.
                            // We skip this because:
                            //
                            // 1. REALITY uses HMAC-SHA512(auth_key, ed25519_pubkey) instead
                            //    of X.509 chains. Verified by reality_client_connect() after
                            //    the handshake completes.
                            //
                            // 2. The Finished message (verified below at 0x14) binds to the
                            //    X25519 shared secret, providing implicit MITM protection.
                            //
                            // 3. CertificateVerify bytes ARE included in the transcript hash,
                            //    so they still bind to the Finished value.
                        } // Future: CertVerifyPolicy::Verify could validate the signature
                          // against the certificate's public key per RFC 8446.
                    }
                    transcript.extend_from_slice(msg_data);
                }
                0x14 => {
                    // Finished
                    // Verify server Finished
                    let transcript_before_finished = hash_bytes(alg, &transcript);
                    let expected = compute_finished_verify_data(
                        alg,
                        &server_hs_secret,
                        &transcript_before_finished,
                    )?;

                    // Finished message body is after header (4 bytes)
                    if msg_data.len() < 4 + expected.len() {
                        return Err(Tls13Error::Protocol("server Finished too short".into()));
                    }
                    let received = &msg_data[4..4 + expected.len()];
                    if !bool::from(received.ct_eq(expected.as_slice())) {
                        return Err(Tls13Error::Crypto(
                            "server Finished verification failed".into(),
                        ));
                    }

                    // Add Finished to transcript
                    transcript.extend_from_slice(msg_data);
                    all_hs_msgs.push((*msg_type, msg_data.clone()));

                    // We've received everything
                    break;
                }
                _ => {
                    // Unknown handshake type -- add to transcript
                    transcript.extend_from_slice(msg_data);
                }
            }
            if *msg_type != 0x14 {
                all_hs_msgs.push((*msg_type, msg_data.clone()));
            }
        }

        // Check if we've seen Finished
        if all_hs_msgs.iter().any(|(t, _)| *t == 0x14) {
            break;
        }
    }

    // Step 7-8: Send client Finished
    let transcript_hash_for_client_fin = hash_bytes(alg, &transcript);
    let client_verify_data =
        compute_finished_verify_data(alg, &client_hs_secret, &transcript_hash_for_client_fin)?;

    // Build Finished message: type(0x14) + length(3) + verify_data
    let mut finished_msg = Vec::with_capacity(4 + client_verify_data.len());
    finished_msg.push(0x14);
    let vlen = client_verify_data.len();
    finished_msg.push(0);
    finished_msg.push((vlen >> 8) as u8);
    finished_msg.push(vlen as u8);
    finished_msg.extend_from_slice(&client_verify_data);

    // Enforce deadline and shrink write timeout before sending client Finished
    let remaining = handshake_deadline.saturating_duration_since(std::time::Instant::now());
    if remaining.is_zero() {
        return Err(Tls13Error::Protocol("handshake timeout exceeded".into()));
    }
    stream.set_write_timeout(Some(remaining))?;

    // Encrypt and send
    let encrypted = encrypt_tls13_record(
        &c_hs_cipher,
        &c_hs_iv,
        0,    // client handshake seq starts at 0
        0x16, // handshake content type
        &finished_msg,
    )?;

    // Send as application data record
    if encrypted.len() > 16384 + 256 {
        return Err(Tls13Error::Protocol(format!(
            "encrypted record too large: {}",
            encrypted.len()
        )));
    }
    let outer_len = encrypted.len() as u16;
    let mut record = Vec::with_capacity(5 + encrypted.len());
    record.push(0x17); // application data
    record.extend_from_slice(&[0x03, 0x03]); // TLS 1.2 (compatibility)
    record.extend_from_slice(&outer_len.to_be_bytes());
    record.extend_from_slice(&encrypted);
    stream.write_all(&record)?;
    stream.flush()?;

    // Add client Finished to transcript
    transcript.extend_from_slice(&finished_msg);

    // Step 9: Derive application traffic secrets
    let derived_hs = derive_secret(alg, &handshake_secret, "derived", &empty_hash)?;
    let master_secret = hkdf_extract(alg, &derived_hs, &zeros);

    let full_transcript_hash = hash_bytes(alg, &transcript);
    let client_app_secret =
        derive_secret(alg, &master_secret, "c ap traffic", &full_transcript_hash)?;
    let server_app_secret =
        derive_secret(alg, &master_secret, "s ap traffic", &full_transcript_hash)?;

    // Step 10: Consume post-handshake records (NewSessionTicket) so that
    // the kTLS RX sequence number accounts for them. Without this, the
    // client installs kTLS RX with seq=0 while the server's kTLS TX starts
    // at seq=N (where N = number of NST records), causing AEAD nonce
    // mismatch and EBADMSG on every read. See docs/ktls-nst-sequence-bug.md.
    let server_post_hs_records = consume_post_handshake_records_tls13(&mut stream);

    // Drop the dup'd stream (closes dup'd fd)
    drop(stream);

    Ok(Tls13State {
        client_app_secret,
        server_app_secret,
        cipher_suite,
        server_cert_chain,
        transcript_hash: full_transcript_hash,
        server_post_hs_records,
    })
}

// ---------------------------------------------------------------------------
// FFI Exports
// ---------------------------------------------------------------------------

#[repr(C)]
pub struct XrayTls13Result {
    pub cipher_suite: u16,
    pub client_secret: [u8; 48], // copied inline (max SHA-384 = 48 bytes)
    pub client_secret_len: u8,
    pub server_secret: [u8; 48],
    pub server_secret_len: u8,
    // Correct starting RX sequence for kTLS installation.
    // Equals the number of post-handshake server records (e.g. NST)
    // consumed by the handshake engine.
    pub rx_seq_start: u64,
    pub transcript_hash: [u8; 48],
    pub transcript_hash_len: u8,
    pub cert_chain_written: usize, // bytes written to Go-provided cert buffer
    pub cert_chain_needed: usize,  // total bytes needed
    pub error_code: i32,
    pub error_msg: [u8; 256],
}

impl XrayTls13Result {
    fn new() -> Self {
        Self {
            cipher_suite: 0,
            client_secret: [0u8; 48],
            client_secret_len: 0,
            server_secret: [0u8; 48],
            server_secret_len: 0,
            rx_seq_start: 0,
            transcript_hash: [0u8; 48],
            transcript_hash_len: 0,
            cert_chain_written: 0,
            cert_chain_needed: 0,
            error_code: 0,
            error_msg: [0u8; 256],
        }
    }

    fn set_error(&mut self, code: i32, msg: &str) {
        self.error_code = code;
        let bytes = msg.as_bytes();
        let len = bytes.len().min(255);
        self.error_msg[..len].copy_from_slice(&bytes[..len]);
        self.error_msg[len] = 0;
    }
}

/// Install kTLS for a TLS 1.3 connection using secrets from the minimal
/// handshake engine. Called internally from the REALITY client path.
/// Returns (ktls_tx, ktls_rx).
///
/// The RX sequence number is set to `state.server_post_hs_records` to
/// account for NewSessionTicket records consumed by the handshake engine
/// before kTLS installation. Without this, the client's kTLS RX nonce
/// would be desynchronized from the server's kTLS TX nonce.
pub(crate) fn install_ktls_from_tls13_state(fd: i32, state: &Tls13State) -> (bool, bool) {
    let inner = || -> Result<(bool, bool), Tls13Error> {
        let cs = state.cipher_suite;
        let alg = HashAlg::from_cipher_suite(cs)?;

        let tx_key = hkdf_expand_label(alg, &state.client_app_secret, "key", &[], key_length(cs)?)?;
        let tx_iv = hkdf_expand_label(alg, &state.client_app_secret, "iv", &[], 12)?;
        let rx_key = hkdf_expand_label(alg, &state.server_app_secret, "key", &[], key_length(cs)?)?;
        let rx_iv = hkdf_expand_label(alg, &state.server_app_secret, "iv", &[], 12)?;

        if crate::tls::setup_ulp_pub(fd).is_err() {
            return Ok((false, false));
        }

        // TX seq=0: client hasn't sent any application data yet
        let tx_ok = install_ktls_raw(fd, 1, cs, &tx_key, &tx_iv, 0).is_ok();
        // RX seq=N: account for N post-handshake records (NSTs) the server sent
        let rx_seq = state.server_post_hs_records;
        let rx_ok = install_ktls_raw(fd, 2, cs, &rx_key, &rx_iv, rx_seq).is_ok();
        Ok((tx_ok, rx_ok))
    };
    inner().unwrap_or((false, false))
}

#[no_mangle]
pub extern "C" fn xray_tls13_handshake(
    fd: i32,
    client_hello_ptr: *const u8,
    client_hello_len: usize,
    ecdh_privkey_ptr: *const u8,
    cert_buf_ptr: *mut u8,
    cert_buf_cap: usize,
    out: *mut XrayTls13Result,
) -> i32 {
    ffi_catch_i32!({
        if out.is_null() {
            return -1;
        }
        if client_hello_ptr.is_null() || ecdh_privkey_ptr.is_null() {
            let out = unsafe { &mut *out };
            *out = XrayTls13Result::new();
            out.set_error(-1, "null input pointer");
            return -1;
        }
        let out = unsafe { &mut *out };
        *out = XrayTls13Result::new();

        if client_hello_len > 16388 {
            out.set_error(-1, "client_hello_len exceeds TLS record limit");
            return -1;
        }

        let ch = unsafe { std::slice::from_raw_parts(client_hello_ptr, client_hello_len) };
        let pk = unsafe { std::slice::from_raw_parts(ecdh_privkey_ptr, 32) };
        let mut privkey = zeroize::Zeroizing::new([0u8; 32]);
        privkey.copy_from_slice(pk);

        match complete_tls13_handshake(fd, ch, &privkey, CertVerifyPolicy::SkipForReality) {
            Ok(state) => {
                out.cipher_suite = state.cipher_suite;

                // Copy secrets inline
                let cs_len = state.client_app_secret.len().min(48);
                out.client_secret[..cs_len].copy_from_slice(&state.client_app_secret[..cs_len]);
                out.client_secret_len = cs_len as u8;

                let ss_len = state.server_app_secret.len().min(48);
                out.server_secret[..ss_len].copy_from_slice(&state.server_app_secret[..ss_len]);
                out.server_secret_len = ss_len as u8;
                out.rx_seq_start = state.server_post_hs_records;

                let th_len = state.transcript_hash.len().min(48);
                out.transcript_hash[..th_len].copy_from_slice(&state.transcript_hash[..th_len]);
                out.transcript_hash_len = th_len as u8;

                // Serialize cert chain into Go-provided buffer
                // Format: count(4 LE) + [len(4 LE) + der_bytes]*
                let mut cert_data = Vec::new();
                cert_data.extend_from_slice(&(state.server_cert_chain.len() as u32).to_le_bytes());
                for cert in &state.server_cert_chain {
                    cert_data.extend_from_slice(&(cert.len() as u32).to_le_bytes());
                    cert_data.extend_from_slice(cert);
                }
                out.cert_chain_needed = cert_data.len();

                if !cert_buf_ptr.is_null() && cert_buf_cap > 0 {
                    let write_len = cert_data.len().min(cert_buf_cap);
                    let dest = unsafe { std::slice::from_raw_parts_mut(cert_buf_ptr, write_len) };
                    dest.copy_from_slice(&cert_data[..write_len]);
                    out.cert_chain_written = write_len;
                }
                0
            }
            Err(e) => {
                out.set_error(1, &e.to_string());
                1
            }
        }
    })
}

/// No-op: XrayTls13Result no longer holds an opaque state handle.
/// Kept for backward compatibility with Go callers.
#[no_mangle]
pub extern "C" fn xray_tls13_state_free(_state: *mut std::ffi::c_void) {
    ffi_catch_void!({
        // No-op: all data is now copied inline into XrayTls13Result.
    })
}

static TLS13_INSTALL_CALLS: AtomicU64 = AtomicU64::new(0);
static TLS13_INSTALL_RX_SEQ_NONZERO: AtomicU64 = AtomicU64::new(0);
static TLS13_INSTALL_LEGACY_REJECTED: AtomicU64 = AtomicU64::new(0);

fn maybe_log_tls13_install_markers(calls: u64) {
    if calls == 1 || calls % 64 == 0 {
        let nonzero = TLS13_INSTALL_RX_SEQ_NONZERO.load(Ordering::Relaxed);
        let rejected = TLS13_INSTALL_LEGACY_REJECTED.load(Ordering::Relaxed);
        eprintln!(
            "tls13 markers[kind=tls13-install]: calls={} rx_seq_nonzero={} legacy_api_rejected={}",
            calls, nonzero, rejected
        );
    }
}

fn install_ktls_from_secrets(
    fd: i32,
    cipher_suite: u16,
    client_secret: &[u8],
    server_secret: &[u8],
    rx_seq_start: u64,
) -> Result<(bool, bool), Tls13Error> {
    let alg = HashAlg::from_cipher_suite(cipher_suite)?;
    let tx_key = hkdf_expand_label(alg, client_secret, "key", &[], key_length(cipher_suite)?)?;
    let tx_iv = hkdf_expand_label(alg, client_secret, "iv", &[], 12)?;
    let rx_key = hkdf_expand_label(alg, server_secret, "key", &[], key_length(cipher_suite)?)?;
    let rx_iv = hkdf_expand_label(alg, server_secret, "iv", &[], 12)?;

    if crate::tls::setup_ulp_pub(fd).is_err() {
        return Ok((false, false));
    }

    let tx_ok = install_ktls_raw(fd, 1, cipher_suite, &tx_key, &tx_iv, 0).is_ok();
    let rx_ok = install_ktls_raw(fd, 2, cipher_suite, &rx_key, &rx_iv, rx_seq_start).is_ok();
    Ok((tx_ok, rx_ok))
}

/// Install kTLS using application traffic secrets directly.
/// Called after xray_tls13_handshake succeeds — secrets are passed from Go
/// (which copied them from the XrayTls13Result inline arrays).
///
/// Legacy API note: this function lacks RX sequence input and therefore cannot
/// safely install TLS RX for TLS 1.3 when post-handshake records were consumed.
/// It fails closed and instructs callers to use
/// `xray_tls13_install_ktls_with_rx_seq`.
#[no_mangle]
pub extern "C" fn xray_tls13_install_ktls(
    _fd: i32,
    _cipher_suite: u16,
    _client_secret_ptr: *const u8,
    _client_secret_len: usize,
    _server_secret_ptr: *const u8,
    _server_secret_len: usize,
    out_ktls_tx: *mut bool,
    out_ktls_rx: *mut bool,
) -> i32 {
    ffi_catch_i32!({
        if out_ktls_tx.is_null() || out_ktls_rx.is_null() {
            return -1;
        }
        unsafe {
            *out_ktls_tx = false;
            *out_ktls_rx = false;
        }
        let calls = TLS13_INSTALL_CALLS.fetch_add(1, Ordering::Relaxed) + 1;
        let rejected = TLS13_INSTALL_LEGACY_REJECTED.fetch_add(1, Ordering::Relaxed) + 1;
        maybe_log_tls13_install_markers(calls);
        if rejected <= 3 || rejected % 64 == 0 {
            eprintln!(
                "[kind=tls13.rx_seq_missing] xray_tls13_install_ktls called without rx_seq_start; refusing install. use xray_tls13_install_ktls_with_rx_seq"
            );
        }
        -1
    })
}

/// Install kTLS using TLS 1.3 application traffic secrets and explicit RX
/// sequence start (post-handshake record count).
#[no_mangle]
pub extern "C" fn xray_tls13_install_ktls_with_rx_seq(
    fd: i32,
    cipher_suite: u16,
    client_secret_ptr: *const u8,
    client_secret_len: usize,
    server_secret_ptr: *const u8,
    server_secret_len: usize,
    rx_seq_start: u64,
    out_ktls_tx: *mut bool,
    out_ktls_rx: *mut bool,
) -> i32 {
    ffi_catch_i32!({
        if out_ktls_tx.is_null() || out_ktls_rx.is_null() {
            return -1;
        }
        if client_secret_ptr.is_null() || server_secret_ptr.is_null() {
            return -1;
        }

        let calls = TLS13_INSTALL_CALLS.fetch_add(1, Ordering::Relaxed) + 1;
        if rx_seq_start > 0 {
            TLS13_INSTALL_RX_SEQ_NONZERO.fetch_add(1, Ordering::Relaxed);
        }
        maybe_log_tls13_install_markers(calls);

        let client_secret =
            unsafe { std::slice::from_raw_parts(client_secret_ptr, client_secret_len) };
        let server_secret =
            unsafe { std::slice::from_raw_parts(server_secret_ptr, server_secret_len) };

        let (tx_ok, rx_ok) =
            install_ktls_from_secrets(fd, cipher_suite, client_secret, server_secret, rx_seq_start)
                .unwrap_or((false, false));
        unsafe {
            *out_ktls_tx = tx_ok;
            *out_ktls_rx = rx_ok;
        }
        0
    })
}

/// Low-level kTLS install using raw key/iv bytes.
fn install_ktls_raw(
    fd: i32,
    direction: i32,
    cipher_suite: u16,
    key: &[u8],
    iv: &[u8],
    seq: u64,
) -> io::Result<()> {
    use crate::tls::{
        TlsCryptoInfoAesGcm128, TlsCryptoInfoAesGcm256, TlsCryptoInfoChacha20Poly1305, SOL_TLS,
        TLS_1_3_VERSION, TLS_CIPHER_AES_GCM_128, TLS_CIPHER_AES_GCM_256,
        TLS_CIPHER_CHACHA20_POLY1305,
    };

    let rec_seq = seq.to_be_bytes();

    match cipher_suite {
        0x1301 => {
            let mut info = TlsCryptoInfoAesGcm128 {
                version: TLS_1_3_VERSION,
                cipher_type: TLS_CIPHER_AES_GCM_128,
                iv: [0u8; 8],
                key: [0u8; 16],
                salt: [0u8; 4],
                rec_seq,
            };
            info.salt.copy_from_slice(&iv[..4]);
            info.iv.copy_from_slice(&iv[4..12]);
            info.key.copy_from_slice(key);
            let ret = unsafe {
                libc::setsockopt(
                    fd,
                    SOL_TLS,
                    direction,
                    &info as *const _ as *const std::ffi::c_void,
                    std::mem::size_of_val(&info) as libc::socklen_t,
                )
            };
            info.key.zeroize();
            info.iv.zeroize();
            info.salt.zeroize();
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        0x1302 => {
            let mut info = TlsCryptoInfoAesGcm256 {
                version: TLS_1_3_VERSION,
                cipher_type: TLS_CIPHER_AES_GCM_256,
                iv: [0u8; 8],
                key: [0u8; 32],
                salt: [0u8; 4],
                rec_seq,
            };
            info.salt.copy_from_slice(&iv[..4]);
            info.iv.copy_from_slice(&iv[4..12]);
            info.key.copy_from_slice(key);
            let ret = unsafe {
                libc::setsockopt(
                    fd,
                    SOL_TLS,
                    direction,
                    &info as *const _ as *const std::ffi::c_void,
                    std::mem::size_of_val(&info) as libc::socklen_t,
                )
            };
            info.key.zeroize();
            info.iv.zeroize();
            info.salt.zeroize();
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        0x1303 => {
            let mut info = TlsCryptoInfoChacha20Poly1305 {
                version: TLS_1_3_VERSION,
                cipher_type: TLS_CIPHER_CHACHA20_POLY1305,
                iv: [0u8; 12],
                key: [0u8; 32],
                rec_seq,
            };
            info.iv.copy_from_slice(iv);
            info.key.copy_from_slice(key);
            let ret = unsafe {
                libc::setsockopt(
                    fd,
                    SOL_TLS,
                    direction,
                    &info as *const _ as *const std::ffi::c_void,
                    std::mem::size_of_val(&info) as libc::socklen_t,
                )
            };
            info.key.zeroize();
            info.iv.zeroize();
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "unsupported cipher for kTLS",
            ));
        }
    }
    Ok(())
}
