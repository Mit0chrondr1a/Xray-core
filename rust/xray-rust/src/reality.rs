//! REALITY protocol implementation.
//!
//! REALITY is an anti-censorship protocol that disguises proxy traffic as
//! legitimate TLS connections to real websites. It embeds authentication data
//! in the ClientHello SessionId field and uses a custom certificate verification
//! scheme based on ECDH shared secrets.

use std::ffi::c_void;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::os::unix::io::FromRawFd;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes128Gcm,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection};
use sha2::{Sha256, Sha512};
use x25519_dalek::{PublicKey, StaticSecret};

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::tls::{self, TlsState, XrayTlsResult};
use crate::tls13::{self, Tls13Error, Tls13State};

// ---------------------------------------------------------------------------
// Public result types
// ---------------------------------------------------------------------------

#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct RealityResult {
    pub tls_state: Tls13State,
    pub auth_key: Vec<u8>,
}

#[derive(Debug)]
pub enum RealityError {
    Tls(Tls13Error),
    AuthFailed(String),
    Io(io::Error),
    Protocol(String),
}

impl From<Tls13Error> for RealityError {
    fn from(e: Tls13Error) -> Self {
        RealityError::Tls(e)
    }
}

impl From<io::Error> for RealityError {
    fn from(e: io::Error) -> Self {
        RealityError::Io(e)
    }
}

impl std::fmt::Display for RealityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RealityError::Tls(e) => write!(f, "tls: {}", e),
            RealityError::AuthFailed(s) => write!(f, "auth: {}", s),
            RealityError::Io(e) => write!(f, "io: {}", e),
            RealityError::Protocol(s) => write!(f, "protocol: {}", s),
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn reality_auth_key(shared_secret: &[u8], random_prefix: &[u8]) -> Result<Vec<u8>, RealityError> {
    // AuthKey = HKDF-SHA256(shared_secret, random[:20], info="REALITY")
    let hkdf = Hkdf::<Sha256>::new(Some(random_prefix), shared_secret);
    let mut key = vec![0u8; 32];
    hkdf.expand(b"REALITY", &mut key)
        .map_err(|e| RealityError::Protocol(format!("hkdf expand: {}", e)))?;
    Ok(key)
}

fn aes_gcm_seal(key: &[u8], nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes128Gcm::new_from_slice(&key[..16]).map_err(|e| format!("aes key: {}", e))?;
    let nonce = aes_gcm::Nonce::from_slice(nonce);
    let payload = aes_gcm::aead::Payload {
        msg: plaintext,
        aad,
    };
    cipher
        .encrypt(nonce, payload)
        .map_err(|e| format!("aes seal: {}", e))
}

fn aes_gcm_open(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    let cipher = Aes128Gcm::new_from_slice(&key[..16]).map_err(|e| format!("aes key: {}", e))?;
    let nonce = aes_gcm::Nonce::from_slice(nonce);
    let payload = aes_gcm::aead::Payload {
        msg: ciphertext,
        aad,
    };
    cipher
        .decrypt(nonce, payload)
        .map_err(|e| format!("aes open: {}", e))
}

/// Verify a REALITY certificate: the server generates an Ed25519 cert with
/// `Signature = HMAC-SHA512(AuthKey, Ed25519PublicKey)`. We extract the
/// public key and signature from the DER and verify the HMAC.
///
/// Matches Go's `VerifyPeerCertificate` at reality.go:108-119.
fn verify_reality_cert_hmac(cert_der: &[u8], auth_key: &[u8]) -> bool {
    // X.509 Certificate is: SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    // We need the Ed25519 public key from tbsCertificate and the signature BIT STRING.
    //
    // The signature is the last field — a BIT STRING containing the HMAC (64 bytes).
    // The public key is inside tbsCertificate > SubjectPublicKeyInfo > BIT STRING (32 bytes).

    let (pubkey, signature) = match extract_ed25519_pubkey_and_signature(cert_der) {
        Some(v) => v,
        None => return false,
    };

    let mut mac = match <Hmac<Sha512> as Mac>::new_from_slice(auth_key) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(&pubkey);
    // Constant-time comparison via hmac crate's verify_slice
    mac.verify_slice(&signature).is_ok()
}

/// Minimal DER parsing to extract the Ed25519 public key and the signature
/// from an X.509 certificate. Returns (pubkey_32_bytes, signature_64_bytes).
fn extract_ed25519_pubkey_and_signature(cert_der: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    // Certificate ::= SEQUENCE { tbsCert, sigAlgo, sigValue }
    let (_, cert_content) = der_read_tag_length(cert_der, 0x30)?;

    // tbsCertificate: skip it to get to sigAlgo and sigValue
    let (tbs_total_len, _) = der_read_tag_length(cert_content, 0x30)?;
    let after_tbs = &cert_content[tbs_total_len..];

    // signatureAlgorithm: SEQUENCE (skip)
    let (sig_algo_total_len, _) = der_read_tag_length(after_tbs, 0x30)?;
    let after_sig_algo = &after_tbs[sig_algo_total_len..];

    // signatureValue: BIT STRING
    let (_, sig_content) = der_read_tag_length(after_sig_algo, 0x03)?;
    if sig_content.is_empty() {
        return None;
    }
    // BIT STRING has a leading "unused bits" byte (should be 0)
    let signature = sig_content[1..].to_vec();

    // Now extract pubkey from tbsCertificate
    let (_, tbs_content) = der_read_tag_length(cert_content, 0x30)?;
    let pubkey = extract_ed25519_pubkey_from_tbs(tbs_content)?;

    Some((pubkey, signature))
}

/// Walk through TBSCertificate fields to find SubjectPublicKeyInfo and
/// extract the Ed25519 public key (32 bytes).
fn extract_ed25519_pubkey_from_tbs(tbs: &[u8]) -> Option<Vec<u8>> {
    let mut pos = 0;
    // TBSCertificate fields:
    // [0] version (EXPLICIT), serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo

    // Skip 6 fields to reach subjectPublicKeyInfo (index 6)
    for _ in 0..6 {
        if pos >= tbs.len() {
            return None;
        }
        let total = der_element_total_length(tbs, pos)?;
        pos += total;
    }

    if pos >= tbs.len() {
        return None;
    }

    // subjectPublicKeyInfo: SEQUENCE { algorithm, subjectPublicKey }
    let (_, spki_content) = der_read_tag_length(&tbs[pos..], 0x30)?;

    // algorithm: SEQUENCE (skip)
    let (algo_total, _) = der_read_tag_length(spki_content, 0x30)?;

    // subjectPublicKey: BIT STRING
    let pubkey_bitstr = &spki_content[algo_total..];
    let (_, pk_content) = der_read_tag_length(pubkey_bitstr, 0x03)?;
    if pk_content.is_empty() {
        return None;
    }
    // Skip unused-bits byte
    Some(pk_content[1..].to_vec())
}

/// Read a DER tag and length at position 0 of `data`. Expected tag must match.
/// Returns (total_element_length, content_slice).
fn der_read_tag_length(data: &[u8], expected_tag: u8) -> Option<(usize, &[u8])> {
    if data.is_empty() || data[0] != expected_tag {
        return None;
    }
    let (header_len, content_len) = der_parse_length(&data[1..])?;
    let total = 1 + header_len + content_len;
    if total > data.len() {
        return None;
    }
    Some((total, &data[1 + header_len..1 + header_len + content_len]))
}

/// Parse a DER length field. Returns (length_field_size, content_length).
fn der_parse_length(data: &[u8]) -> Option<(usize, usize)> {
    if data.is_empty() {
        return None;
    }
    if data[0] < 0x80 {
        Some((1, data[0] as usize))
    } else if data[0] == 0x81 {
        if data.len() < 2 {
            return None;
        }
        Some((2, data[1] as usize))
    } else if data[0] == 0x82 {
        if data.len() < 3 {
            return None;
        }
        Some((3, ((data[1] as usize) << 8) | data[2] as usize))
    } else {
        None // lengths > 65535 not expected in REALITY certs
    }
}

/// Calculate the total byte length of a DER element starting at `offset`.
fn der_element_total_length(data: &[u8], offset: usize) -> Option<usize> {
    if offset >= data.len() {
        return None;
    }
    let rest = &data[offset..];
    if rest.len() < 2 {
        return None;
    }
    let (header_len, content_len) = der_parse_length(&rest[1..])?;
    Some(1 + header_len + content_len)
}

// ---------------------------------------------------------------------------
// Client: embed REALITY auth in SessionId and complete handshake
// ---------------------------------------------------------------------------

pub fn reality_client_connect(
    fd: i32,
    client_hello_raw: &mut [u8],
    ecdh_privkey: &[u8; 32],
    server_pubkey: &[u8; 32],
    short_id: &[u8],
    client_version: (u8, u8, u8),
) -> Result<RealityResult, RealityError> {
    // The ClientHello is a handshake message: type(1) + length(3) + body
    // body: version(2) + random(32) + session_id_len(1) + session_id(32) + ...
    // random starts at offset 6 (4 header + 2 version)
    // session_id_len at offset 38, session_id at offset 39

    if client_hello_raw.len() < 71 {
        return Err(RealityError::Protocol("ClientHello too short".into()));
    }

    // Extract Random
    let random: [u8; 32] = {
        let mut r = [0u8; 32];
        r.copy_from_slice(&client_hello_raw[6..38]);
        r
    };

    // ECDH with REALITY server's public key
    let privkey = StaticSecret::from(*ecdh_privkey);
    let pubkey = PublicKey::from(*server_pubkey);
    let shared_secret = privkey.diffie_hellman(&pubkey);

    // Derive auth key
    let auth_key = reality_auth_key(shared_secret.as_bytes(), &random[..20])?;

    // Build session_id plaintext: version(3) + reserved(1) + timestamp(4) + short_id(8)
    let mut session_id_plain = [0u8; 16];
    session_id_plain[0] = client_version.0;
    session_id_plain[1] = client_version.1;
    session_id_plain[2] = client_version.2;
    session_id_plain[3] = 0; // reserved

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32;
    session_id_plain[4..8].copy_from_slice(&timestamp.to_be_bytes());

    let sid_len = short_id.len().min(8);
    session_id_plain[8..8 + sid_len].copy_from_slice(&short_id[..sid_len]);

    // AES-GCM-128 seal: nonce=random[20:32], plaintext=session_id[0..16],
    // aad=ClientHello raw with session_id zeroed (matches Go's REALITY client).
    let nonce = &random[20..32];
    // Zero session_id in the raw buffer to build AAD (Go zeros it before Seal).
    client_hello_raw[39..71].fill(0);
    let encrypted = aes_gcm_seal(&auth_key, nonce, &session_id_plain, client_hello_raw)
        .map_err(|e| RealityError::Protocol(e))?;

    // Overwrite session_id in ClientHello (offset 39, 32 bytes)
    if encrypted.len() != 32 {
        return Err(RealityError::Protocol(format!(
            "expected 32 byte encrypted session_id, got {}",
            encrypted.len()
        )));
    }
    client_hello_raw[39..71].copy_from_slice(&encrypted);

    // Complete the TLS 1.3 handshake. tls13::complete_tls13_handshake()
    // skips CertificateVerify — REALITY relies on the HMAC-based cert
    // verification below (verify_reality_cert_hmac) and the Finished
    // message's implicit binding to the ECDH shared secret instead.
    let tls_state = tls13::complete_tls13_handshake(fd, client_hello_raw, ecdh_privkey)?;

    // Verify REALITY certificate: the server's cert must have an Ed25519 public
    // key whose HMAC-SHA512(auth_key, pubkey) equals the certificate's signature.
    // This matches Go's VerifyPeerCertificate at reality.go:108-119.
    if !tls_state.server_cert_chain.is_empty() {
        let cert_der = &tls_state.server_cert_chain[0];
        if !verify_reality_cert_hmac(cert_der, &auth_key) {
            return Err(RealityError::AuthFailed(
                "server cert HMAC verification failed".into(),
            ));
        }
    } else {
        return Err(RealityError::AuthFailed(
            "server sent no certificates".into(),
        ));
    }

    Ok(RealityResult {
        tls_state,
        auth_key,
    })
}

// ---------------------------------------------------------------------------
// Server: parse ClientHello, validate REALITY auth
// ---------------------------------------------------------------------------

#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct RealityServerResult {
    pub authenticated: bool,
    pub client_version: (u8, u8, u8),
    pub short_id: Vec<u8>,
    pub auth_key: Vec<u8>,
    pub sni: String,
    pub client_hello_raw: Vec<u8>,
}

fn server_name_allowed(server_names: &[String], sni: &str) -> bool {
    server_names.iter().any(|name| name == sni)
}

fn timestamp_within_max_diff(timestamp: u32, max_time_diff_ms: u64) -> bool {
    timestamp_within_max_diff_at(timestamp, max_time_diff_ms, SystemTime::now())
}

fn timestamp_within_max_diff_at(timestamp: u32, max_time_diff_ms: u64, now: SystemTime) -> bool {
    if max_time_diff_ms == 0 {
        return true;
    }

    let ts = UNIX_EPOCH + Duration::from_secs(timestamp as u64);
    let diff = match now.duration_since(ts) {
        Ok(d) => d,
        Err(e) => e.duration(),
    };

    diff <= Duration::from_millis(max_time_diff_ms)
}

pub fn reality_server_accept(
    fd: i32,
    private_key: &[u8; 32],
    short_ids: &[Vec<u8>],
    server_names: &[String],
    max_time_diff: u64,
    version_range: ((u8, u8, u8), (u8, u8, u8)),
) -> Result<RealityServerResult, RealityError> {
    // Read the first TLS record (ClientHello)
    let dup_fd = unsafe { libc::dup(fd) };
    if dup_fd < 0 {
        return Err(RealityError::Io(io::Error::last_os_error()));
    }
    let mut stream = unsafe { TcpStream::from_raw_fd(dup_fd) };

    // Read TLS record header
    let mut header = [0u8; 5];
    stream.read_exact(&mut header)?;
    let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;

    if record_len > 16384 {
        drop(stream);
        return Err(RealityError::Protocol(
            "ClientHello record too large".into(),
        ));
    }

    let mut ch_raw = vec![0u8; record_len];
    stream.read_exact(&mut ch_raw)?;
    drop(stream);

    // Parse ClientHello handshake message
    if ch_raw.len() < 71 || ch_raw[0] != 0x01 {
        return Err(RealityError::Protocol("not a ClientHello".into()));
    }

    // Extract Random (offset 6)
    let random: [u8; 32] = {
        let mut r = [0u8; 32];
        r.copy_from_slice(&ch_raw[6..38]);
        r
    };

    // Extract encrypted session_id (offset 39, 32 bytes)
    let session_id_len = ch_raw[38] as usize;
    if session_id_len != 32 {
        return Err(RealityError::AuthFailed("session_id not 32 bytes".into()));
    }
    let encrypted_session_id = ch_raw[39..71].to_vec();

    // Extract SNI from extensions
    let sni = parse_sni_from_client_hello(&ch_raw).unwrap_or_default();
    if !server_name_allowed(server_names, &sni) {
        return Err(RealityError::AuthFailed(format!(
            "server name mismatch: {}",
            sni
        )));
    }

    // Find the client's X25519 key_share
    let client_x25519 = parse_x25519_key_share(&ch_raw)
        .ok_or_else(|| RealityError::Protocol("no X25519 key_share in ClientHello".into()))?;

    // ECDH
    let privkey = StaticSecret::from(*private_key);
    let client_pubkey = PublicKey::from(client_x25519);
    let shared_secret = privkey.diffie_hellman(&client_pubkey);

    // Derive auth key
    let auth_key = reality_auth_key(shared_secret.as_bytes(), &random[..20])?;

    // Decrypt session_id: nonce=random[20:32], ciphertext=encrypted_session_id,
    // aad=ClientHello raw with session_id zeroed (matches Go's REALITY server).
    let nonce = &random[20..32];
    let mut aad = ch_raw.clone();
    aad[39..71].fill(0);
    let plaintext = aes_gcm_open(&auth_key, nonce, &encrypted_session_id, &aad)
        .map_err(|e| RealityError::AuthFailed(format!("session_id decrypt: {}", e)))?;

    if plaintext.len() != 16 {
        return Err(RealityError::AuthFailed(
            "decrypted session_id wrong size".into(),
        ));
    }

    // Parse: version(3) + reserved(1) + timestamp(4) + short_id(8)
    let client_ver = (plaintext[0], plaintext[1], plaintext[2]);
    let timestamp = u32::from_be_bytes([plaintext[4], plaintext[5], plaintext[6], plaintext[7]]);
    let short_id = plaintext[8..16].to_vec();

    // Validate version range
    let (min_ver, max_ver) = version_range;
    let ver_tuple = (client_ver.0, client_ver.1, client_ver.2);
    if ver_tuple < min_ver || ver_tuple > max_ver {
        return Err(RealityError::AuthFailed(format!(
            "client version {}.{}.{} out of range",
            client_ver.0, client_ver.1, client_ver.2
        )));
    }

    // Validate timestamp (max_time_diff=0 disables time check, matching Go REALITY)
    if !timestamp_within_max_diff(timestamp, max_time_diff) {
        return Err(RealityError::AuthFailed(format!(
            "timestamp exceeds max_time_diff {}ms",
            max_time_diff
        )));
    }

    // Validate short_id (constant-time comparison for defense-in-depth)
    let short_id_trimmed: Vec<u8> = short_id.iter().copied().take_while(|&b| b != 0).collect();
    let mut short_id_matched = false;
    for s in short_ids {
        let trimmed_match: bool =
            s.len() == short_id_trimmed.len() && s.ct_eq(&short_id_trimmed).into();
        let full_match: bool = s.len() == short_id.len() && s.ct_eq(&short_id).into();
        short_id_matched |= trimmed_match || full_match;
    }
    if !short_id_matched {
        return Err(RealityError::AuthFailed(
            "short_id not in allowed list".into(),
        ));
    }

    Ok(RealityServerResult {
        authenticated: true,
        client_version: client_ver,
        short_id,
        auth_key,
        sni,
        client_hello_raw: ch_raw,
    })
}

// ---------------------------------------------------------------------------
// Server: full REALITY handshake (auth + rustls + kTLS)
// ---------------------------------------------------------------------------

/// Build a minimal self-signed X.509 DER certificate with an Ed25519 public
/// key and a custom "signature" that is actually HMAC-SHA512(auth_key, pubkey).
/// This matches the Go client's VerifyPeerCertificate at reality.go:108-119.
fn build_reality_cert(
    _ed25519_pkcs8: &[u8],
    ed25519_pub: &[u8],
    auth_key: &[u8],
    sni: &str,
) -> Result<Vec<u8>, String> {
    // Compute HMAC-SHA512(AuthKey, ed25519_pubkey) as the "signature"
    let mut mac =
        <Hmac<Sha512> as Mac>::new_from_slice(auth_key).map_err(|e| format!("hmac: {}", e))?;
    mac.update(ed25519_pub);
    let hmac_sig = mac.finalize().into_bytes(); // 64 bytes

    // Build DER manually
    let cn_value = sni.as_bytes();

    // --- SubjectPublicKeyInfo for Ed25519 ---
    // AlgorithmIdentifier: OID 1.3.101.112
    let algo_id = &[0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70];
    // BIT STRING wrapping the 32-byte Ed25519 public key
    let mut spki = Vec::new();
    spki.extend_from_slice(algo_id);
    spki.push(0x03); // BIT STRING tag
    der_push_length(&mut spki, ed25519_pub.len() + 1);
    spki.push(0x00); // no unused bits
    spki.extend_from_slice(ed25519_pub);
    let spki_seq = der_sequence(&spki);

    // --- RDNSequence: CN=sni ---
    let cn_attr_value = der_wrap(0x0c, cn_value); // UTF8String
    let cn_attr = der_sequence(
        &[
            &[0x06, 0x03, 0x55, 0x04, 0x03][..], // OID 2.5.4.3
            &cn_attr_value,
        ]
        .concat(),
    );
    let cn_rdn = der_wrap(0x31, &cn_attr); // SET OF
    let name = der_sequence(&cn_rdn);

    // --- Validity: now to now+1hour ---
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let not_before = der_utctime(now);
    let not_after = der_utctime(now + 3600);
    let validity = der_sequence(&[not_before, not_after].concat());

    // --- TBSCertificate ---
    let version = &[0xa0, 0x03, 0x02, 0x01, 0x02]; // [0] EXPLICIT INTEGER 2 (v3)
    let serial = &[0x02, 0x01, 0x01]; // INTEGER 1
    let sig_algo = der_sequence(&[0x06, 0x03, 0x2b, 0x65, 0x70]); // Ed25519 OID

    let mut tbs_contents = Vec::new();
    tbs_contents.extend_from_slice(version);
    tbs_contents.extend_from_slice(serial);
    tbs_contents.extend_from_slice(&sig_algo);
    tbs_contents.extend_from_slice(&name); // issuer
    tbs_contents.extend_from_slice(&validity);
    tbs_contents.extend_from_slice(&name); // subject = issuer
    tbs_contents.extend_from_slice(&spki_seq);
    let tbs = der_sequence(&tbs_contents);

    // --- Certificate ---
    let sig_bits = der_bitstring(&hmac_sig);
    let cert = der_sequence(&[tbs, sig_algo.clone(), sig_bits].concat());

    Ok(cert)
}

fn der_wrap(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    der_push_length(&mut out, content.len());
    out.extend_from_slice(content);
    out
}

fn der_sequence(content: &[u8]) -> Vec<u8> {
    der_wrap(0x30, content)
}

fn der_bitstring(content: &[u8]) -> Vec<u8> {
    let mut out = vec![0x03];
    der_push_length(&mut out, content.len() + 1);
    out.push(0x00); // no unused bits
    out.extend_from_slice(content);
    out
}

fn der_push_length(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len < 0x100 {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    }
}

fn der_utctime(epoch_secs: u64) -> Vec<u8> {
    // Convert epoch to UTCTime: YYMMDDHHMMSSZ
    // Simple calculation without chrono
    let secs_per_day = 86400u64;
    let days = epoch_secs / secs_per_day;
    let day_secs = epoch_secs % secs_per_day;
    let hours = day_secs / 3600;
    let minutes = (day_secs % 3600) / 60;
    let seconds = day_secs % 60;

    // Days since 1970-01-01 to Y-M-D (simplified Gregorian)
    let (year, month, day) = days_to_ymd(days);
    let yy = year % 100;

    let s = format!(
        "{:02}{:02}{:02}{:02}{:02}{:02}Z",
        yy, month, day, hours, minutes, seconds
    );
    der_wrap(0x17, s.as_bytes())
}

fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    let mut year = 1970u64;
    loop {
        let days_in_year = if is_leap(year) { 366 } else { 365 };
        if days < days_in_year {
            break;
        }
        days -= days_in_year;
        year += 1;
    }
    let leap = is_leap(year);
    let month_days: [u64; 12] = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 1u64;
    for &md in &month_days {
        if days < md {
            break;
        }
        days -= md;
        month += 1;
    }
    (year, month, days + 1)
}

fn is_leap(y: u64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

/// Peek at N bytes from a socket using MSG_PEEK (non-consuming).
/// Blocks until all bytes are available or an error occurs.
fn peek_exact(fd: i32, buf: &mut [u8]) -> io::Result<()> {
    loop {
        let n = unsafe {
            libc::recv(
                fd,
                buf.as_mut_ptr() as *mut c_void,
                buf.len(),
                libc::MSG_PEEK | libc::MSG_WAITALL,
            )
        };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "peer closed"));
        }
        if (n as usize) < buf.len() {
            // MSG_PEEK|MSG_WAITALL may return short on some kernels; retry
            continue;
        }
        return Ok(());
    }
}

/// Perform the full REALITY server handshake: auth validation + rustls + kTLS.
///
/// Auth validation uses MSG_PEEK so that on auth failure, the socket data
/// remains unconsumed and the Go fallback can handle camouflage.
///
/// Returns XrayTlsResult with kTLS flags set on success.
/// Error code 1 = auth failed (Go should handle camouflage fallback).
fn reality_server_handshake_full(
    fd: i32,
    cfg: &RealityConfig,
) -> Result<
    (
        u16,         // cipher_suite
        bool,        // ktls_tx
        bool,        // ktls_rx
        *mut c_void, // state_handle
        Vec<u8>,     // tx base traffic secret
        Vec<u8>,     // rx base traffic secret
        Vec<u8>,     // drained plaintext data
    ),
    (i32, String), // (error_code, message)
> {
    let private_key = cfg.private_key.ok_or((1, "private_key not set".into()))?;
    let version_range = cfg.version_range.unwrap_or(((0, 0, 0), (255, 255, 255)));

    // Step 1: Peek at ClientHello using MSG_PEEK (non-consuming).
    // If auth fails, data stays in the buffer for Go's camouflage fallback.
    let mut header = [0u8; 5];
    peek_exact(fd, &mut header).map_err(|e| (2, format!("peek header: {}", e)))?;

    let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;
    if record_len > 16384 {
        return Err((2, "ClientHello record too large".into()));
    }

    let mut peek_buf = vec![0u8; 5 + record_len];
    peek_exact(fd, &mut peek_buf).map_err(|e| (2, format!("peek record: {}", e)))?;

    let ch_raw = &peek_buf[5..]; // ClientHello body (after TLS record header)

    // Step 2: Validate REALITY auth (using peeked data — socket not consumed)
    if ch_raw.len() < 71 || ch_raw[0] != 0x01 {
        return Err((1, "not a ClientHello".into()));
    }

    let random: [u8; 32] = {
        let mut r = [0u8; 32];
        r.copy_from_slice(&ch_raw[6..38]);
        r
    };

    let session_id_len = ch_raw[38] as usize;
    if session_id_len != 32 {
        return Err((1, "session_id not 32 bytes".into()));
    }
    let encrypted_session_id = &ch_raw[39..71];

    let sni = parse_sni_from_client_hello(ch_raw).unwrap_or_default();
    if !server_name_allowed(&cfg.server_names, &sni) {
        return Err((1, format!("server name mismatch: {}", sni)));
    }

    let client_x25519 = parse_x25519_key_share(ch_raw).ok_or((1, "no X25519 key_share".into()))?;

    let privkey = StaticSecret::from(private_key);
    let client_pubkey = PublicKey::from(client_x25519);
    let shared_secret = privkey.diffie_hellman(&client_pubkey);

    let auth_key = reality_auth_key(shared_secret.as_bytes(), &random[..20])
        .map_err(|e| (2, format!("auth key: {}", e)))?;

    // Decrypt session_id with AAD = ClientHello raw with session_id zeroed
    // (matches Go's github.com/xtls/reality server behavior).
    let nonce = &random[20..32];
    let mut aad = ch_raw.to_vec();
    aad[39..71].fill(0);
    let plaintext = aes_gcm_open(&auth_key, nonce, encrypted_session_id, &aad)
        .map_err(|e| (1, format!("session_id decrypt: {}", e)))?;

    if plaintext.len() != 16 {
        return Err((1, "decrypted session_id wrong size".into()));
    }

    let client_ver = (plaintext[0], plaintext[1], plaintext[2]);
    let timestamp = u32::from_be_bytes([plaintext[4], plaintext[5], plaintext[6], plaintext[7]]);
    let short_id = plaintext[8..16].to_vec();

    let (min_ver, max_ver) = version_range;
    if client_ver < min_ver || client_ver > max_ver {
        return Err((
            1,
            format!(
                "client version {}.{}.{} out of range",
                client_ver.0, client_ver.1, client_ver.2
            ),
        ));
    }

    if !timestamp_within_max_diff(timestamp, cfg.max_time_diff) {
        return Err((
            1,
            format!("timestamp exceeds max_time_diff {}ms", cfg.max_time_diff),
        ));
    }

    let short_id_trimmed: Vec<u8> = short_id.iter().copied().take_while(|&b| b != 0).collect();
    let mut short_id_matched = false;
    for s in &cfg.short_ids {
        let trimmed_match: bool =
            s.len() == short_id_trimmed.len() && s.ct_eq(&short_id_trimmed).into();
        let full_match: bool = s.len() == short_id.len() && s.ct_eq(&short_id).into();
        short_id_matched |= trimmed_match || full_match;
    }
    if !short_id_matched {
        return Err((1, "short_id not in allowed list".into()));
    }

    // Auth succeeded — from here on, we commit to consuming the socket data.
    // The peeked ClientHello is still in the kernel buffer; rustls will read
    // it normally (consuming it) as the first step of the TLS handshake.

    // Hash the peeked record for TOCTOU verification after rustls consumes it.
    let peek_hash = ring::digest::digest(&ring::digest::SHA256, &peek_buf);

    // Step 3: Generate REALITY certificate.
    let rng = SystemRandom::new();
    let pkcs8_doc =
        Ed25519KeyPair::generate_pkcs8(&rng).map_err(|e| (2, format!("ed25519 keygen: {}", e)))?;
    let ed25519_pair = Ed25519KeyPair::from_pkcs8(pkcs8_doc.as_ref())
        .map_err(|e| (2, format!("ed25519 parse: {}", e)))?;
    let ed25519_pub = ed25519_pair.public_key().as_ref();

    let cert_sni = if sni.is_empty() { "localhost" } else { &sni };
    let cert_der = build_reality_cert(pkcs8_doc.as_ref(), ed25519_pub, &auth_key, cert_sni)
        .map_err(|e| (2, format!("cert gen: {}", e)))?;

    // Step 4: Build rustls ServerConfig with the REALITY cert
    let provider = Arc::new(default_provider());
    let cert = CertificateDer::from(cert_der);
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8_doc.as_ref().to_vec()));

    let mut sc = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| (2, format!("protocol version: {}", e)))?
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .map_err(|e| (2, format!("server cert: {}", e)))?;

    let capture = Arc::new(tls::SecretCapture::new(None));
    sc.key_log = capture.clone();

    let mut conn = ServerConnection::new(Arc::new(sc))
        .map_err(|e| (2, format!("server connection: {}", e)))?;

    // Step 5: rustls handshake — reads the ClientHello from the socket
    // (consuming the data that was previously only peeked).
    let dup_fd = unsafe { libc::dup(fd) };
    if dup_fd < 0 {
        return Err((2, format!("dup: {}", io::Error::last_os_error())));
    }
    let tcp = unsafe { TcpStream::from_raw_fd(dup_fd) };
    let mut reader = tls::RecordReader::new(tcp);

    // Drive handshake record-by-record
    drive_handshake!(&mut conn, &mut reader)
        .map_err(|e| (2i32, format!("handshake: {}", e)))?;

    // TOCTOU verification: ensure the first record rustls consumed matches
    // what we peeked during auth validation.
    let consumed_hash = reader.first_record_hash().ok_or_else(|| {
        (2i32, "TOCTOU: no record consumed by rustls".to_string())
    })?;
    if consumed_hash != peek_hash.as_ref() {
        drop(reader);
        return Err((2, "TOCTOU: consumed ClientHello differs from peeked data".into()));
    }

    // Drain any plaintext rustls buffered (should be empty with RecordReader)
    let drained = tls::drain_plaintext(&mut conn);

    let tls_version = conn
        .protocol_version()
        .map(|v| match v {
            rustls::ProtocolVersion::TLSv1_3 => 0x0304u16,
            _ => 0u16,
        })
        .unwrap_or(0);

    // Close dup'd fd
    drop(reader);

    let secrets = conn
        .dangerous_extract_secrets()
        .map_err(|e| (2, format!("extract secrets: {}", e)))?;

    let (tx_seq, tx_secrets) = secrets.tx;
    let (rx_seq, rx_secrets) = secrets.rx;

    let cipher_suite = tls::cipher_suite_to_u16(&tx_secrets);

    // Step 6: Install kTLS
    tls::setup_ulp(fd).map_err(|e| (2, format!("ULP: {}", e)))?;

    let tx_ok = tls::install_ktls(fd, tls::TLS_TX, tls_version, &tx_secrets, tx_seq).is_ok();
    let rx_ok = tls::install_ktls(fd, tls::TLS_RX, tls_version, &rx_secrets, rx_seq).is_ok();

    if !tx_ok || !rx_ok {
        return Err((2, format!("kTLS incomplete (tx={}, rx={})", tx_ok, rx_ok)));
    }

    // Create TlsState (metadata only — KeyUpdate handled on Go side)
    let state = Box::new(TlsState::new(fd, cipher_suite));
    let state_handle = Box::into_raw(state) as *mut c_void;

    // Server: TX = server secret, RX = client secret
    let tx_secret = capture.server_secret.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let rx_secret = capture.client_secret.lock().unwrap_or_else(|e| e.into_inner()).clone();

    Ok((
        cipher_suite,
        tx_ok,
        rx_ok,
        state_handle,
        tx_secret,
        rx_secret,
        drained,
    ))
}

// ---------------------------------------------------------------------------
// ClientHello extension parsing helpers
// ---------------------------------------------------------------------------

fn parse_sni_from_client_hello(ch: &[u8]) -> Option<String> {
    // Skip: type(1) + length(3) + version(2) + random(32) + session_id
    if ch.len() < 39 {
        return None;
    }
    let session_id_len = ch[38] as usize;
    let mut pos = 39 + session_id_len;

    // cipher_suites: length(2) + data
    if pos + 2 > ch.len() {
        return None;
    }
    let cs_len = u16::from_be_bytes([ch[pos], ch[pos + 1]]) as usize;
    pos += 2 + cs_len;

    // compression: length(1) + data
    if pos + 1 > ch.len() {
        return None;
    }
    let comp_len = ch[pos] as usize;
    pos += 1 + comp_len;

    // extensions: length(2)
    if pos + 2 > ch.len() {
        return None;
    }
    let ext_len = u16::from_be_bytes([ch[pos], ch[pos + 1]]) as usize;
    pos += 2;
    let ext_end = (pos + ext_len).min(ch.len());

    while pos + 4 <= ext_end {
        let etype = u16::from_be_bytes([ch[pos], ch[pos + 1]]);
        let elen = u16::from_be_bytes([ch[pos + 2], ch[pos + 3]]) as usize;
        pos += 4;
        if pos + elen > ext_end {
            break;
        }

        if etype == 0x0000 {
            // SNI extension: list_len(2) + type(1) + name_len(2) + name
            let ext = &ch[pos..pos + elen];
            if ext.len() >= 5 {
                let name_len = u16::from_be_bytes([ext[3], ext[4]]) as usize;
                if ext.len() >= 5 + name_len {
                    return String::from_utf8(ext[5..5 + name_len].to_vec()).ok();
                }
            }
        }

        pos += elen;
    }

    None
}

fn parse_x25519_key_share(ch: &[u8]) -> Option<[u8; 32]> {
    if ch.len() < 39 {
        return None;
    }
    let session_id_len = ch[38] as usize;
    let mut pos = 39 + session_id_len;

    // cipher_suites
    if pos + 2 > ch.len() {
        return None;
    }
    let cs_len = u16::from_be_bytes([ch[pos], ch[pos + 1]]) as usize;
    pos += 2 + cs_len;

    // compression
    if pos + 1 > ch.len() {
        return None;
    }
    let comp_len = ch[pos] as usize;
    pos += 1 + comp_len;

    // extensions
    if pos + 2 > ch.len() {
        return None;
    }
    let ext_len = u16::from_be_bytes([ch[pos], ch[pos + 1]]) as usize;
    pos += 2;
    let ext_end = (pos + ext_len).min(ch.len());

    while pos + 4 <= ext_end {
        let etype = u16::from_be_bytes([ch[pos], ch[pos + 1]]);
        let elen = u16::from_be_bytes([ch[pos + 2], ch[pos + 3]]) as usize;
        pos += 4;
        if pos + elen > ext_end {
            break;
        }

        if etype == 0x0033 {
            // key_share extension: client_shares_len(2) + [group(2) + key_len(2) + key]*
            let ks = &ch[pos..pos + elen];
            if ks.len() >= 2 {
                let shares_len = u16::from_be_bytes([ks[0], ks[1]]) as usize;
                let mut kpos = 2;
                while kpos + 4 <= (2 + shares_len).min(ks.len()) {
                    let group = u16::from_be_bytes([ks[kpos], ks[kpos + 1]]);
                    let klen = u16::from_be_bytes([ks[kpos + 2], ks[kpos + 3]]) as usize;
                    kpos += 4;
                    if kpos + klen > ks.len() {
                        break;
                    }
                    if group == 0x001d && klen == 32 {
                        let mut key = [0u8; 32];
                        key.copy_from_slice(&ks[kpos..kpos + 32]);
                        return Some(key);
                    }
                    kpos += klen;
                }
            }
        }

        pos += elen;
    }

    None
}

// ---------------------------------------------------------------------------
// FFI Config
// ---------------------------------------------------------------------------

pub struct RealityConfig {
    pub(crate) is_client: bool,
    pub(crate) server_pubkey: Option<[u8; 32]>,
    pub(crate) private_key: Option<[u8; 32]>,
    pub(crate) short_id: Vec<u8>,
    pub(crate) short_ids: Vec<Vec<u8>>,
    pub(crate) server_names: Vec<String>,
    pub(crate) version: (u8, u8, u8),
    pub(crate) version_range: Option<((u8, u8, u8), (u8, u8, u8))>,
    pub(crate) max_time_diff: u64,
    // Server-only fields
    pub(crate) mldsa65_verify_key: Vec<u8>,
    pub(crate) mldsa65_sign_key: Vec<u8>,
    pub(crate) dest: String,
    pub(crate) tls_cert_pem: Vec<u8>,
    pub(crate) tls_key_pem: Vec<u8>,
}

impl Drop for RealityConfig {
    fn drop(&mut self) {
        if let Some(ref mut key) = self.private_key {
            key.zeroize();
        }
        if let Some(ref mut key) = self.server_pubkey {
            key.zeroize();
        }
        self.short_id.zeroize();
        for sid in &mut self.short_ids {
            sid.zeroize();
        }
        self.tls_key_pem.zeroize();
        self.mldsa65_sign_key.zeroize();
    }
}

// ---------------------------------------------------------------------------
// FFI Exports — Config builder
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn xray_reality_config_new(is_client: bool) -> *mut RealityConfig {
    ffi_catch_ptr!({
        Box::into_raw(Box::new(RealityConfig {
            is_client,
            server_pubkey: None,
            private_key: None,
            short_id: Vec::new(),
            short_ids: Vec::new(),
            server_names: Vec::new(),
            version: (0, 0, 0),
            version_range: None,
            max_time_diff: 0, // default disabled (matches Go REALITY semantics)
            mldsa65_verify_key: Vec::new(),
            mldsa65_sign_key: Vec::new(),
            dest: String::new(),
            tls_cert_pem: Vec::new(),
            tls_key_pem: Vec::new(),
        }))
    })
}

#[no_mangle]
pub extern "C" fn xray_reality_config_set_server_pubkey(
    cfg: *mut RealityConfig,
    key_ptr: *const u8,
    len: usize,
) {
    ffi_catch_void!({
        if cfg.is_null() { return; }
        let cfg = unsafe { &mut *cfg };
        if key_ptr.is_null() || len < 32 { return; }
        let key = unsafe { std::slice::from_raw_parts(key_ptr, 32) };
        let mut k = [0u8; 32];
        k.copy_from_slice(key);
        cfg.server_pubkey = Some(k);
    })
}

#[no_mangle]
pub extern "C" fn xray_reality_config_set_private_key(
    cfg: *mut RealityConfig,
    key_ptr: *const u8,
    len: usize,
) {
    ffi_catch_void!({
        if cfg.is_null() { return; }
        let cfg = unsafe { &mut *cfg };
        if key_ptr.is_null() || len < 32 { return; }
        let key = unsafe { std::slice::from_raw_parts(key_ptr, 32) };
        let mut k = [0u8; 32];
        k.copy_from_slice(key);
        cfg.private_key = Some(k);
    })
}

#[no_mangle]
pub extern "C" fn xray_reality_config_set_short_id(
    cfg: *mut RealityConfig,
    id_ptr: *const u8,
    id_len: usize,
) {
    ffi_catch_void!({
        if cfg.is_null() { return; }
        let cfg = unsafe { &mut *cfg };
        let id = if id_ptr.is_null() || id_len == 0 {
            &[] as &[u8]
        } else {
            unsafe { std::slice::from_raw_parts(id_ptr, id_len) }
        };
        cfg.short_id = id.to_vec();
    })
}

#[no_mangle]
pub extern "C" fn xray_reality_config_set_mldsa65_verify(
    cfg: *mut RealityConfig,
    key_ptr: *const u8,
    key_len: usize,
) {
    ffi_catch_void!({
        if cfg.is_null() { return; }
        let cfg = unsafe { &mut *cfg };
        let key = if key_ptr.is_null() || key_len == 0 {
            &[] as &[u8]
        } else {
            unsafe { std::slice::from_raw_parts(key_ptr, key_len) }
        };
        cfg.mldsa65_verify_key = key.to_vec();
    })
}

#[no_mangle]
pub extern "C" fn xray_reality_config_set_version(
    cfg: *mut RealityConfig,
    major: u8,
    minor: u8,
    patch: u8,
) {
    ffi_catch_void!({
        if cfg.is_null() { return; }
        let cfg = unsafe { &mut *cfg };
        cfg.version = (major, minor, patch);
    })
}

#[no_mangle]
pub extern "C" fn xray_reality_config_free(cfg: *mut RealityConfig) {
    ffi_catch_void!({
        if !cfg.is_null() {
            let _ = unsafe { Box::from_raw(cfg) };
        }
    })
}

#[no_mangle]
pub extern "C" fn xray_reality_config_set_server_names(
    cfg: *mut RealityConfig,
    data_ptr: *const u8,
    data_len: usize,
) {
    ffi_catch_void!({
        if cfg.is_null() { return; }
        let cfg = unsafe { &mut *cfg };
        let data = if data_ptr.is_null() || data_len == 0 {
            &[] as &[u8]
        } else {
            unsafe { std::slice::from_raw_parts(data_ptr, data_len) }
        };
        // Parse as null-separated UTF-8 strings
        cfg.server_names.clear();
        for chunk in data.split(|&b| b == 0) {
            if let Ok(s) = std::str::from_utf8(chunk) {
                if !s.is_empty() {
                    cfg.server_names.push(s.to_string());
                }
            }
        }
    })
}

#[no_mangle]
pub extern "C" fn xray_reality_config_set_short_ids(
    cfg: *mut RealityConfig,
    data_ptr: *const u8,
    data_len: usize,
) {
    ffi_catch_void!({
        if cfg.is_null() { return; }
        let cfg = unsafe { &mut *cfg };
        let data = if data_ptr.is_null() || data_len == 0 {
            &[] as &[u8]
        } else {
            unsafe { std::slice::from_raw_parts(data_ptr, data_len) }
        };
        // Parse as null-separated binary short IDs
        cfg.short_ids.clear();
        for chunk in data.split(|&b| b == 0) {
            if !chunk.is_empty() {
                cfg.short_ids.push(chunk.to_vec());
            }
        }
    })
}

#[no_mangle]
pub extern "C" fn xray_reality_config_set_mldsa65_key(
    cfg: *mut RealityConfig,
    key_ptr: *const u8,
    key_len: usize,
) {
    ffi_catch_void!({
        if cfg.is_null() { return; }
        let cfg = unsafe { &mut *cfg };
        let key = if key_ptr.is_null() || key_len == 0 {
            &[] as &[u8]
        } else {
            unsafe { std::slice::from_raw_parts(key_ptr, key_len) }
        };
        cfg.mldsa65_sign_key = key.to_vec();
    })
}

#[no_mangle]
pub extern "C" fn xray_reality_config_set_dest(
    cfg: *mut RealityConfig,
    addr_ptr: *const u8,
    addr_len: usize,
) {
    ffi_catch_void!({
        if cfg.is_null() { return; }
        let cfg = unsafe { &mut *cfg };
        let addr = if addr_ptr.is_null() || addr_len == 0 {
            &[] as &[u8]
        } else {
            unsafe { std::slice::from_raw_parts(addr_ptr, addr_len) }
        };
        if let Ok(s) = std::str::from_utf8(addr) {
            cfg.dest = s.to_string();
        }
    })
}

#[no_mangle]
pub extern "C" fn xray_reality_config_set_max_time_diff(cfg: *mut RealityConfig, ms: u64) {
    ffi_catch_void!({
        if cfg.is_null() { return; }
        let cfg = unsafe { &mut *cfg };
        cfg.max_time_diff = ms;
    })
}

#[no_mangle]
pub extern "C" fn xray_reality_config_set_version_range(
    cfg: *mut RealityConfig,
    min_major: u8,
    min_minor: u8,
    min_patch: u8,
    max_major: u8,
    max_minor: u8,
    max_patch: u8,
) {
    ffi_catch_void!({
        if cfg.is_null() { return; }
        let cfg = unsafe { &mut *cfg };
        cfg.version_range = Some((
            (min_major, min_minor, min_patch),
            (max_major, max_minor, max_patch),
        ));
    })
}

#[no_mangle]
pub extern "C" fn xray_reality_config_set_tls_cert(
    cfg: *mut RealityConfig,
    cert_ptr: *const u8,
    cert_len: usize,
    key_ptr: *const u8,
    key_len: usize,
) {
    ffi_catch_void!({
        if cfg.is_null() { return; }
        let cfg = unsafe { &mut *cfg };
        let cert = if cert_ptr.is_null() || cert_len == 0 {
            &[] as &[u8]
        } else {
            unsafe { std::slice::from_raw_parts(cert_ptr, cert_len) }
        };
        let key = if key_ptr.is_null() || key_len == 0 {
            &[] as &[u8]
        } else {
            unsafe { std::slice::from_raw_parts(key_ptr, key_len) }
        };
        cfg.tls_cert_pem = cert.to_vec();
        cfg.tls_key_pem = key.to_vec();
    })
}

// Keep the individual add functions for compatibility
#[no_mangle]
pub extern "C" fn xray_reality_config_add_short_id(
    cfg: *mut RealityConfig,
    id_ptr: *const u8,
    id_len: usize,
) {
    ffi_catch_void!({
        if cfg.is_null() { return; }
        let cfg = unsafe { &mut *cfg };
        if id_ptr.is_null() || id_len == 0 { return; }
        let id = unsafe { std::slice::from_raw_parts(id_ptr, id_len) };
        cfg.short_ids.push(id.to_vec());
    })
}

#[no_mangle]
pub extern "C" fn xray_reality_config_add_server_name(
    cfg: *mut RealityConfig,
    name_ptr: *const u8,
    name_len: usize,
) {
    ffi_catch_void!({
        if cfg.is_null() { return; }
        let cfg = unsafe { &mut *cfg };
        if name_ptr.is_null() || name_len == 0 { return; }
        let name = unsafe { std::slice::from_raw_parts(name_ptr, name_len) };
        if let Ok(s) = String::from_utf8(name.to_vec()) {
            cfg.server_names.push(s);
        }
    })
}

// ---------------------------------------------------------------------------
// FFI Exports — Client connect
// Uses XrayTlsResult from tls.rs (same struct Go expects for all paths)
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn xray_reality_client_connect(
    fd: i32,
    client_hello_ptr: *mut u8,
    client_hello_len: usize,
    ecdh_privkey_ptr: *const u8,
    _privkey_len: usize,
    cfg: *const RealityConfig,
    out: *mut XrayTlsResult,
) -> i32 {
    ffi_catch_i32!({
        if out.is_null() { return -1; }
        if cfg.is_null() || client_hello_ptr.is_null() || ecdh_privkey_ptr.is_null() {
            let out = unsafe { &mut *out };
            *out = XrayTlsResult::new();
            out.set_error(-1, "null input pointer");
            return -1;
        }
        let out = unsafe { &mut *out };
        *out = XrayTlsResult::new();

        let cfg = unsafe { &*cfg };

        if client_hello_len > 16388 {
            out.set_error(-1, "client_hello_len exceeds TLS record limit");
            return -1;
        }

        let ch = unsafe { std::slice::from_raw_parts_mut(client_hello_ptr, client_hello_len) };
        let pk = unsafe { std::slice::from_raw_parts(ecdh_privkey_ptr, 32) };
        let mut privkey = [0u8; 32];
        privkey.copy_from_slice(pk);

        // Native client verification currently covers REALITY's Ed25519/HMAC binding.
        // If ML-DSA verification is configured, force Go/uTLS fallback so semantics
        // remain identical to VerifyPeerCertificate on the Go path.
        if !cfg.mldsa65_verify_key.is_empty() {
            out.set_error(1, "mldsa65_verify requires Go REALITY verification path");
            return 1;
        }

        let server_pubkey = match cfg.server_pubkey {
            Some(k) => k,
            None => {
                out.set_error(1, "server_pubkey not set");
                return 1;
            }
        };

        match reality_client_connect(fd, ch, &privkey, &server_pubkey, &cfg.short_id, cfg.version) {
            Ok(result) => {
                out.version = 0x0304; // TLS 1.3
                out.cipher_suite = result.tls_state.cipher_suite;

                // Copy base traffic secrets for Go-side KeyUpdate handler
                // Client: TX = client secret, RX = server secret
                let tx_sec = &result.tls_state.client_app_secret;
                let rx_sec = &result.tls_state.server_app_secret;
                let len = tx_sec.len().min(48);
                out.tx_secret[..len].copy_from_slice(&tx_sec[..len]);
                let len = rx_sec.len().min(48);
                out.rx_secret[..len].copy_from_slice(&rx_sec[..len]);
                out.secret_len = tx_sec.len().min(48) as u8;

                let (ktls_tx, ktls_rx) =
                    tls13::install_ktls_from_tls13_state(fd, &result.tls_state);
                out.ktls_tx = ktls_tx;
                out.ktls_rx = ktls_rx;

                if ktls_tx || ktls_rx {
                    let state = Box::new(TlsState::new(fd, result.tls_state.cipher_suite));
                    out.state_handle = Box::into_raw(state) as *mut c_void;
                } else {
                    out.state_handle = std::ptr::null_mut();
                }
                0
            }
            Err(e) => {
                // error_code 1 = auth failed (Go handles fallback)
                // error_code 2+ = actual errors
                let code = match &e {
                    RealityError::AuthFailed(_) => 1,
                    _ => 2,
                };
                out.set_error(code, &e.to_string());
                code
            }
        }
    })
}

// ---------------------------------------------------------------------------
// FFI Exports — Server accept
// Uses XrayTlsResult from tls.rs (same struct Go expects for all paths)
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn xray_reality_server_accept(
    fd: i32,
    cfg: *const RealityConfig,
    out: *mut XrayTlsResult,
) -> i32 {
    ffi_catch_i32!({
        if out.is_null() { return -1; }
        if cfg.is_null() {
            let out = unsafe { &mut *out };
            *out = XrayTlsResult::new();
            out.set_error(-1, "null config pointer");
            return -1;
        }
        let out = unsafe { &mut *out };
        *out = XrayTlsResult::new();

        let cfg = unsafe { &*cfg };
        let private_key = match cfg.private_key {
            Some(k) => k,
            None => {
                out.set_error(1, "private_key not set");
                return 1;
            }
        };

        let version_range = cfg.version_range.unwrap_or(((0, 0, 0), (255, 255, 255)));

        match reality_server_accept(
            fd,
            &private_key,
            &cfg.short_ids,
            &cfg.server_names,
            cfg.max_time_diff,
            version_range,
        ) {
            Ok(_result) => {
                out.version = 0x0304; // TLS 1.3
                out.ktls_tx = false;
                out.ktls_rx = false;
                out.state_handle = std::ptr::null_mut();
                0
            }
            Err(e) => {
                let code = match &e {
                    RealityError::AuthFailed(_) => 1,
                    _ => 2,
                };
                out.set_error(code, &e.to_string());
                code
            }
        }
    })
}

// ---------------------------------------------------------------------------
// FFI Exports — Server full handshake (auth + rustls + kTLS)
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn xray_reality_server_handshake(
    fd: i32,
    cfg: *const RealityConfig,
    out: *mut XrayTlsResult,
) -> i32 {
    ffi_catch_i32!({
        if out.is_null() { return -1; }
        if cfg.is_null() {
            let out = unsafe { &mut *out };
            *out = XrayTlsResult::new();
            out.set_error(-1, "null config pointer");
            return -1;
        }
        let out = unsafe { &mut *out };
        *out = XrayTlsResult::new();
        let cfg = unsafe { &*cfg };

        match reality_server_handshake_full(fd, cfg) {
            Ok((cipher_suite, ktls_tx, ktls_rx, state_handle, tx_secret, rx_secret, drained)) => {
                out.version = 0x0304;
                out.cipher_suite = cipher_suite;
                out.ktls_tx = ktls_tx;
                out.ktls_rx = ktls_rx;
                out.state_handle = state_handle;

                if !tx_secret.is_empty() {
                    let len = tx_secret.len().min(48);
                    out.tx_secret[..len].copy_from_slice(&tx_secret[..len]);
                    out.secret_len = len as u8;
                }
                if !rx_secret.is_empty() {
                    let len = rx_secret.len().min(48);
                    out.rx_secret[..len].copy_from_slice(&rx_secret[..len]);
                }

                // Forward drained data to Go
                if !drained.is_empty() {
                    let len = drained.len();
                    let boxed = drained.into_boxed_slice();
                    out.drained_ptr = Box::into_raw(boxed) as *mut u8;
                    out.drained_len = len as u32;
                }
                0
            }
            Err((code, msg)) => {
                out.set_error(code, &msg);
                code
            }
        }
    })
}

#[no_mangle]
pub extern "C" fn xray_reality_state_free(state: *mut c_void) {
    ffi_catch_void!({
        if !state.is_null() {
            let _ = unsafe { Box::from_raw(state as *mut TlsState) };
        }
    })
}

#[no_mangle]
pub extern "C" fn xray_reality_server_state_free(state: *mut c_void) {
    ffi_catch_void!({
        if !state.is_null() {
            let _ = unsafe { Box::from_raw(state as *mut TlsState) };
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_reality_cert_hmac_roundtrip() {
        // Generate an Ed25519 keypair
        let rng = SystemRandom::new();
        let pkcs8_doc = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let keypair = Ed25519KeyPair::from_pkcs8(pkcs8_doc.as_ref()).unwrap();
        let ed25519_pub = keypair.public_key().as_ref();

        // Generate a random auth_key
        let auth_key = vec![0x42u8; 32];

        // Build the REALITY cert
        let cert_der =
            build_reality_cert(pkcs8_doc.as_ref(), ed25519_pub, &auth_key, "example.com")
                .expect("failed to build cert");

        // Verify it
        assert!(
            verify_reality_cert_hmac(&cert_der, &auth_key),
            "HMAC verification should succeed for matching auth_key"
        );

        // Verify with wrong key should fail
        let wrong_key = vec![0x99u8; 32];
        assert!(
            !verify_reality_cert_hmac(&cert_der, &wrong_key),
            "HMAC verification should fail for wrong auth_key"
        );
    }

    #[test]
    fn test_aes_gcm_seal_open_with_aad() {
        let key = vec![0x01u8; 32];
        let nonce = [0x02u8; 12];
        let plaintext = vec![0x03u8; 16];
        let aad = vec![0x04u8; 100];

        // Seal with AAD
        let ct = aes_gcm_seal(&key, &nonce, &plaintext, &aad).unwrap();

        // Open with matching AAD should succeed
        let pt = aes_gcm_open(&key, &nonce, &ct, &aad).unwrap();
        assert_eq!(pt, plaintext);

        // Open with wrong AAD should fail
        let wrong_aad = vec![0x05u8; 100];
        assert!(aes_gcm_open(&key, &nonce, &ct, &wrong_aad).is_err());

        // Open with empty AAD should fail (the critical bug we fixed)
        assert!(aes_gcm_open(&key, &nonce, &ct, &[]).is_err());
    }

    #[test]
    fn test_server_name_allowed_exact_match() {
        let names = vec!["example.com".to_string(), "www.example.org".to_string()];
        assert!(server_name_allowed(&names, "example.com"));
        assert!(!server_name_allowed(&names, "EXAMPLE.COM"));
        assert!(!server_name_allowed(&names, "unknown.example"));
    }

    #[test]
    fn test_timestamp_within_max_diff_zero_disables_check() {
        let now = UNIX_EPOCH + Duration::from_secs(500);
        assert!(timestamp_within_max_diff_at(0, 0, now));
    }

    #[test]
    fn test_timestamp_within_max_diff_ms_precision_boundary() {
        let now = UNIX_EPOCH + Duration::from_secs(100) + Duration::from_millis(999);
        assert!(timestamp_within_max_diff_at(100, 999, now));
        assert!(!timestamp_within_max_diff_at(100, 998, now));
    }

    #[test]
    fn test_timestamp_within_max_diff_future_timestamp() {
        let now = UNIX_EPOCH + Duration::from_secs(100) + Duration::from_millis(500);
        assert!(timestamp_within_max_diff_at(101, 500, now));
        assert!(!timestamp_within_max_diff_at(101, 499, now));
    }
}
