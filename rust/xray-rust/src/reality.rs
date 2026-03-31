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
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::CertifiedKey;
use rustls::{ServerConfig, ServerConnection, SignatureScheme};
use sha2::{Sha256, Sha512};
use x25519_dalek::{PublicKey, StaticSecret};

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::tls::{
    self, TlsState, XrayTlsResult, DEFERRED_HANDLE_OWNERSHIP_CONSUMED,
    DEFERRED_HANDLE_OWNERSHIP_RETAINED,
};
use crate::tls13::{self, CertVerifyPolicy, Tls13Error, Tls13State};

// ---------------------------------------------------------------------------
// Public result types
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct RealityResult {
    pub tls_state: Tls13State,
    pub auth_key: Zeroizing<Vec<u8>>,
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

fn copy_secret_to_result_slot(dst: &mut [u8], secret: &mut Vec<u8>) -> usize {
    let len = secret.len().min(dst.len());
    if len > 0 {
        dst[..len].copy_from_slice(&secret[..len]);
    }
    secret.zeroize();
    len
}

// AES-256-GCM with 32-byte key from HKDF-SHA256. This matches the Go REALITY
// implementation: Go derives a 32-byte AuthKey via HKDF and passes it to
// aes.NewCipher(), which auto-selects AES-256 for 32-byte keys. The previous
// Rust code (Aes128Gcm with key[..16]) was truncating to 16 bytes, which was
// the actual interop bug — it caused AEAD decryption failures against Go.
fn aes_gcm_seal(key: &[u8], nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| format!("aes key: {}", e))?;
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
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| format!("aes key: {}", e))?;
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
    let auth_key = Zeroizing::new(reality_auth_key(shared_secret.as_bytes(), &random[..20])?);

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

    // AES-GCM seal: nonce=random[20:32], plaintext=session_id[0..16],
    // aad=ClientHello raw with session_id zeroed (matches Go's REALITY client).
    let nonce = &random[20..32];
    // Zero session_id in the raw buffer to build AAD (Go zeros it before Seal).
    client_hello_raw[39..71].fill(0);
    let encrypted = aes_gcm_seal(
        auth_key.as_ref(),
        nonce,
        &session_id_plain,
        client_hello_raw,
    )
    .map_err(|e| RealityError::Protocol(e))?;
    session_id_plain.zeroize();

    // Overwrite session_id in ClientHello (offset 39, 32 bytes)
    if encrypted.len() != 32 {
        return Err(RealityError::Protocol(format!(
            "expected 32 byte encrypted session_id, got {}",
            encrypted.len()
        )));
    }
    client_hello_raw[39..71].copy_from_slice(&encrypted);

    // Complete the TLS 1.3 handshake with CertificateVerify skipped.
    // REALITY relies on the HMAC-based cert verification below
    // (verify_reality_cert_hmac) and the Finished message's implicit
    // binding to the ECDH shared secret instead of X.509 CertificateVerify.
    let tls_state = tls13::complete_tls13_handshake(
        fd,
        client_hello_raw,
        ecdh_privkey,
        CertVerifyPolicy::SkipForReality,
    )?;

    // Verify REALITY certificate: the server's cert must have an Ed25519 public
    // key whose HMAC-SHA512(auth_key, pubkey) equals the certificate's signature.
    // This matches Go's VerifyPeerCertificate at reality.go:108-119.
    if !tls_state.server_cert_chain.is_empty() {
        let cert_der = &tls_state.server_cert_chain[0];
        if !verify_reality_cert_hmac(cert_der, auth_key.as_ref()) {
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

#[derive(Debug)]
pub struct RealityServerResult {
    pub authenticated: bool,
    pub client_version: (u8, u8, u8),
    pub short_id: Vec<u8>,
    pub auth_key: Zeroizing<Vec<u8>>,
    pub sni: String,
    pub client_hello_raw: Vec<u8>,
}

/// Constant-time server name check to prevent timing oracles.
/// An active DPI adversary probing different SNI values must not be able to
/// distinguish "matched" from "not matched" by measuring response time.
const MAX_SERVER_NAME_LEN: usize = 255;

fn pad_server_name_for_ct_eq(name: &[u8]) -> [u8; MAX_SERVER_NAME_LEN] {
    let mut padded = [0u8; MAX_SERVER_NAME_LEN];
    let copy_len = name.len().min(MAX_SERVER_NAME_LEN);
    padded[..copy_len].copy_from_slice(&name[..copy_len]);
    padded
}

fn server_name_allowed(server_names: &[String], sni: &str) -> bool {
    let sni_bytes = sni.as_bytes();
    let padded_sni = pad_server_name_for_ct_eq(sni_bytes);
    let sni_in_range = subtle::Choice::from((sni_bytes.len() <= MAX_SERVER_NAME_LEN) as u8);
    let mut matched: subtle::Choice = 0u8.into();
    for name in server_names {
        let name_bytes = name.as_bytes();
        let padded_name = pad_server_name_for_ct_eq(name_bytes);
        let name_in_range = subtle::Choice::from((name_bytes.len() <= MAX_SERVER_NAME_LEN) as u8);
        let same_len = (name_bytes.len() as u16).ct_eq(&(sni_bytes.len() as u16));
        matched |= name_in_range & sni_in_range & same_len & padded_name.ct_eq(&padded_sni);
    }
    bool::from(matched)
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
    let encrypted_session_id = &ch_raw[39..71];

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
    let auth_key = Zeroizing::new(reality_auth_key(shared_secret.as_bytes(), &random[..20])?);

    // Decrypt session_id: nonce=random[20:32], ciphertext=encrypted_session_id,
    // aad=ClientHello raw with session_id zeroed (matches Go's REALITY server).
    let nonce = &random[20..32];
    let mut aad = ch_raw.clone();
    aad[39..71].fill(0);
    let plaintext = Zeroizing::new(
        aes_gcm_open(auth_key.as_ref(), nonce, encrypted_session_id, &aad)
            .map_err(|e| RealityError::AuthFailed(format!("session_id decrypt: {}", e)))?,
    );

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

    // Validate short_id using fixed-width constant-time comparison.
    // All values are padded to 8 bytes to prevent length-based timing leaks:
    // without padding, the length check short-circuits before ct_eq, letting
    // an attacker enumerate the configured short_id length via timing.
    let mut padded_received = [0u8; 8];
    let received_len = short_id.len().min(8);
    padded_received[..received_len].copy_from_slice(&short_id[..received_len]);

    let mut short_id_matched: subtle::Choice = 0u8.into();
    for s in short_ids {
        let mut padded_configured = [0u8; 8];
        let cfg_len = s.len().min(8);
        padded_configured[..cfg_len].copy_from_slice(&s[..cfg_len]);
        short_id_matched |= padded_configured.ct_eq(&padded_received);
    }
    if !bool::from(short_id_matched) {
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

// ---------------------------------------------------------------------------
// REALITY signing key bypass
// ---------------------------------------------------------------------------

/// Signing key wrapper that bypasses rustls signature scheme negotiation.
///
/// Go REALITY hardcodes `hs.sigAlg = Ed25519` and comments out
/// `pickCertificate()`, ignoring the client's `signature_algorithms`
/// extension entirely. Rustls is standards-compliant and rejects the
/// handshake if Ed25519 isn't in the client's offered list. This wrapper
/// makes `choose_scheme()` always return an Ed25519 signer regardless of
/// what the client advertises, matching Go's behavior.
///
/// The Go REALITY client verifies CertificateVerify against its own
/// internal `supportedSignatureAlgorithms()` (which includes Ed25519),
/// NOT against the uTLS fingerprint's advertised list, so this is safe.
///
/// # SAFETY: REALITY-only — do NOT use for generic TLS
///
/// This wrapper is intentionally non-RFC-8446-compliant: it ignores the
/// client's `signature_algorithms` extension. It MUST NOT be used in the
/// generic TLS handshake path (`tls.rs`), which serves standard TLS
/// clients that rely on correct signature scheme negotiation. Applying
/// this wrapper there would cause interop failures with any client that
/// does not offer Ed25519.
#[derive(Debug)]
struct RealitySigningKey(Arc<dyn rustls::sign::SigningKey>);

impl rustls::sign::SigningKey for RealitySigningKey {
    fn choose_scheme(&self, _offered: &[SignatureScheme]) -> Option<Box<dyn rustls::sign::Signer>> {
        self.0.choose_scheme(&[SignatureScheme::ED25519])
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        self.0.algorithm()
    }
}

/// Cert resolver that always returns the REALITY certificate.
#[derive(Debug)]
struct RealityCertResolver(Arc<CertifiedKey>);

impl rustls::server::ResolvesServerCert for RealityCertResolver {
    fn resolve(&self, _client_hello: rustls::server::ClientHello) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

/// Peek at N bytes from a socket using MSG_PEEK (non-consuming).
/// Blocks until all bytes are available or an error occurs.
fn peek_exact(fd: i32, buf: &mut [u8], timeout: Duration) -> io::Result<()> {
    // Limit retries to prevent slow-loris attacks holding threads indefinitely.
    // At 100us per retry, 100_000 retries = ~10 seconds. Wall-clock timeout is
    // still enforced by `timeout` and socket SO_RCVTIMEO.
    const MAX_RETRIES: u32 = 100_000;
    const RETRY_BACKOFF: Duration = Duration::from_micros(100);
    let mut retries: u32 = 0;
    let start = Instant::now();
    let deadline = start + timeout;
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "peek_exact: handshake timeout exceeded after {:?} (retries={})",
                    now.saturating_duration_since(start),
                    retries
                ),
            ));
        }
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
            if err.kind() == io::ErrorKind::WouldBlock || err.kind() == io::ErrorKind::TimedOut {
                retries += 1;
                if retries >= MAX_RETRIES || Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!(
                            "peek_exact: receive timeout after {:?} (retries={})",
                            Instant::now().saturating_duration_since(start),
                            retries
                        ),
                    ));
                }
                // On nonblocking sockets, MSG_PEEK|MSG_WAITALL may yield
                // EAGAIN until the full record arrives. Retry until deadline.
                std::thread::sleep(RETRY_BACKOFF);
                continue;
            }
            return Err(err);
        }
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "peer closed"));
        }
        if (n as usize) < buf.len() {
            retries += 1;
            if retries >= MAX_RETRIES {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "peek_exact: short read after {} retries ({}/{} bytes)",
                        retries,
                        n,
                        buf.len()
                    ),
                ));
            }
            // MSG_PEEK|MSG_WAITALL may return short on some kernels; sleep briefly and retry
            std::thread::sleep(RETRY_BACKOFF);
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
    handshake_timeout: std::time::Duration,
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
    let mut private_key = cfg.private_key.ok_or((1, "private_key not set".into()))?;
    let version_range = cfg.version_range.unwrap_or(((0, 0, 0), (255, 255, 255)));

    // Step 1: Peek at ClientHello using MSG_PEEK (non-consuming).
    // If auth fails, data stays in the buffer for Go's camouflage fallback.
    let _peek_timeout_guard = crate::fdutil::SocketTimeoutGuard::install(fd, fd, handshake_timeout)
        .map_err(|e| (2, format!("peek timeout guard: {}", e)))?;
    let mut header = [0u8; 5];
    peek_exact(fd, &mut header, handshake_timeout)
        .map_err(|e| (2, format!("peek header: {}", e)))?;

    let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;
    if record_len > 16384 {
        return Err((2, "ClientHello record too large".into()));
    }

    let mut peek_buf = vec![0u8; 5 + record_len];
    peek_exact(fd, &mut peek_buf, handshake_timeout)
        .map_err(|e| (2, format!("peek record: {}", e)))?;

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
    private_key.zeroize();
    let client_pubkey = PublicKey::from(client_x25519);
    let shared_secret = privkey.diffie_hellman(&client_pubkey);

    let auth_key = Zeroizing::new(
        reality_auth_key(shared_secret.as_bytes(), &random[..20])
            .map_err(|e| (2, format!("auth key: {}", e)))?,
    );

    // Decrypt session_id with AAD = ClientHello raw with session_id zeroed
    // (matches Go's github.com/xtls/reality server behavior).
    let nonce = &random[20..32];
    let mut aad = ch_raw.to_vec();
    aad[39..71].fill(0);
    let plaintext = Zeroizing::new(
        aes_gcm_open(auth_key.as_ref(), nonce, encrypted_session_id, &aad)
            .map_err(|e| (1, format!("session_id decrypt: {}", e)))?,
    );

    if plaintext.len() != 16 {
        return Err((1, "decrypted session_id wrong size".into()));
    }

    let client_ver = (plaintext[0], plaintext[1], plaintext[2]);
    let timestamp = u32::from_be_bytes([plaintext[4], plaintext[5], plaintext[6], plaintext[7]]);
    let short_id = &plaintext[8..16];

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

    // Fixed-width constant-time short_id comparison (see reality_server_accept).
    let mut padded_received = [0u8; 8];
    let received_len = short_id.len().min(8);
    padded_received[..received_len].copy_from_slice(&short_id[..received_len]);

    let mut short_id_matched: subtle::Choice = 0u8.into();
    for s in &cfg.short_ids {
        let mut padded_configured = [0u8; 8];
        let cfg_len = s.len().min(8);
        padded_configured[..cfg_len].copy_from_slice(&s[..cfg_len]);
        short_id_matched |= padded_configured.ct_eq(&padded_received);
    }
    if !bool::from(short_id_matched) {
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
    let cert_der = build_reality_cert(pkcs8_doc.as_ref(), ed25519_pub, auth_key.as_ref(), cert_sni)
        .map_err(|e| (2, format!("cert gen: {}", e)))?;

    // Step 4: Build rustls ServerConfig with the REALITY cert.
    //
    // We use RealitySigningKey to bypass rustls's signature scheme negotiation.
    // Go REALITY hardcodes Ed25519 and ignores the client's signature_algorithms
    // extension. Rustls is standards-compliant and would reject if Ed25519 isn't
    // in the client's offered list (NoSignatureSchemesInCommon). The wrapper
    // always offers Ed25519 regardless.
    let provider = tls::cached_provider();
    let cert = CertificateDer::from(cert_der);
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8_doc.as_ref().to_vec()));

    let signing_key = provider
        .key_provider
        .load_private_key(key)
        .map_err(|e| (2, format!("private key: {}", e)))?;
    let reality_key = Arc::new(RealitySigningKey(signing_key));
    let certified_key = Arc::new(CertifiedKey::new(vec![cert], reality_key));

    let mut sc = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| (2, format!("protocol version: {}", e)))?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(RealityCertResolver(certified_key)));

    sc.enable_secret_extraction = true;
    let capture = Arc::new(tls::SecretCapture::new(None));
    sc.key_log = capture.clone();

    let mut conn = ServerConnection::new(Arc::new(sc))
        .map_err(|e| (2, format!("server connection: {}", e)))?;

    // Step 5: rustls handshake — reads the ClientHello from the socket
    // (consuming the data that was previously only peeked).
    let mut pipeline = crate::fdutil::HandshakePipeline::new(fd, handshake_timeout)
        .map_err(|e| (2, format!("pipeline: {}", e)))?;

    // Drive handshake record-by-record
    let hs_result = drive_handshake!(&mut conn, pipeline.reader_mut());
    hs_result.map_err(|e| (2i32, format!("handshake: {}", e)))?;

    // TOCTOU verification: ensure the first record rustls consumed matches
    // what we peeked during auth validation.
    let consumed_hash = pipeline
        .first_record_hash()
        .ok_or_else(|| (2i32, "TOCTOU: no record consumed by rustls".to_string()))?;
    if consumed_hash != peek_hash.as_ref() {
        return Err((
            2,
            "TOCTOU: consumed ClientHello differs from peeked data".into(),
        ));
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

    let secrets = conn
        .dangerous_extract_secrets()
        .map_err(|e| (2, format!("extract secrets: {}", e)))?;

    let (tx_seq, tx_secrets) = secrets.tx;
    let (rx_seq, rx_secrets) = secrets.rx;

    let cipher_suite = tls::cipher_suite_to_u16(&tx_secrets);

    // Step 6: Install kTLS via pipeline (dup'd fd still alive — guaranteed
    // by ownership). Pipeline drop closes dup'd fd and restores O_NONBLOCK.
    let ktls_result = pipeline
        .install_ktls_and_finish(tls_version, &tx_secrets, tx_seq, &rx_secrets, rx_seq)
        .map_err(|e| (2, e))?;

    if !ktls_result.tx_ok || !ktls_result.rx_ok {
        return Err((
            2,
            format!(
                "kTLS incomplete (tx={}, rx={}, tx_err={}, rx_err={})",
                ktls_result.tx_ok,
                ktls_result.rx_ok,
                ktls_result.tx_err.as_deref().unwrap_or("none"),
                ktls_result.rx_err.as_deref().unwrap_or("none"),
            ),
        ));
    }
    let (tx_ok, rx_ok) = (ktls_result.tx_ok, ktls_result.rx_ok);

    // Create TlsState (metadata only — KeyUpdate handled on Go side)
    let state = Box::new(TlsState::new(fd, cipher_suite));
    let state_handle = Box::into_raw(state) as *mut c_void;

    // Server: TX = server secret, RX = client secret
    let tx_secret = capture.take_server_secret();
    let rx_secret = capture.take_client_secret();

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
// Deferred REALITY handshake (Phase 1: no kTLS install)
// ---------------------------------------------------------------------------

/// Write all bytes from `buf` to `fd`, handling EAGAIN via poll(2).
/// Handles EINTR from both write() and poll() (SA_RESTART does not apply to poll on Linux).
/// Used by DeferredSession::write() after RestoreNonBlock restores O_NONBLOCK.
fn timeout_deadline(timeout_ms: i64) -> Option<Instant> {
    if timeout_ms < 0 {
        return None;
    }
    Some(Instant::now() + Duration::from_millis(timeout_ms as u64))
}

// After the Go-side netpoll bridge was added for zero-deadline deferred reads,
// this ceiling no longer serves as the primary idle wait. It only needs to be
// long enough for the initial rustls-buffer check plus a brief fd probe before
// Go takes over the idle wait on epoll.
const DEFERRED_READ_WAKEUP_CEILING: Duration = Duration::from_millis(50);

fn deferred_read_deadline(timeout_ms: i64) -> (Option<Instant>, bool) {
    if timeout_ms < 0 {
        return (Some(Instant::now() + DEFERRED_READ_WAKEUP_CEILING), true);
    }
    (timeout_deadline(timeout_ms), false)
}

fn remaining_poll_timeout(deadline: Option<Instant>) -> io::Result<i32> {
    let Some(deadline) = deadline else {
        return Ok(-1);
    };
    let now = Instant::now();
    if now >= deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "deferred poll timeout exceeded",
        ));
    }
    let remaining = deadline.saturating_duration_since(now);
    let millis = remaining.as_millis();
    if millis == 0 {
        return Ok(1);
    }
    Ok(millis.min(i32::MAX as u128) as i32)
}

fn write_all_with_poll_deadline(
    fd: std::os::unix::io::RawFd,
    buf: &[u8],
    deadline: Option<Instant>,
) -> io::Result<()> {
    let mut written = 0;
    while written < buf.len() {
        let ret = unsafe {
            libc::write(
                fd,
                buf[written..].as_ptr() as *const libc::c_void,
                buf.len() - written,
            )
        };
        if ret > 0 {
            written += ret as usize;
        } else if ret == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "write_all_with_poll: zero-length write",
            ));
        } else {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock {
                poll_writable(fd, deadline)?;
                continue;
            }
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
    }
    Ok(())
}

fn write_all_with_poll(fd: std::os::unix::io::RawFd, buf: &[u8]) -> io::Result<()> {
    write_all_with_poll_deadline(fd, buf, None)
}

/// Block until `fd` is writable, handling EINTR.
fn poll_writable(fd: std::os::unix::io::RawFd, deadline: Option<Instant>) -> io::Result<()> {
    loop {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLOUT,
            revents: 0,
        };
        let timeout_ms = remaining_poll_timeout(deadline)?;
        let pret = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
        if pret < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue; // EINTR — retry poll
            }
            return Err(err);
        }
        if pret == 0 {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "deferred write poll timeout exceeded",
            ));
        }
        if pfd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "poll_writable: poll error/hangup",
            ));
        }
        return Ok(());
    }
}

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

/// DeferredSession holds a completed REALITY handshake without kTLS installed.
/// The caller reads/writes through rustls, then either:
/// - calls `enable_ktls()` to install kTLS in-place (non-Vision flows)
/// - calls `drain_and_detach()` then free (Vision flows — outer TLS stripped)
///
/// Uses three independent locks so read() and write() never contend:
/// - `tls`:    rustls ServerConnection (brief lock, no socket I/O)
/// - `reader`: RecordReader (may block on socket read, independent)
/// - `writer`: TcpStream dup (brief socket writes, independent)
///
/// No method ever holds two locks simultaneously — deadlock impossible.
pub(crate) struct DeferredSession {
    tls: Mutex<Option<ServerConnection>>,
    reader: Mutex<Option<tls::RecordReader>>,
    writer: Mutex<Option<std::net::TcpStream>>,
    detached: AtomicBool,
    capture: Mutex<Option<Arc<tls::SecretCapture>>>,
    pub original_fd: i32,
    _timeout_guard: crate::fdutil::SocketTimeoutGuard,
    // Immutable metadata (set at construction, no lock needed)
    pub cipher_suite: u16,
    pub tls_version: u16,
    pub alpn: Vec<u8>,
    pub sni: String,
}

impl DeferredSession {
    /// Construct a DeferredSession from a completed server handshake.
    /// Used by both REALITY (reality.rs) and regular TLS (tls.rs) deferred paths.
    /// Returns Result because `into_parts()` may fail on dup().
    pub(crate) fn new(
        conn: ServerConnection,
        pipeline: crate::fdutil::HandshakePipeline,
        capture: Arc<tls::SecretCapture>,
        cipher_suite: u16,
        tls_version: u16,
        alpn: Vec<u8>,
        sni: String,
    ) -> Result<Self, std::io::Error> {
        let (reader, write_stream, timeout, original_fd) = pipeline.into_parts()?;
        Ok(Self {
            tls: Mutex::new(Some(conn)),
            reader: Mutex::new(Some(reader)),
            writer: Mutex::new(Some(write_stream)),
            detached: AtomicBool::new(false),
            capture: Mutex::new(Some(capture)),
            original_fd,
            _timeout_guard: timeout,
            cipher_suite,
            tls_version,
            alpn,
            sni,
        })
    }

    /// Read decrypted plaintext through rustls.
    /// Three-step lock protocol — no lock held during socket I/O:
    /// 1. Lock tls (brief) → check rustls plaintext buffer → return if data → unlock
    /// 2. Lock reader (may block) → read_one_record() → get record bytes → unlock
    /// 3. Lock tls (brief) → feed record to rustls → read plaintext → unlock
    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.read_with_timeout(buf, -1)
    }

    pub fn read_with_timeout(&self, buf: &mut [u8], timeout_ms: i64) -> io::Result<usize> {
        if self.detached.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "deferred session detached",
            ));
        }
        let (deadline, wakeup_ceiling_armed) = deferred_read_deadline(timeout_ms);
        loop {
            // Step 1: Check if rustls already has plaintext buffered
            {
                let mut tls_guard = self.tls.lock().unwrap_or_else(|e| e.into_inner());
                let conn = tls_guard.as_mut().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::BrokenPipe, "deferred session closed")
                })?;
                match conn.reader().read(buf) {
                    Ok(0) => {} // no plaintext yet
                    Ok(n) => return Ok(n),
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) => return Err(e),
                }
            } // tls lock released

            // Step 2: Read one TLS record from socket (may block)
            let record = {
                let mut reader_guard = self.reader.lock().unwrap_or_else(|e| e.into_inner());
                let reader = reader_guard.as_mut().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::BrokenPipe, "deferred session reader closed")
                })?;
                match reader.read_one_record_deadline(deadline) {
                    Ok(record) => record,
                    Err(err) if wakeup_ceiling_armed && err.kind() == io::ErrorKind::TimedOut => {
                        return Err(io::Error::new(
                            io::ErrorKind::WouldBlock,
                            "deferred read wakeup ceiling reached",
                        ));
                    }
                    Err(err) => return Err(err),
                }
            }; // reader lock released

            // Check detached between socket I/O and tls lock
            if self.detached.load(Ordering::Acquire) {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "deferred session detached",
                ));
            }

            // Step 3: Feed record bytes to rustls and read plaintext.
            // Save any bytes the Cursor didn't consume back into the reader
            // (e.g., leftover from handshake containing multiple TLS records).
            let leftover = {
                let mut tls_guard = self.tls.lock().unwrap_or_else(|e| e.into_inner());
                let conn = tls_guard.as_mut().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::BrokenPipe, "deferred session closed")
                })?;
                let mut cursor = io::Cursor::new(&record);
                match conn.read_tls(&mut cursor) {
                    Ok(0) => {
                        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "peer closed"));
                    }
                    Ok(_) => {
                        conn.process_new_packets()
                            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                    }
                    Err(e) => return Err(e),
                }
                // Capture any bytes the Cursor didn't consume
                let pos = cursor.position() as usize;
                if pos < record.len() {
                    Some(record[pos..].to_vec())
                } else {
                    None
                }
            }; // tls lock released

            // Push unconsumed bytes back into the reader so the next
            // read_one_record() returns them before reading from the socket.
            if let Some(leftover) = leftover {
                let mut reader_guard = self.reader.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(reader) = reader_guard.as_mut() {
                    reader.push_back(&leftover);
                }
            }
        }
    }

    /// Write plaintext through rustls (encrypts and sends on wire).
    /// Two-step lock protocol — socket I/O under separate writer lock:
    /// 1. Lock tls (brief) → encrypt plaintext → get ciphertext bytes → unlock
    /// 2. Lock writer (brief) → write_all ciphertext → flush → unlock
    pub fn write(&self, buf: &[u8]) -> io::Result<usize> {
        self.write_with_timeout(buf, -1)
    }

    pub fn write_with_timeout(&self, buf: &[u8], timeout_ms: i64) -> io::Result<usize> {
        if self.detached.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "deferred session detached",
            ));
        }
        let deadline = timeout_deadline(timeout_ms);

        // Step 1: Encrypt plaintext through rustls → ciphertext buffer
        let (n, ciphertext) = {
            let mut tls_guard = self.tls.lock().unwrap_or_else(|e| e.into_inner());
            let conn = tls_guard.as_mut().ok_or_else(|| {
                io::Error::new(io::ErrorKind::BrokenPipe, "deferred session closed")
            })?;
            let n = conn.writer().write(buf)?;
            let mut ciphertext = Vec::new();
            while conn.wants_write() {
                conn.write_tls(&mut ciphertext)?;
            }
            (n, ciphertext)
        }; // tls lock released

        // Step 2: Send ciphertext on wire (poll-based for non-blocking fd safety)
        {
            use std::os::unix::io::AsRawFd;
            let mut writer_guard = self.writer.lock().unwrap_or_else(|e| e.into_inner());
            let writer = writer_guard.as_mut().ok_or_else(|| {
                io::Error::new(io::ErrorKind::BrokenPipe, "deferred session writer closed")
            })?;
            write_all_with_poll_deadline(writer.as_raw_fd(), &ciphertext, deadline)?;
            writer.flush()?;
        } // writer lock released

        Ok(n)
    }

    /// Drain rustls plaintext buffers plus raw read-ahead bytes and detach.
    /// After success, the deferred session no longer owns rustls/reader/writer state.
    /// Sequential locks — never two at once.
    pub fn drain_and_detach(&self) -> Result<(Vec<u8>, Vec<u8>), (i32, String)> {
        if self.detached.load(Ordering::Acquire) {
            return Err((2, "deferred session already detached".into()));
        }

        // Step 1: Lock tls → process + drain plaintext → unlock
        let plaintext = {
            let mut tls_guard = self.tls.lock().unwrap_or_else(|e| e.into_inner());
            let conn = tls_guard
                .as_mut()
                .ok_or_else(|| (2, "deferred session closed".to_string()))?;
            conn.process_new_packets()
                .map_err(|e| (2, format!("process new packets: {}", e)))?;
            tls::drain_plaintext(conn)
        }; // tls lock released

        // Step 2: Lock reader → take pending bytes → unlock
        let raw_ahead = {
            let mut reader_guard = self.reader.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(reader) = reader_guard.as_mut() {
                reader.take_pending_bytes()
            } else {
                Vec::new()
            }
        }; // reader lock released

        self.detached.store(true, Ordering::Release);

        // Step 3: Take all Options to None (drops rustls + dup'd fds)
        {
            let mut tls_guard = self.tls.lock().unwrap_or_else(|e| e.into_inner());
            tls_guard.take();
        }
        {
            let mut reader_guard = self.reader.lock().unwrap_or_else(|e| e.into_inner());
            reader_guard.take();
        }
        {
            let mut writer_guard = self.writer.lock().unwrap_or_else(|e| e.into_inner());
            writer_guard.take();
        }
        {
            let mut capture_guard = self.capture.lock().unwrap_or_else(|e| e.into_inner());
            capture_guard.take();
        }

        Ok((plaintext, raw_ahead))
    }

    /// Compatibility no-op.
    ///
    /// BlockingGuard is now handshake-scoped, so DeferredSession starts with
    /// O_NONBLOCK already restored. Keep the method to avoid a cross-language
    /// flag day while Go call sites are still wired through this API.
    pub fn restore_nonblock(&self) -> io::Result<()> {
        Ok(())
    }

    /// Consume the session, install kTLS on the socket, and return the
    /// same tuple as `reality_server_handshake_full`.
    pub fn enable_ktls(
        &mut self,
    ) -> Result<
        (
            u16,         // cipher_suite
            bool,        // ktls_tx
            bool,        // ktls_rx
            u64,         // rx_seq_start
            *mut c_void, // state_handle
            Vec<u8>,     // tx base traffic secret
            Vec<u8>,     // rx base traffic secret
            Vec<u8>,     // drained plaintext data
        ),
        (i32, String, bool), // code, message, handle_retained
    > {
        let tls_version = self.tls_version;
        let original_fd = self.original_fd;

        if self.detached.load(Ordering::Acquire) {
            return Err((2, "deferred session already detached".into(), true));
        }

        // Keep session components in-place so early failures can retain the
        // deferred handle for userspace rustls fallback.
        let mut tls_guard = self.tls.lock().unwrap_or_else(|e| e.into_inner());
        let mut reader_guard = self.reader.lock().unwrap_or_else(|e| e.into_inner());
        let mut writer_guard = self.writer.lock().unwrap_or_else(|e| e.into_inner());
        let mut capture_guard = self.capture.lock().unwrap_or_else(|e| e.into_inner());

        let _conn = tls_guard
            .as_ref()
            .ok_or_else(|| (2, "deferred session closed".to_string(), true))?;
        let _reader = reader_guard
            .as_mut()
            .ok_or_else(|| (2, "deferred session reader closed".to_string(), true))?;
        let _writer = writer_guard
            .as_mut()
            .ok_or_else(|| (2, "deferred session writer closed".to_string(), true))?;
        let capture = capture_guard
            .as_mut()
            .ok_or_else(|| (2, "deferred session capture closed".to_string(), true))?;

        // From this point onward the deferred session is consumed: extracting
        // secrets takes ownership of ServerConnection and cannot be undone.
        let mut conn = tls_guard
            .take()
            .ok_or_else(|| (2, "deferred session closed".to_string(), false))?;
        let drained = tls::drain_plaintext(&mut conn);
        let secrets = conn
            .dangerous_extract_secrets()
            .map_err(|e| (2, format!("extract secrets: {}", e), false))?;

        let (tx_seq, tx_secrets) = secrets.tx;
        let (rx_seq, rx_secrets) = secrets.rx;

        let cipher_suite = tls::cipher_suite_to_u16(&tx_secrets);

        // ULP can fail independently; do it after secrets are extracted so a rustls
        // failure does not leave the socket in TLS ULP state.
        tls::setup_ulp(original_fd).map_err(|e| (2, format!("ULP: {}", e), false))?;

        // Install kTLS on the original fd
        #[cfg(debug_assertions)]
        eprintln!(
            "kTLS install: fd={} version=0x{:04x} cipher=0x{:04x} tx_seq={} rx_seq={}",
            original_fd, tls_version, cipher_suite, tx_seq, rx_seq,
        );

        let tx_result =
            tls::install_ktls(original_fd, tls::TLS_TX, tls_version, &tx_secrets, tx_seq);
        let rx_result =
            tls::install_ktls(original_fd, tls::TLS_RX, tls_version, &rx_secrets, rx_seq);

        #[cfg(debug_assertions)]
        {
            if let Err(ref e) = tx_result {
                eprintln!("kTLS install TX failed: fd={} err={}", original_fd, e);
            }
            if let Err(ref e) = rx_result {
                eprintln!("kTLS install RX failed: fd={} err={}", original_fd, e);
            }
        }

        let ktls_tx = tx_result.is_ok();
        let ktls_rx = rx_result.is_ok();

        if !ktls_tx || !ktls_rx {
            return Err((
                2,
                format!(
                    "kTLS incomplete (tx={}, rx={}, tx_err={}, rx_err={})",
                    ktls_tx,
                    ktls_rx,
                    tx_result
                        .err()
                        .map(|e| e.to_string())
                        .as_deref()
                        .unwrap_or("none"),
                    rx_result
                        .err()
                        .map(|e| e.to_string())
                        .as_deref()
                        .unwrap_or("none"),
                ),
                false,
            ));
        }

        // Create TlsState (metadata for KeyUpdate on Go side)
        let state = Box::new(TlsState::new(original_fd, cipher_suite));
        let state_handle = Box::into_raw(state) as *mut c_void;

        // Server: TX = server secret, RX = client secret
        // Use take() to zero the source, matching the non-deferred path.
        let tx_secret = capture.take_server_secret();
        let rx_secret = capture.take_client_secret();

        // self drops here: _blocking_guard restores O_NONBLOCK, _timeout_guard restores SO_RCVTIMEO

        Ok((
            cipher_suite,
            ktls_tx,
            ktls_rx,
            rx_seq,
            state_handle,
            tx_secret,
            rx_secret,
            drained,
        ))
    }
}

/// Perform REALITY server auth + handshake but stop before kTLS installation.
/// Returns a DeferredSession that can read/write through rustls, then later
/// either enable kTLS (non-Vision) or be dropped (Vision).
fn reality_server_handshake_deferred(
    fd: i32,
    cfg: &RealityConfig,
    handshake_timeout: std::time::Duration,
) -> Result<Box<DeferredSession>, (i32, String)> {
    let mut private_key = cfg.private_key.ok_or((1, "private_key not set".into()))?;
    let version_range = cfg.version_range.unwrap_or(((0, 0, 0), (255, 255, 255)));

    // Step 1: Peek at ClientHello using MSG_PEEK (non-consuming).
    let _peek_timeout_guard = crate::fdutil::SocketTimeoutGuard::install(fd, fd, handshake_timeout)
        .map_err(|e| (2, format!("peek timeout guard: {}", e)))?;
    let mut header = [0u8; 5];
    peek_exact(fd, &mut header, handshake_timeout)
        .map_err(|e| (2, format!("peek header: {}", e)))?;

    let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;
    if record_len > 16384 {
        return Err((2, "ClientHello record too large".into()));
    }

    let mut peek_buf = vec![0u8; 5 + record_len];
    peek_exact(fd, &mut peek_buf, handshake_timeout)
        .map_err(|e| (2, format!("peek record: {}", e)))?;

    let ch_raw = &peek_buf[5..];

    // Step 2: Validate REALITY auth
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
    private_key.zeroize();
    let client_pubkey = PublicKey::from(client_x25519);
    let shared_secret = privkey.diffie_hellman(&client_pubkey);

    let auth_key = Zeroizing::new(
        reality_auth_key(shared_secret.as_bytes(), &random[..20])
            .map_err(|e| (2, format!("auth key: {}", e)))?,
    );

    let nonce = &random[20..32];
    let mut aad = ch_raw.to_vec();
    aad[39..71].fill(0);
    let plaintext = Zeroizing::new(
        aes_gcm_open(auth_key.as_ref(), nonce, encrypted_session_id, &aad)
            .map_err(|e| (1, format!("session_id decrypt: {}", e)))?,
    );

    if plaintext.len() != 16 {
        return Err((1, "decrypted session_id wrong size".into()));
    }

    let client_ver = (plaintext[0], plaintext[1], plaintext[2]);
    let timestamp = u32::from_be_bytes([plaintext[4], plaintext[5], plaintext[6], plaintext[7]]);
    let short_id = &plaintext[8..16];

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

    let mut padded_received = [0u8; 8];
    let received_len = short_id.len().min(8);
    padded_received[..received_len].copy_from_slice(&short_id[..received_len]);

    let mut short_id_matched: subtle::Choice = 0u8.into();
    for s in &cfg.short_ids {
        let mut padded_configured = [0u8; 8];
        let cfg_len = s.len().min(8);
        padded_configured[..cfg_len].copy_from_slice(&s[..cfg_len]);
        short_id_matched |= padded_configured.ct_eq(&padded_received);
    }
    if !bool::from(short_id_matched) {
        return Err((1, "short_id not in allowed list".into()));
    }

    // Auth succeeded — hash peeked record for TOCTOU check
    let peek_hash = ring::digest::digest(&ring::digest::SHA256, &peek_buf);

    // Step 3: Generate REALITY certificate
    let rng = SystemRandom::new();
    let pkcs8_doc =
        Ed25519KeyPair::generate_pkcs8(&rng).map_err(|e| (2, format!("ed25519 keygen: {}", e)))?;
    let ed25519_pair = Ed25519KeyPair::from_pkcs8(pkcs8_doc.as_ref())
        .map_err(|e| (2, format!("ed25519 parse: {}", e)))?;
    let ed25519_pub = ed25519_pair.public_key().as_ref();

    let cert_sni = if sni.is_empty() { "localhost" } else { &sni };
    let cert_der = build_reality_cert(pkcs8_doc.as_ref(), ed25519_pub, auth_key.as_ref(), cert_sni)
        .map_err(|e| (2, format!("cert gen: {}", e)))?;

    // Step 4: Build rustls ServerConfig
    let provider = tls::cached_provider();
    let cert = CertificateDer::from(cert_der);
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8_doc.as_ref().to_vec()));

    let signing_key = provider
        .key_provider
        .load_private_key(key)
        .map_err(|e| (2, format!("private key: {}", e)))?;
    let reality_key = Arc::new(RealitySigningKey(signing_key));
    let certified_key = Arc::new(CertifiedKey::new(vec![cert], reality_key));

    // Parse ALPN from config for server negotiation
    let mut sc = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| (2, format!("protocol version: {}", e)))?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(RealityCertResolver(certified_key)));

    sc.enable_secret_extraction = true;
    let capture = Arc::new(tls::SecretCapture::new(None));
    sc.key_log = capture.clone();

    let mut conn = ServerConnection::new(Arc::new(sc))
        .map_err(|e| (2, format!("server connection: {}", e)))?;

    // Step 5: rustls handshake
    let mut pipeline = crate::fdutil::HandshakePipeline::new(fd, handshake_timeout)
        .map_err(|e| (2, format!("pipeline: {}", e)))?;

    let hs_result = drive_handshake!(&mut conn, pipeline.reader_mut());
    hs_result.map_err(|e| (2i32, format!("handshake: {}", e)))?;

    // Step 6: TOCTOU verification
    let consumed_hash = pipeline
        .first_record_hash()
        .ok_or_else(|| (2i32, "TOCTOU: no record consumed by rustls".to_string()))?;
    if consumed_hash != peek_hash.as_ref() {
        return Err((
            2,
            "TOCTOU: consumed ClientHello differs from peeked data".into(),
        ));
    }

    // Step 7: Extract metadata and prepare for deferred phase
    let tls_version = conn
        .protocol_version()
        .map(|v| match v {
            rustls::ProtocolVersion::TLSv1_3 => 0x0304u16,
            _ => 0u16,
        })
        .unwrap_or(0);

    let negotiated_alpn: Vec<u8> = conn.alpn_protocol().map(|a| a.to_vec()).unwrap_or_default();

    // Clear handshake timeout for the data-transfer phase
    pipeline.clear_handshake_timeout();

    let cipher_suite = conn
        .negotiated_cipher_suite()
        .map(|cs| {
            // Map rustls CipherSuite to IANA u16 value
            let suite = cs.suite();
            // Use debug format to match since CipherSuite doesn't expose raw u16 directly
            match suite {
                rustls::CipherSuite::TLS13_AES_128_GCM_SHA256 => 0x1301u16,
                rustls::CipherSuite::TLS13_AES_256_GCM_SHA384 => 0x1302,
                rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 => 0x1303,
                _ => 0,
            }
        })
        .unwrap_or(0);

    let session = DeferredSession::new(
        conn,
        pipeline,
        capture,
        cipher_suite,
        tls_version,
        negotiated_alpn,
        sni,
    )
    .map_err(|e| (2, format!("deferred session init: {}", e)))?;
    Ok(Box::new(session))
}

// ---------------------------------------------------------------------------
// FFI: Deferred REALITY handshake
// ---------------------------------------------------------------------------

/// FFI result struct for deferred REALITY handshake.
#[repr(C)]
pub struct XrayDeferredResult {
    pub handle: *mut c_void,
    pub version: u16,
    pub cipher_suite: u16,
    pub alpn: [u8; 32],
    pub sni: [u8; 256],
    pub error_code: i32,
    pub error_msg: [u8; 256],
}

impl XrayDeferredResult {
    pub(crate) fn new() -> Self {
        Self {
            handle: std::ptr::null_mut(),
            version: 0,
            cipher_suite: 0,
            alpn: [0u8; 32],
            sni: [0u8; 256],
            error_code: 0,
            error_msg: [0u8; 256],
        }
    }

    pub(crate) fn set_error(&mut self, code: i32, msg: &str) {
        self.error_code = code;
        let bytes = msg.as_bytes();
        let len = bytes.len().min(255);
        self.error_msg[..len].copy_from_slice(&bytes[..len]);
        self.error_msg[len] = 0;
    }
}

/// Perform REALITY server auth + handshake, returning a deferred session handle.
/// No kTLS is installed — the caller decides later via enable_ktls or free.
#[no_mangle]
pub extern "C" fn xray_reality_server_deferred(
    fd: i32,
    cfg: *const RealityConfig,
    handshake_timeout_ms: u32,
    out: *mut XrayDeferredResult,
) -> i32 {
    ffi_catch_i32!({
        if out.is_null() {
            return -1;
        }
        if cfg.is_null() {
            let out = unsafe { &mut *out };
            *out = XrayDeferredResult::new();
            out.set_error(-1, "null config pointer");
            return -1;
        }
        let out = unsafe { &mut *out };
        *out = XrayDeferredResult::new();
        let cfg = unsafe { &*cfg };

        let handshake_timeout = tls::handshake_timeout_from_ms(handshake_timeout_ms);
        match reality_server_handshake_deferred(fd, cfg, handshake_timeout) {
            Ok(session) => {
                out.version = session.tls_version;
                out.cipher_suite = session.cipher_suite;

                // Copy ALPN (null-terminated)
                let alpn_len = session.alpn.len().min(31);
                out.alpn[..alpn_len].copy_from_slice(&session.alpn[..alpn_len]);
                out.alpn[alpn_len] = 0;

                // Copy SNI (null-terminated)
                let sni_bytes = session.sni.as_bytes();
                let sni_len = sni_bytes.len().min(255);
                out.sni[..sni_len].copy_from_slice(&sni_bytes[..sni_len]);
                out.sni[sni_len] = 0;

                out.handle = Box::into_raw(session) as *mut c_void;
                0
            }
            Err((code, msg)) => {
                out.set_error(code, &msg);
                code
            }
        }
    })
}

/// Read decrypted data through the deferred session's rustls connection.
#[no_mangle]
pub extern "C" fn xray_deferred_read(
    handle: *mut c_void,
    buf: *mut u8,
    len: usize,
    out_n: *mut usize,
) -> i32 {
    xray_deferred_read_timeout(handle, buf, len, -1, out_n)
}

/// Read decrypted data through the deferred session's rustls connection with
/// an optional per-call timeout in milliseconds (-1 means no deadline).
#[no_mangle]
pub extern "C" fn xray_deferred_read_timeout(
    handle: *mut c_void,
    buf: *mut u8,
    len: usize,
    timeout_ms: i64,
    out_n: *mut usize,
) -> i32 {
    ffi_catch_i32!({
        if handle.is_null() || buf.is_null() || out_n.is_null() {
            return -1;
        }
        let session = unsafe { &*(handle as *const DeferredSession) };
        let slice = unsafe { std::slice::from_raw_parts_mut(buf, len) };
        match session.read_with_timeout(slice, timeout_ms) {
            Ok(n) => {
                unsafe { *out_n = n };
                0
            }
            Err(e) => {
                eprintln!("xray_deferred_read: {}", e);
                match e.kind() {
                    io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset => {
                        unsafe { *out_n = 0 };
                        1 // EOF / peer closed
                    }
                    io::ErrorKind::BrokenPipe
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::NotConnected => {
                        unsafe { *out_n = 0 };
                        2 // local closed / detached
                    }
                    io::ErrorKind::TimedOut => {
                        unsafe { *out_n = 0 };
                        3 // deadline exceeded
                    }
                    io::ErrorKind::WouldBlock => {
                        unsafe { *out_n = 0 };
                        4 // retryable wake-up for zero-deadline deferred reads
                    }
                    _ => -1,
                }
            }
        }
    })
}

/// Write plaintext data through the deferred session's rustls connection.
#[no_mangle]
pub extern "C" fn xray_deferred_write(
    handle: *mut c_void,
    buf: *const u8,
    len: usize,
    out_n: *mut usize,
) -> i32 {
    xray_deferred_write_timeout(handle, buf, len, -1, out_n)
}

/// Write plaintext data through the deferred session's rustls connection with
/// an optional per-call timeout in milliseconds (-1 means no deadline).
#[no_mangle]
pub extern "C" fn xray_deferred_write_timeout(
    handle: *mut c_void,
    buf: *const u8,
    len: usize,
    timeout_ms: i64,
    out_n: *mut usize,
) -> i32 {
    ffi_catch_i32!({
        if handle.is_null() || buf.is_null() || out_n.is_null() {
            return -1;
        }
        let session = unsafe { &*(handle as *const DeferredSession) };
        let slice = unsafe { std::slice::from_raw_parts(buf, len) };
        match session.write_with_timeout(slice, timeout_ms) {
            Ok(n) => {
                unsafe { *out_n = n };
                0
            }
            Err(e) => {
                eprintln!("xray_deferred_write: {}", e);
                let mut code = match e.kind() {
                    io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::BrokenPipe
                    | io::ErrorKind::ConnectionReset => {
                        1 // EOF / peer closed
                    }
                    io::ErrorKind::ConnectionAborted | io::ErrorKind::NotConnected => {
                        2 // local closed / detached
                    }
                    io::ErrorKind::TimedOut => 3,
                    _ => -1,
                };
                if code < 0 {
                    if let Some(raw) = e.raw_os_error() {
                        code = match raw {
                            libc::EPIPE | libc::ECONNRESET | libc::ESHUTDOWN => 1,
                            libc::ENOTCONN | libc::EBADF => 2,
                            _ => -1,
                        };
                    }
                }
                if code < 0 {
                    let msg = e.to_string().to_ascii_lowercase();
                    if msg.contains("broken pipe")
                        || msg.contains("connection reset")
                        || msg.contains("peer closed")
                        || msg.contains("close notify")
                    {
                        code = 1;
                    } else if msg.contains("not connected")
                        || msg.contains("closed")
                        || msg.contains("detached")
                    {
                        code = 2;
                    }
                }
                if code < 0 {
                    // For streaming proxy semantics, unknown write-side I/O
                    // errors are safest treated as connection-closure events.
                    // This avoids surfacing transient close races as fatal
                    // "deferred write failed" errors.
                    code = 1;
                }
                if code > 0 {
                    unsafe { *out_n = 0 };
                }
                code
            }
        }
    })
}

/// Drain buffered plaintext and raw read-ahead bytes, then detach the deferred
/// rustls session from the socket. On success, the handle becomes detached and
/// subsequent read/write calls on it will fail.
///
/// Returns:
/// - out_plaintext_ptr/out_plaintext_len: decrypted bytes buffered in rustls
/// - out_raw_ptr/out_raw_len: bytes already read from socket but not yet
///   consumed by rustls
#[no_mangle]
pub extern "C" fn xray_deferred_drain_and_detach(
    handle: *mut c_void,
    out_plaintext_ptr: *mut *mut u8,
    out_plaintext_len: *mut usize,
    out_raw_ptr: *mut *mut u8,
    out_raw_len: *mut usize,
) -> i32 {
    ffi_catch_i32!({
        if handle.is_null()
            || out_plaintext_ptr.is_null()
            || out_plaintext_len.is_null()
            || out_raw_ptr.is_null()
            || out_raw_len.is_null()
        {
            return -1;
        }

        unsafe {
            *out_plaintext_ptr = std::ptr::null_mut();
            *out_plaintext_len = 0;
            *out_raw_ptr = std::ptr::null_mut();
            *out_raw_len = 0;
        }

        let session = unsafe { &*(handle as *const DeferredSession) };
        match session.drain_and_detach() {
            Ok((plaintext, raw_ahead)) => {
                if !plaintext.is_empty() {
                    let len = plaintext.len();
                    let boxed = plaintext.into_boxed_slice();
                    unsafe {
                        *out_plaintext_ptr = Box::into_raw(boxed) as *mut u8;
                        *out_plaintext_len = len;
                    }
                }
                if !raw_ahead.is_empty() {
                    let len = raw_ahead.len();
                    let boxed = raw_ahead.into_boxed_slice();
                    unsafe {
                        *out_raw_ptr = Box::into_raw(boxed) as *mut u8;
                        *out_raw_len = len;
                    }
                }
                0
            }
            Err((_, msg)) => {
                eprintln!("xray_deferred_drain_and_detach: {}", msg);
                -1
            }
        }
    })
}

#[inline]
unsafe fn write_or_export_bytes(
    mut data: Vec<u8>,
    dst_buf: *mut u8,
    dst_cap: usize,
    out_len: *mut usize,
    out_ptr: *mut *mut u8,
) {
    *out_len = data.len();
    *out_ptr = std::ptr::null_mut();
    if data.is_empty() {
        return;
    }
    if !dst_buf.is_null() && dst_cap >= data.len() {
        std::ptr::copy_nonoverlapping(data.as_ptr(), dst_buf, data.len());
        data.zeroize();
        return;
    }
    let boxed = std::mem::take(&mut data).into_boxed_slice();
    *out_ptr = Box::into_raw(boxed) as *mut u8;
}

/// Drain buffered plaintext and raw read-ahead bytes, then detach the deferred
/// rustls session from the socket.
///
/// Preferred fast path:
/// - If caller-provided output buffers are large enough, bytes are copied
///   directly into those buffers (Go-owned memory).
///
/// Fallback path:
/// - If a caller buffer is null or too small, Rust allocates that output and
///   returns ownership via out_*_ptr + out_*_len. Caller must free using
///   `xray_tls_drained_free`.
#[no_mangle]
pub extern "C" fn xray_deferred_drain_and_detach_into(
    handle: *mut c_void,
    plaintext_buf: *mut u8,
    plaintext_cap: usize,
    out_plaintext_len: *mut usize,
    out_plaintext_ptr: *mut *mut u8,
    raw_buf: *mut u8,
    raw_cap: usize,
    out_raw_len: *mut usize,
    out_raw_ptr: *mut *mut u8,
) -> i32 {
    ffi_catch_i32!({
        if handle.is_null()
            || out_plaintext_len.is_null()
            || out_plaintext_ptr.is_null()
            || out_raw_len.is_null()
            || out_raw_ptr.is_null()
        {
            return -1;
        }
        if (plaintext_cap > 0 && plaintext_buf.is_null()) || (raw_cap > 0 && raw_buf.is_null()) {
            return -1;
        }

        unsafe {
            *out_plaintext_len = 0;
            *out_plaintext_ptr = std::ptr::null_mut();
            *out_raw_len = 0;
            *out_raw_ptr = std::ptr::null_mut();
        }

        let session = unsafe { &*(handle as *const DeferredSession) };
        match session.drain_and_detach() {
            Ok((plaintext, raw_ahead)) => {
                unsafe {
                    write_or_export_bytes(
                        plaintext,
                        plaintext_buf,
                        plaintext_cap,
                        out_plaintext_len,
                        out_plaintext_ptr,
                    );
                    write_or_export_bytes(raw_ahead, raw_buf, raw_cap, out_raw_len, out_raw_ptr);
                }
                0
            }
            Err((_, msg)) => {
                eprintln!("xray_deferred_drain_and_detach_into: {}", msg);
                -1
            }
        }
    })
}

/// Compatibility no-op retained for Go-side API stability.
/// Returns 0 on success, -1 on error for invalid input.
#[unsafe(no_mangle)]
pub extern "C" fn xray_deferred_restore_nonblock(handle: *mut c_void) -> i32 {
    ffi_catch_i32!({
        if handle.is_null() {
            return -1;
        }
        let _session = unsafe { &*(handle as *const DeferredSession) };
        0
    })
}

/// Attempt deferred kTLS installation and report handle ownership in
/// XrayTlsResult.deferred_handle_ownership:
/// - consumed: handle must not be used again
/// - retained: caller may continue rustls I/O on fallback path
#[no_mangle]
pub extern "C" fn xray_deferred_enable_ktls(handle: *mut c_void, out: *mut XrayTlsResult) -> i32 {
    xray_deferred_enable_ktls_into(handle, out, std::ptr::null_mut(), 0)
}

#[no_mangle]
pub extern "C" fn xray_deferred_enable_ktls_into(
    handle: *mut c_void,
    out: *mut XrayTlsResult,
    drained_buf: *mut u8,
    drained_cap: usize,
) -> i32 {
    ffi_catch_i32!({
        if handle.is_null() || out.is_null() {
            return -1;
        }
        let out = unsafe { &mut *out };
        *out = XrayTlsResult::new();
        out.deferred_handle_ownership = DEFERRED_HANDLE_OWNERSHIP_CONSUMED;

        // Take ownership of the handle, then explicitly report whether the
        // handle was consumed or retained when returning to Go.
        let mut session = unsafe { Box::from_raw(handle as *mut DeferredSession) };
        let tls_version = session.tls_version;
        match session.enable_ktls() {
            Ok((
                cipher_suite,
                ktls_tx,
                ktls_rx,
                rx_seq_start,
                state_handle,
                mut tx_secret,
                mut rx_secret,
                drained,
            )) => {
                out.version = tls_version;
                out.cipher_suite = cipher_suite;
                out.ktls_tx = ktls_tx;
                out.ktls_rx = ktls_rx;
                out.rx_seq_start = rx_seq_start;
                out.state_handle = state_handle;

                let tx_len = copy_secret_to_result_slot(&mut out.tx_secret, &mut tx_secret);
                out.secret_len = tx_len as u8;
                let _ = copy_secret_to_result_slot(&mut out.rx_secret, &mut rx_secret);

                unsafe { tls::write_drained_to_result(out, drained, drained_buf, drained_cap) };
                out.deferred_handle_ownership = DEFERRED_HANDLE_OWNERSHIP_CONSUMED;
                0
            }
            Err((code, msg, retained)) => {
                out.set_error(code, &msg);
                if retained {
                    out.deferred_handle_ownership = DEFERRED_HANDLE_OWNERSHIP_RETAINED;
                    let _ = Box::into_raw(session);
                } else {
                    out.deferred_handle_ownership = DEFERRED_HANDLE_OWNERSHIP_CONSUMED;
                }
                code
            }
        }
    })
}

/// Free a deferred session handle without enabling kTLS.
/// Used for Vision flows where kTLS is not wanted.
/// Drains residual plaintext (defense-in-depth), then drops.
#[no_mangle]
pub extern "C" fn xray_deferred_free(handle: *mut c_void) {
    ffi_catch_void!({
        if !handle.is_null() {
            let session = unsafe { Box::from_raw(handle as *mut DeferredSession) };
            // Drain any residual plaintext for defense-in-depth
            {
                let mut tls_guard = session.tls.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(conn) = tls_guard.as_mut() {
                    tls::drain_plaintext(conn);
                }
            }
            // session drops here: reader/writer dup'd fds close,
            // _blocking_guard restores O_NONBLOCK, _timeout_guard restores timeouts
        }
    })
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
                let mut mlkem_x25519: Option<[u8; 32]> = None;
                while kpos + 4 <= (2 + shares_len).min(ks.len()) {
                    let group = u16::from_be_bytes([ks[kpos], ks[kpos + 1]]);
                    let klen = u16::from_be_bytes([ks[kpos + 2], ks[kpos + 3]]) as usize;
                    kpos += 4;
                    if kpos + klen > ks.len() {
                        break;
                    }
                    // Pure X25519 (group 0x001d): prefer this if present.
                    if group == 0x001d && klen == 32 {
                        let mut key = [0u8; 32];
                        key.copy_from_slice(&ks[kpos..kpos + 32]);
                        return Some(key);
                    }
                    // X25519MLKEM768 (group 0x11ec): 1184-byte ML-KEM-768 encap key ‖ 32-byte X25519
                    // (draft-ietf-tls-hybrid-design). Extract the trailing X25519 portion.
                    const MLKEM768_ENCAP_KEY_SIZE: usize = 1184;
                    if group == 0x11ec && klen == MLKEM768_ENCAP_KEY_SIZE + 32 {
                        let mut key = [0u8; 32];
                        key.copy_from_slice(&ks[kpos + MLKEM768_ENCAP_KEY_SIZE..kpos + klen]);
                        mlkem_x25519 = Some(key);
                    }
                    kpos += klen;
                }
                // Fall back to X25519 extracted from X25519MLKEM768 hybrid.
                if let Some(key) = mlkem_x25519 {
                    return Some(key);
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
        if cfg.is_null() {
            return;
        }
        let cfg = unsafe { &mut *cfg };
        if key_ptr.is_null() || len < 32 {
            return;
        }
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
        if cfg.is_null() {
            return;
        }
        let cfg = unsafe { &mut *cfg };
        if key_ptr.is_null() || len < 32 {
            return;
        }
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
        if cfg.is_null() {
            return;
        }
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
        if cfg.is_null() {
            return;
        }
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
        if cfg.is_null() {
            return;
        }
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
        if cfg.is_null() {
            return;
        }
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
        if cfg.is_null() {
            return;
        }
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
        if cfg.is_null() {
            return;
        }
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
        if cfg.is_null() {
            return;
        }
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
        if cfg.is_null() {
            return;
        }
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
        if cfg.is_null() {
            return;
        }
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
        if cfg.is_null() {
            return;
        }
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
        if cfg.is_null() {
            return;
        }
        let cfg = unsafe { &mut *cfg };
        if id_ptr.is_null() || id_len == 0 {
            return;
        }
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
        if cfg.is_null() {
            return;
        }
        let cfg = unsafe { &mut *cfg };
        if name_ptr.is_null() || name_len == 0 {
            return;
        }
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
    privkey_len: usize,
    cfg: *const RealityConfig,
    out: *mut XrayTlsResult,
) -> i32 {
    ffi_catch_i32!({
        if out.is_null() {
            return -1;
        }
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
        if privkey_len != 32 {
            out.set_error(-1, "invalid ecdh private key length");
            return -1;
        }

        let ch = unsafe { std::slice::from_raw_parts_mut(client_hello_ptr, client_hello_len) };
        let pk = unsafe { std::slice::from_raw_parts(ecdh_privkey_ptr, privkey_len) };
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

        let connect_result =
            reality_client_connect(fd, ch, &privkey, &server_pubkey, &cfg.short_id, cfg.version);
        privkey.zeroize();

        match connect_result {
            Ok(result) => {
                out.version = 0x0304; // TLS 1.3
                out.cipher_suite = result.tls_state.cipher_suite;
                out.rx_seq_start = result.tls_state.server_post_hs_records;

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
        if out.is_null() {
            return -1;
        }
        if cfg.is_null() {
            let out = unsafe { &mut *out };
            *out = XrayTlsResult::new();
            out.set_error(-1, "null config pointer");
            return -1;
        }
        let out = unsafe { &mut *out };
        *out = XrayTlsResult::new();

        let cfg = unsafe { &*cfg };
        let mut private_key = match cfg.private_key {
            Some(k) => k,
            None => {
                out.set_error(1, "private_key not set");
                return 1;
            }
        };

        let version_range = cfg.version_range.unwrap_or(((0, 0, 0), (255, 255, 255)));

        let accept_result = reality_server_accept(
            fd,
            &private_key,
            &cfg.short_ids,
            &cfg.server_names,
            cfg.max_time_diff,
            version_range,
        );
        private_key.zeroize();

        match accept_result {
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
    handshake_timeout_ms: u32,
    out: *mut XrayTlsResult,
) -> i32 {
    xray_reality_server_handshake_into(fd, cfg, handshake_timeout_ms, out, std::ptr::null_mut(), 0)
}

#[no_mangle]
pub extern "C" fn xray_reality_server_handshake_into(
    fd: i32,
    cfg: *const RealityConfig,
    handshake_timeout_ms: u32,
    out: *mut XrayTlsResult,
    drained_buf: *mut u8,
    drained_cap: usize,
) -> i32 {
    ffi_catch_i32!({
        if out.is_null() {
            return -1;
        }
        if cfg.is_null() {
            let out = unsafe { &mut *out };
            *out = XrayTlsResult::new();
            out.set_error(-1, "null config pointer");
            return -1;
        }
        let out = unsafe { &mut *out };
        *out = XrayTlsResult::new();
        let cfg = unsafe { &*cfg };

        let handshake_timeout = tls::handshake_timeout_from_ms(handshake_timeout_ms);
        match reality_server_handshake_full(fd, cfg, handshake_timeout) {
            Ok((
                cipher_suite,
                ktls_tx,
                ktls_rx,
                state_handle,
                mut tx_secret,
                mut rx_secret,
                drained,
            )) => {
                out.version = 0x0304;
                out.cipher_suite = cipher_suite;
                out.ktls_tx = ktls_tx;
                out.ktls_rx = ktls_rx;
                out.state_handle = state_handle;

                let tx_len = copy_secret_to_result_slot(&mut out.tx_secret, &mut tx_secret);
                out.secret_len = tx_len as u8;
                let _ = copy_secret_to_result_slot(&mut out.rx_secret, &mut rx_secret);

                // Forward drained data to Go (Go buffer first, Rust allocation fallback)
                unsafe { tls::write_drained_to_result(out, drained, drained_buf, drained_cap) };
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
    fn test_copy_secret_to_result_slot_zeroizes_source() {
        let mut dst = [0u8; 8];
        let mut secret = vec![1u8, 2, 3, 4, 5, 6];
        let copied = copy_secret_to_result_slot(&mut dst, &mut secret);
        assert_eq!(copied, 6);
        assert_eq!(&dst[..6], &[1, 2, 3, 4, 5, 6]);
        assert!(secret.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_copy_secret_to_result_slot_truncates_and_zeroizes() {
        let mut dst = [0u8; 4];
        let mut secret = vec![9u8, 8, 7, 6, 5, 4];
        let copied = copy_secret_to_result_slot(&mut dst, &mut secret);
        assert_eq!(copied, 4);
        assert_eq!(&dst, &[9, 8, 7, 6]);
        assert!(secret.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_server_name_allowed_exact_match() {
        let names = vec!["example.com".to_string(), "www.example.org".to_string()];
        assert!(server_name_allowed(&names, "example.com"));
        assert!(!server_name_allowed(&names, "EXAMPLE.COM"));
        assert!(!server_name_allowed(&names, "unknown.example"));
    }

    #[test]
    fn test_server_name_allowed_length_mismatch_rejected() {
        let names = vec!["example.com".to_string()];
        assert!(!server_name_allowed(&names, "example.co"));
        assert!(!server_name_allowed(&names, "example.com."));
    }

    #[test]
    fn test_server_name_allowed_oversized_rejected() {
        let oversized = "a".repeat(MAX_SERVER_NAME_LEN + 1);
        let names = vec![oversized.clone()];
        assert!(!server_name_allowed(&names, &oversized));
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

    #[test]
    fn test_write_all_with_poll_basic() {
        // Test write_all_with_poll on a pipe (always blocking-safe)
        use std::os::unix::io::AsRawFd;
        let (reader, writer) = std::os::unix::net::UnixStream::pair().unwrap();
        let fd = writer.as_raw_fd();
        let data = b"hello from write_all_with_poll";
        write_all_with_poll(fd, data).unwrap();

        let mut buf = vec![0u8; data.len()];
        use std::io::Read;
        let mut r = reader;
        r.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, data);
    }

    #[test]
    fn test_deferred_read_deadline_uses_wakeup_ceiling_for_unbounded_reads() {
        let (deadline, armed) = deferred_read_deadline(-1);
        assert!(armed);
        let remaining = deadline
            .expect("missing wake-up deadline")
            .saturating_duration_since(Instant::now());
        assert!(
            remaining <= DEFERRED_READ_WAKEUP_CEILING,
            "remaining {:?} exceeded ceiling {:?}",
            remaining,
            DEFERRED_READ_WAKEUP_CEILING
        );
        assert!(
            remaining >= Duration::from_millis(25),
            "remaining {:?} was unexpectedly short",
            remaining
        );
    }

    #[test]
    fn test_deferred_read_deadline_preserves_explicit_deadlines() {
        let (deadline, armed) = deferred_read_deadline(250);
        assert!(!armed);
        let remaining = deadline
            .expect("missing explicit deadline")
            .saturating_duration_since(Instant::now());
        assert!(
            remaining <= Duration::from_millis(250),
            "remaining {:?} exceeded explicit timeout",
            remaining
        );
        assert!(
            remaining >= Duration::from_millis(200),
            "remaining {:?} was unexpectedly short",
            remaining
        );
    }
}
