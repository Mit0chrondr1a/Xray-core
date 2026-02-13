//! REALITY protocol implementation.
//!
//! REALITY is an anti-censorship protocol that disguises proxy traffic as
//! legitimate TLS connections to real websites. It embeds authentication data
//! in the ClientHello SessionId field and uses a custom certificate verification
//! scheme based on ECDH shared secrets.

use std::ffi::c_void;
use std::io::{self, Read};
use std::net::TcpStream;
use std::os::unix::io::FromRawFd;
use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::{aead::{Aead, KeyInit}, Aes128Gcm};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::tls::XrayTlsResult;
use crate::tls13::{self, Tls13State, Tls13Error};

// ---------------------------------------------------------------------------
// Public result types
// ---------------------------------------------------------------------------

#[derive(Debug)]
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

fn reality_auth_key(shared_secret: &[u8], random_prefix: &[u8]) -> Vec<u8> {
    // AuthKey = HKDF-SHA256(shared_secret, random[:20], info="REALITY")
    let hkdf = Hkdf::<Sha256>::new(Some(random_prefix), shared_secret);
    let mut key = vec![0u8; 32];
    hkdf.expand(b"REALITY", &mut key).unwrap();
    key
}

fn aes_gcm_seal(key: &[u8], nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes128Gcm::new_from_slice(&key[..16])
        .map_err(|e| format!("aes key: {}", e))?;
    let nonce = aes_gcm::Nonce::from_slice(nonce);
    let payload = aes_gcm::aead::Payload { msg: plaintext, aad };
    cipher.encrypt(nonce, payload)
        .map_err(|e| format!("aes seal: {}", e))
}

fn aes_gcm_open(key: &[u8], nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes128Gcm::new_from_slice(&key[..16])
        .map_err(|e| format!("aes key: {}", e))?;
    let nonce = aes_gcm::Nonce::from_slice(nonce);
    let payload = aes_gcm::aead::Payload { msg: ciphertext, aad };
    cipher.decrypt(nonce, payload)
        .map_err(|e| format!("aes open: {}", e))
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
    let auth_key = reality_auth_key(shared_secret.as_bytes(), &random[..20]);

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

    // AES-GCM-128 seal: nonce=random[20:32], plaintext=session_id[0..16], aad=[]
    // This produces 16 + 16 = 32 bytes (16 ciphertext + 16 tag)
    let nonce = &random[20..32];
    let encrypted = aes_gcm_seal(&auth_key, nonce, &session_id_plain, &[])
        .map_err(|e| RealityError::Protocol(e))?;

    // Overwrite session_id in ClientHello (offset 39, 32 bytes)
    if encrypted.len() != 32 {
        return Err(RealityError::Protocol(format!(
            "expected 32 byte encrypted session_id, got {}", encrypted.len()
        )));
    }
    client_hello_raw[39..71].copy_from_slice(&encrypted);

    // Complete TLS 1.3 handshake
    let tls_state = tls13::complete_tls13_handshake(fd, client_hello_raw, ecdh_privkey)?;

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
    pub auth_key: Vec<u8>,
    pub sni: String,
    pub client_hello_raw: Vec<u8>,
}

pub fn reality_server_accept(
    fd: i32,
    private_key: &[u8; 32],
    short_ids: &[Vec<u8>],
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
        return Err(RealityError::Protocol("ClientHello record too large".into()));
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

    // Find the client's X25519 key_share
    let client_x25519 = parse_x25519_key_share(&ch_raw)
        .ok_or_else(|| RealityError::Protocol("no X25519 key_share in ClientHello".into()))?;

    // ECDH
    let privkey = StaticSecret::from(*private_key);
    let client_pubkey = PublicKey::from(client_x25519);
    let shared_secret = privkey.diffie_hellman(&client_pubkey);

    // Derive auth key
    let auth_key = reality_auth_key(shared_secret.as_bytes(), &random[..20]);

    // Decrypt session_id: nonce=random[20:32], ciphertext=encrypted_session_id, aad=[]
    let nonce = &random[20..32];
    let plaintext = aes_gcm_open(&auth_key, nonce, &encrypted_session_id, &[])
        .map_err(|e| RealityError::AuthFailed(format!("session_id decrypt: {}", e)))?;

    if plaintext.len() != 16 {
        return Err(RealityError::AuthFailed("decrypted session_id wrong size".into()));
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

    // Validate timestamp
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u64;
    let ts = timestamp as u64;
    let diff = if now > ts { now - ts } else { ts - now };
    if diff > max_time_diff / 1000 {
        return Err(RealityError::AuthFailed(format!(
            "timestamp diff {}s exceeds max {}ms",
            diff, max_time_diff
        )));
    }

    // Validate short_id
    let short_id_trimmed: Vec<u8> = short_id.iter().copied().take_while(|&b| b != 0).collect();
    if !short_ids.iter().any(|s| *s == short_id_trimmed || *s == short_id) {
        return Err(RealityError::AuthFailed("short_id not in allowed list".into()));
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
    if pos + 2 > ch.len() { return None; }
    let cs_len = u16::from_be_bytes([ch[pos], ch[pos + 1]]) as usize;
    pos += 2 + cs_len;

    // compression: length(1) + data
    if pos + 1 > ch.len() { return None; }
    let comp_len = ch[pos] as usize;
    pos += 1 + comp_len;

    // extensions: length(2)
    if pos + 2 > ch.len() { return None; }
    let ext_len = u16::from_be_bytes([ch[pos], ch[pos + 1]]) as usize;
    pos += 2;
    let ext_end = (pos + ext_len).min(ch.len());

    while pos + 4 <= ext_end {
        let etype = u16::from_be_bytes([ch[pos], ch[pos + 1]]);
        let elen = u16::from_be_bytes([ch[pos + 2], ch[pos + 3]]) as usize;
        pos += 4;
        if pos + elen > ext_end { break; }

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
    if ch.len() < 39 { return None; }
    let session_id_len = ch[38] as usize;
    let mut pos = 39 + session_id_len;

    // cipher_suites
    if pos + 2 > ch.len() { return None; }
    let cs_len = u16::from_be_bytes([ch[pos], ch[pos + 1]]) as usize;
    pos += 2 + cs_len;

    // compression
    if pos + 1 > ch.len() { return None; }
    let comp_len = ch[pos] as usize;
    pos += 1 + comp_len;

    // extensions
    if pos + 2 > ch.len() { return None; }
    let ext_len = u16::from_be_bytes([ch[pos], ch[pos + 1]]) as usize;
    pos += 2;
    let ext_end = (pos + ext_len).min(ch.len());

    while pos + 4 <= ext_end {
        let etype = u16::from_be_bytes([ch[pos], ch[pos + 1]]);
        let elen = u16::from_be_bytes([ch[pos + 2], ch[pos + 3]]) as usize;
        pos += 4;
        if pos + elen > ext_end { break; }

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
                    if kpos + klen > ks.len() { break; }
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

// ---------------------------------------------------------------------------
// FFI Exports — Config builder
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn xray_reality_config_new(is_client: bool) -> *mut RealityConfig {
    Box::into_raw(Box::new(RealityConfig {
        is_client,
        server_pubkey: None,
        private_key: None,
        short_id: Vec::new(),
        short_ids: Vec::new(),
        server_names: Vec::new(),
        version: (0, 0, 0),
        version_range: None,
        max_time_diff: 120_000, // 2 minutes default
        mldsa65_verify_key: Vec::new(),
        mldsa65_sign_key: Vec::new(),
        dest: String::new(),
        tls_cert_pem: Vec::new(),
        tls_key_pem: Vec::new(),
    }))
}

#[no_mangle]
pub extern "C" fn xray_reality_config_set_server_pubkey(
    cfg: *mut RealityConfig,
    key_ptr: *const u8,
    _len: usize,
) {
    let cfg = unsafe { &mut *cfg };
    let key = unsafe { std::slice::from_raw_parts(key_ptr, 32) };
    let mut k = [0u8; 32];
    k.copy_from_slice(key);
    cfg.server_pubkey = Some(k);
}

#[no_mangle]
pub extern "C" fn xray_reality_config_set_private_key(
    cfg: *mut RealityConfig,
    key_ptr: *const u8,
    _len: usize,
) {
    let cfg = unsafe { &mut *cfg };
    let key = unsafe { std::slice::from_raw_parts(key_ptr, 32) };
    let mut k = [0u8; 32];
    k.copy_from_slice(key);
    cfg.private_key = Some(k);
}

#[no_mangle]
pub extern "C" fn xray_reality_config_set_short_id(
    cfg: *mut RealityConfig,
    id_ptr: *const u8,
    id_len: usize,
) {
    let cfg = unsafe { &mut *cfg };
    let id = unsafe { std::slice::from_raw_parts(id_ptr, id_len) };
    cfg.short_id = id.to_vec();
}

#[no_mangle]
pub extern "C" fn xray_reality_config_set_mldsa65_verify(
    cfg: *mut RealityConfig,
    key_ptr: *const u8,
    key_len: usize,
) {
    let cfg = unsafe { &mut *cfg };
    let key = unsafe { std::slice::from_raw_parts(key_ptr, key_len) };
    cfg.mldsa65_verify_key = key.to_vec();
}

#[no_mangle]
pub extern "C" fn xray_reality_config_set_version(
    cfg: *mut RealityConfig,
    major: u8,
    minor: u8,
    patch: u8,
) {
    let cfg = unsafe { &mut *cfg };
    cfg.version = (major, minor, patch);
}

#[no_mangle]
pub extern "C" fn xray_reality_config_free(cfg: *mut RealityConfig) {
    if !cfg.is_null() {
        let _ = unsafe { Box::from_raw(cfg) };
    }
}

#[no_mangle]
pub extern "C" fn xray_reality_config_set_server_names(
    cfg: *mut RealityConfig,
    data_ptr: *const u8,
    data_len: usize,
) {
    let cfg = unsafe { &mut *cfg };
    let data = unsafe { std::slice::from_raw_parts(data_ptr, data_len) };
    // Parse as null-separated UTF-8 strings
    cfg.server_names.clear();
    for chunk in data.split(|&b| b == 0) {
        if let Ok(s) = std::str::from_utf8(chunk) {
            if !s.is_empty() {
                cfg.server_names.push(s.to_string());
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn xray_reality_config_set_short_ids(
    cfg: *mut RealityConfig,
    data_ptr: *const u8,
    data_len: usize,
) {
    let cfg = unsafe { &mut *cfg };
    let data = unsafe { std::slice::from_raw_parts(data_ptr, data_len) };
    // Parse as null-separated binary short IDs
    cfg.short_ids.clear();
    for chunk in data.split(|&b| b == 0) {
        if !chunk.is_empty() {
            cfg.short_ids.push(chunk.to_vec());
        }
    }
}

#[no_mangle]
pub extern "C" fn xray_reality_config_set_mldsa65_key(
    cfg: *mut RealityConfig,
    key_ptr: *const u8,
    key_len: usize,
) {
    let cfg = unsafe { &mut *cfg };
    let key = unsafe { std::slice::from_raw_parts(key_ptr, key_len) };
    cfg.mldsa65_sign_key = key.to_vec();
}

#[no_mangle]
pub extern "C" fn xray_reality_config_set_dest(
    cfg: *mut RealityConfig,
    addr_ptr: *const u8,
    addr_len: usize,
) {
    let cfg = unsafe { &mut *cfg };
    let addr = unsafe { std::slice::from_raw_parts(addr_ptr, addr_len) };
    if let Ok(s) = std::str::from_utf8(addr) {
        cfg.dest = s.to_string();
    }
}

#[no_mangle]
pub extern "C" fn xray_reality_config_set_max_time_diff(
    cfg: *mut RealityConfig,
    ms: u64,
) {
    let cfg = unsafe { &mut *cfg };
    cfg.max_time_diff = ms;
}

#[no_mangle]
pub extern "C" fn xray_reality_config_set_version_range(
    cfg: *mut RealityConfig,
    min_major: u8, min_minor: u8, min_patch: u8,
    max_major: u8, max_minor: u8, max_patch: u8,
) {
    let cfg = unsafe { &mut *cfg };
    cfg.version_range = Some((
        (min_major, min_minor, min_patch),
        (max_major, max_minor, max_patch),
    ));
}

#[no_mangle]
pub extern "C" fn xray_reality_config_set_tls_cert(
    cfg: *mut RealityConfig,
    cert_ptr: *const u8,
    cert_len: usize,
    key_ptr: *const u8,
    key_len: usize,
) {
    let cfg = unsafe { &mut *cfg };
    let cert = unsafe { std::slice::from_raw_parts(cert_ptr, cert_len) };
    let key = unsafe { std::slice::from_raw_parts(key_ptr, key_len) };
    cfg.tls_cert_pem = cert.to_vec();
    cfg.tls_key_pem = key.to_vec();
}

// Keep the individual add functions for compatibility
#[no_mangle]
pub extern "C" fn xray_reality_config_add_short_id(
    cfg: *mut RealityConfig,
    id_ptr: *const u8,
    id_len: usize,
) {
    let cfg = unsafe { &mut *cfg };
    let id = unsafe { std::slice::from_raw_parts(id_ptr, id_len) };
    cfg.short_ids.push(id.to_vec());
}

#[no_mangle]
pub extern "C" fn xray_reality_config_add_server_name(
    cfg: *mut RealityConfig,
    name_ptr: *const u8,
    name_len: usize,
) {
    let cfg = unsafe { &mut *cfg };
    let name = unsafe { std::slice::from_raw_parts(name_ptr, name_len) };
    if let Ok(s) = String::from_utf8(name.to_vec()) {
        cfg.server_names.push(s);
    }
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
    let result = std::panic::catch_unwind(|| {
        let out = unsafe { &mut *out };
        *out = XrayTlsResult::new();

        let cfg = unsafe { &*cfg };
        let ch = unsafe { std::slice::from_raw_parts_mut(client_hello_ptr, client_hello_len) };
        let pk = unsafe { std::slice::from_raw_parts(ecdh_privkey_ptr, 32) };
        let mut privkey = [0u8; 32];
        privkey.copy_from_slice(pk);

        let server_pubkey = match cfg.server_pubkey {
            Some(k) => k,
            None => {
                out.set_error(1, "server_pubkey not set");
                return 1;
            }
        };

        match reality_client_connect(
            fd,
            ch,
            &privkey,
            &server_pubkey,
            &cfg.short_id,
            cfg.version,
        ) {
            Ok(result) => {
                out.version = 0x0304; // TLS 1.3
                out.cipher_suite = result.tls_state.cipher_suite;
                // kTLS not enabled yet for REALITY path (Phase 2 future work)
                out.ktls_tx = false;
                out.ktls_rx = false;
                // No state handle — kTLS not active, no KeyUpdate needed
                out.state_handle = std::ptr::null_mut();
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
    });
    result.unwrap_or_else(|_| {
        let out = unsafe { &mut *out };
        out.set_error(-1, "panic in xray_reality_client_connect");
        -1
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
    let result = std::panic::catch_unwind(|| {
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
    });
    result.unwrap_or_else(|_| {
        let out = unsafe { &mut *out };
        out.set_error(-1, "panic in xray_reality_server_accept");
        -1
    })
}

#[no_mangle]
pub extern "C" fn xray_reality_state_free(state: *mut c_void) {
    if !state.is_null() {
        let _ = unsafe { Box::from_raw(state as *mut RealityResult) };
    }
}

#[no_mangle]
pub extern "C" fn xray_reality_server_state_free(state: *mut c_void) {
    if !state.is_null() {
        let _ = unsafe { Box::from_raw(state as *mut RealityServerResult) };
    }
}
