use std::ffi::c_void;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};

/// Cached CryptoProvider to avoid reconstructing algorithm tables per handshake.
static DEFAULT_PROVIDER: std::sync::OnceLock<Arc<rustls::crypto::CryptoProvider>> =
    std::sync::OnceLock::new();

pub(crate) fn cached_provider() -> Arc<rustls::crypto::CryptoProvider> {
    DEFAULT_PROVIDER
        .get_or_init(|| Arc::new(default_provider()))
        .clone()
}
use rustls::{
    ClientConfig, ClientConnection, ConnectionTrafficSecrets, ServerConfig, ServerConnection,
};
use rustls_pki_types::pem::PemObject;

// ---------------------------------------------------------------------------
// FFI result struct returned to Go
// ---------------------------------------------------------------------------

pub const DEFERRED_HANDLE_OWNERSHIP_UNKNOWN: u8 = 0;
pub const DEFERRED_HANDLE_OWNERSHIP_CONSUMED: u8 = 1;
pub const DEFERRED_HANDLE_OWNERSHIP_RETAINED: u8 = 2;

#[repr(C)]
pub struct XrayTlsResult {
    pub ktls_tx: bool,
    pub ktls_rx: bool,
    pub version: u16,
    pub cipher_suite: u16,
    pub alpn: [u8; 32],
    pub state_handle: *mut c_void,
    pub error_code: i32,
    // Deferred handle ownership outcome for xray_deferred_enable_ktls_*:
    // 0 = unknown / not-applicable, 1 = consumed, 2 = retained.
    pub deferred_handle_ownership: u8,
    pub error_msg: [u8; 256],
    pub tx_secret: [u8; 48],
    pub rx_secret: [u8; 48],
    pub secret_len: u8,
    pub drained_ptr: *mut u8,
    pub drained_len: u32,
    // kTLS RX starting sequence number used during installation.
    // For TLS 1.3 client flows this includes post-handshake records
    // (e.g. NewSessionTicket) already consumed before handoff.
    pub rx_seq_start: u64,
}

impl XrayTlsResult {
    pub(crate) fn new() -> Self {
        Self {
            ktls_tx: false,
            ktls_rx: false,
            version: 0,
            cipher_suite: 0,
            alpn: [0u8; 32],
            state_handle: std::ptr::null_mut(),
            error_code: 0,
            deferred_handle_ownership: 0,
            error_msg: [0u8; 256],
            tx_secret: [0u8; 48],
            rx_secret: [0u8; 48],
            secret_len: 0,
            drained_ptr: std::ptr::null_mut(),
            drained_len: 0,
            rx_seq_start: 0,
        }
    }

    pub(crate) fn set_error(&mut self, code: i32, msg: &str) {
        self.error_code = code;
        let bytes = msg.as_bytes();
        let len = bytes.len().min(255);
        self.error_msg[..len].copy_from_slice(&bytes[..len]);
        self.error_msg[len] = 0;
    }

    /// Zero out the tx_secret and rx_secret arrays and reset secret_len.
    /// Called after secrets have been consumed to avoid leaving key material
    /// in the FFI result struct.
    pub(crate) fn zeroize_secrets(&mut self) {
        self.tx_secret.zeroize();
        self.rx_secret.zeroize();
        self.secret_len = 0;
    }
}

pub(crate) unsafe fn write_drained_to_result(
    out: &mut XrayTlsResult,
    mut drained: Vec<u8>,
    drained_buf: *mut u8,
    drained_cap: usize,
) {
    out.drained_ptr = std::ptr::null_mut();
    out.drained_len = 0;
    if drained.is_empty() {
        return;
    }
    let len = drained.len();
    if !drained_buf.is_null() && drained_cap >= len {
        std::ptr::copy_nonoverlapping(drained.as_ptr(), drained_buf, len);
        drained.zeroize();
        out.drained_len = len as u32;
        return;
    }
    let boxed = drained.into_boxed_slice();
    out.drained_ptr = Box::into_raw(boxed) as *mut u8;
    out.drained_len = len as u32;
}

// ---------------------------------------------------------------------------
// TlsState — kept alive across FFI boundary for KeyUpdate
// ---------------------------------------------------------------------------

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct TlsState {
    fd: i32,
    cipher_suite: u16,
    // After kTLS handoff, stores the traffic secrets needed for KeyUpdate.
    // For TLS 1.3 KeyUpdate, we'd need to re-derive keys; for now this is
    // a placeholder that tracks the connection metadata.
    _tx_secret: Vec<u8>,
    _rx_secret: Vec<u8>,
}

impl TlsState {
    pub(crate) fn new(fd: i32, cipher_suite: u16) -> Self {
        Self {
            fd,
            cipher_suite,
            _tx_secret: Vec::new(),
            _rx_secret: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// TlsConfig — opaque builder accumulated from Go side
// ---------------------------------------------------------------------------

pub struct TlsConfig {
    is_server: bool,
    server_name: Option<String>,
    certs: Vec<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
    root_cas: Vec<CertificateDer<'static>>,
    use_system_roots: bool,
    alpn_protocols: Vec<Vec<u8>>,
    min_version: Option<u16>,
    max_version: Option<u16>,
    insecure_skip_verify: bool,
    pinned_cert_sha256: Vec<Vec<u8>>,
    verify_names: Vec<String>,
    key_log_path: Option<String>,
}

// ---------------------------------------------------------------------------
// kTLS constants and structs (Linux kernel)
// ---------------------------------------------------------------------------

pub(crate) const SOL_TCP: i32 = 6;
pub(crate) const TCP_ULP: i32 = 31;
pub(crate) const SOL_TLS: i32 = 282;
pub(crate) const TLS_TX: i32 = 1;
pub(crate) const TLS_RX: i32 = 2;

pub(crate) const TLS_1_2_VERSION: u16 = 0x0303;
pub(crate) const TLS_1_3_VERSION: u16 = 0x0304;

pub(crate) const TLS_CIPHER_AES_GCM_128: u16 = 51;
pub(crate) const TLS_CIPHER_AES_GCM_256: u16 = 52;
pub(crate) const TLS_CIPHER_CHACHA20_POLY1305: u16 = 54;

#[repr(C)]
pub(crate) struct TlsCryptoInfoAesGcm128 {
    pub version: u16,
    pub cipher_type: u16,
    pub iv: [u8; 8],
    pub key: [u8; 16],
    pub salt: [u8; 4],
    pub rec_seq: [u8; 8],
}

#[repr(C)]
pub(crate) struct TlsCryptoInfoAesGcm256 {
    pub version: u16,
    pub cipher_type: u16,
    pub iv: [u8; 8],
    pub key: [u8; 32],
    pub salt: [u8; 4],
    pub rec_seq: [u8; 8],
}

#[repr(C)]
pub(crate) struct TlsCryptoInfoChacha20Poly1305 {
    pub version: u16,
    pub cipher_type: u16,
    pub iv: [u8; 12],
    pub key: [u8; 32],
    // chacha20-poly1305 has no separate salt field in kernel struct
    pub rec_seq: [u8; 8],
}

// ---------------------------------------------------------------------------
// kTLS helpers
// ---------------------------------------------------------------------------

pub(crate) fn setup_ulp_pub(fd: i32) -> std::io::Result<()> {
    setup_ulp(fd)
}

pub(crate) fn setup_ulp(fd: i32) -> std::io::Result<()> {
    match setup_ulp_once(fd) {
        Ok(()) => Ok(()),
        Err(e) if e.raw_os_error() == Some(libc::ENOTCONN) => {
            // Race window: peer may close between handshake completion and
            // kTLS install. Single retry with 100us sleep covers the gap.
            std::thread::sleep(std::time::Duration::from_micros(100));
            setup_ulp_once(fd)
        }
        Err(e) => Err(e),
    }
}

fn setup_ulp_once(fd: i32) -> std::io::Result<()> {
    let ulp = b"tls\0";
    let ret = unsafe {
        libc::setsockopt(
            fd,
            SOL_TCP,
            TCP_ULP,
            ulp.as_ptr() as *const c_void,
            ulp.len() as libc::socklen_t,
        )
    };
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOTCONN) {
            // Diagnostic: why is socket not in ESTABLISHED state?
            let mut addr: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            let peer_ok = unsafe {
                libc::getpeername(fd, &mut addr as *mut _ as *mut libc::sockaddr, &mut len)
            } == 0;
            eprintln!(
                "setup_ulp: ENOTCONN on fd={}, getpeername={}",
                fd,
                if peer_ok {
                    "ok (has peer)"
                } else {
                    "failed (no peer)"
                }
            );
            // Preserve raw ENOTCONN so caller retry logic can match errno.
            return Err(err);
        }
        return Err(err);
    }
    Ok(())
}

pub(crate) const DEFAULT_NATIVE_HANDSHAKE_TIMEOUT_MS: u32 = 30_000;

pub(crate) fn handshake_timeout_from_ms(timeout_ms: u32) -> std::time::Duration {
    let ms = if timeout_ms == 0 {
        DEFAULT_NATIVE_HANDSHAKE_TIMEOUT_MS
    } else {
        timeout_ms
    };
    std::time::Duration::from_millis(ms as u64)
}

fn seq_to_bytes(seq: u64) -> [u8; 8] {
    seq.to_be_bytes()
}

/// Install kTLS crypto info for one direction on the given fd.
/// `iv_bytes` is the full 12-byte IV from rustls. For AES-GCM, the first 4
/// bytes are the "salt" (implicit nonce) and the remaining 8 are the
/// explicit IV. For ChaCha20-Poly1305, all 12 bytes are the IV.
pub(crate) fn install_ktls(
    fd: i32,
    direction: i32,
    tls_version: u16,
    secrets: &ConnectionTrafficSecrets,
    seq: u64,
) -> std::io::Result<()> {
    let version = match tls_version {
        0x0303 => TLS_1_2_VERSION,
        0x0304 => TLS_1_3_VERSION,
        v => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                format!("unsupported TLS version: 0x{:04x}", v),
            ))
        }
    };

    let rec_seq = seq_to_bytes(seq);

    match secrets {
        ConnectionTrafficSecrets::Aes128Gcm { key, iv } => {
            let key_bytes = key.as_ref();
            let iv_bytes = iv.as_ref();
            let mut info = TlsCryptoInfoAesGcm128 {
                version,
                cipher_type: TLS_CIPHER_AES_GCM_128,
                iv: [0u8; 8],
                key: [0u8; 16],
                salt: [0u8; 4],
                rec_seq,
            };
            info.salt.copy_from_slice(&iv_bytes[..4]);
            info.iv.copy_from_slice(&iv_bytes[4..12]);
            info.key.copy_from_slice(key_bytes);
            let ret = unsafe {
                libc::setsockopt(
                    fd,
                    SOL_TLS,
                    direction,
                    &info as *const _ as *const c_void,
                    std::mem::size_of::<TlsCryptoInfoAesGcm128>() as libc::socklen_t,
                )
            };
            info.key.zeroize();
            info.iv.zeroize();
            info.salt.zeroize();
            if ret < 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        ConnectionTrafficSecrets::Aes256Gcm { key, iv } => {
            let key_bytes = key.as_ref();
            let iv_bytes = iv.as_ref();
            let mut info = TlsCryptoInfoAesGcm256 {
                version,
                cipher_type: TLS_CIPHER_AES_GCM_256,
                iv: [0u8; 8],
                key: [0u8; 32],
                salt: [0u8; 4],
                rec_seq,
            };
            info.salt.copy_from_slice(&iv_bytes[..4]);
            info.iv.copy_from_slice(&iv_bytes[4..12]);
            info.key.copy_from_slice(key_bytes);
            let ret = unsafe {
                libc::setsockopt(
                    fd,
                    SOL_TLS,
                    direction,
                    &info as *const _ as *const c_void,
                    std::mem::size_of::<TlsCryptoInfoAesGcm256>() as libc::socklen_t,
                )
            };
            info.key.zeroize();
            info.iv.zeroize();
            info.salt.zeroize();
            if ret < 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv } => {
            let key_bytes = key.as_ref();
            let iv_bytes = iv.as_ref();
            let mut info = TlsCryptoInfoChacha20Poly1305 {
                version,
                cipher_type: TLS_CIPHER_CHACHA20_POLY1305,
                iv: [0u8; 12],
                key: [0u8; 32],
                rec_seq,
            };
            info.iv.copy_from_slice(iv_bytes);
            info.key.copy_from_slice(key_bytes);
            let ret = unsafe {
                libc::setsockopt(
                    fd,
                    SOL_TLS,
                    direction,
                    &info as *const _ as *const c_void,
                    std::mem::size_of::<TlsCryptoInfoChacha20Poly1305>() as libc::socklen_t,
                )
            };
            info.key.zeroize();
            info.iv.zeroize();
            if ret < 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "unsupported cipher suite for kTLS",
            ));
        }
    }
    Ok(())
}

pub(crate) fn cipher_suite_to_u16(secrets: &ConnectionTrafficSecrets) -> u16 {
    match secrets {
        ConnectionTrafficSecrets::Aes128Gcm { .. } => 0x1301, // TLS_AES_128_GCM_SHA256
        ConnectionTrafficSecrets::Aes256Gcm { .. } => 0x1302, // TLS_AES_256_GCM_SHA384
        ConnectionTrafficSecrets::Chacha20Poly1305 { .. } => 0x1303, // TLS_CHACHA20_POLY1305_SHA256
        _ => 0,
    }
}

// ---------------------------------------------------------------------------
// Custom certificate verifiers
// ---------------------------------------------------------------------------

mod verifier {
    use std::sync::Arc;

    use ring::digest;
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::client::WebPkiServerVerifier;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, Error, SignatureScheme};
    use subtle::ConstantTimeEq;

    /// Skip all certificate verification.
    #[derive(Debug)]
    pub struct AllowInsecure;

    impl ServerCertVerifier for AllowInsecure {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    /// Verify that the leaf certificate's SHA-256 hash matches one of the
    /// pinned hashes.
    #[derive(Debug)]
    pub struct PinnedCertSha256 {
        pub hashes: Vec<Vec<u8>>,
        pub verifier: Arc<WebPkiServerVerifier>,
    }

    impl ServerCertVerifier for PinnedCertSha256 {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            let hash = digest::digest(&digest::SHA256, end_entity.as_ref());
            // Constant-time comparison without short-circuit: iterate all pins
            // to prevent a MITM from timing-leaking the expected hash bytes.
            let matched = self
                .hashes
                .iter()
                .fold(subtle::Choice::from(0u8), |acc, h| {
                    acc | h.as_slice().ct_eq(hash.as_ref())
                });
            if bool::from(matched) {
                Ok(ServerCertVerified::assertion())
            } else {
                Err(Error::General("certificate SHA-256 pin mismatch".into()))
            }
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            self.verifier.verify_tls12_signature(message, cert, dss)
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            self.verifier.verify_tls13_signature(message, cert, dss)
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.verifier.supported_verify_schemes()
        }
    }

    /// Verify that the certificate's SANs or CN match one of the given names,
    /// with suffix matching support (e.g. ".example.com" matches
    /// "foo.example.com").
    #[derive(Debug)]
    pub struct VerifyByName {
        pub names: Vec<String>,
        pub hashes: Vec<Vec<u8>>,
        pub verifier: Arc<WebPkiServerVerifier>,
    }

    fn suffix_matches_dns_name(pattern: &str, server_name: &ServerName<'_>) -> bool {
        let suffix = match pattern.strip_prefix('.') {
            Some(s) if !s.is_empty() => s.to_ascii_lowercase(),
            _ => return false,
        };
        let dns_name = match server_name {
            ServerName::DnsName(dns) => dns.as_ref().to_ascii_lowercase(),
            ServerName::IpAddress(_) => return false,
            _ => return false,
        };
        if dns_name.len() <= suffix.len() || !dns_name.ends_with(&suffix) {
            return false;
        }
        matches!(
            dns_name.as_bytes().get(dns_name.len() - suffix.len() - 1),
            Some(b'.')
        )
    }

    impl ServerCertVerifier for VerifyByName {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            intermediates: &[CertificateDer<'_>],
            server_name: &ServerName<'_>,
            ocsp_response: &[u8],
            now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            // Check pinned hash if any (constant-time, no short-circuit)
            if !self.hashes.is_empty() {
                let hash = digest::digest(&digest::SHA256, end_entity.as_ref());
                let matched = self
                    .hashes
                    .iter()
                    .fold(subtle::Choice::from(0u8), |acc, h| {
                        acc | h.as_slice().ct_eq(hash.as_ref())
                    });
                if bool::from(matched) {
                    return Ok(ServerCertVerified::assertion());
                }
            }

            // Validate cert chain + subject names against configured names.
            for name in &self.names {
                if name.starts_with('.') {
                    if suffix_matches_dns_name(name, server_name)
                        && self
                            .verifier
                            .verify_server_cert(
                                end_entity,
                                intermediates,
                                server_name,
                                ocsp_response,
                                now,
                            )
                            .is_ok()
                    {
                        return Ok(ServerCertVerified::assertion());
                    }
                    continue;
                }

                if let Ok(candidate_name) = ServerName::try_from(name.as_str()) {
                    if self
                        .verifier
                        .verify_server_cert(
                            end_entity,
                            intermediates,
                            &candidate_name,
                            ocsp_response,
                            now,
                        )
                        .is_ok()
                    {
                        return Ok(ServerCertVerified::assertion());
                    }
                }
            }

            Err(Error::General("no matching name in certificate".into()))
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            self.verifier.verify_tls12_signature(message, cert, dss)
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            self.verifier.verify_tls13_signature(message, cert, dss)
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.verifier.supported_verify_schemes()
        }
    }
}

// ---------------------------------------------------------------------------
// KeyLog implementation
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct FileKeyLog {
    path: String,
}

impl rustls::KeyLog for FileKeyLog {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            let cr_hex: String = client_random.iter().map(|b| format!("{:02x}", b)).collect();
            let s_hex: String = secret.iter().map(|b| format!("{:02x}", b)).collect();
            let _ = writeln!(f, "{} {} {}", label, cr_hex, s_hex);
        }
    }
}

// ---------------------------------------------------------------------------
// SecretCapture — intercepts base traffic secrets via KeyLog
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub(crate) struct SecretCapture {
    pub(crate) client_secret: Mutex<Vec<u8>>,
    pub(crate) server_secret: Mutex<Vec<u8>>,
    file_log: Option<FileKeyLog>,
}

impl SecretCapture {
    pub(crate) fn new(key_log_path: Option<&str>) -> Self {
        Self {
            client_secret: Mutex::new(Vec::new()),
            server_secret: Mutex::new(Vec::new()),
            file_log: key_log_path.map(|p| FileKeyLog {
                path: p.to_string(),
            }),
        }
    }

    pub(crate) fn take_client_secret(&self) -> Vec<u8> {
        let mut s = self.client_secret.lock().unwrap_or_else(|e| e.into_inner());
        std::mem::take(&mut *s)
    }

    pub(crate) fn take_server_secret(&self) -> Vec<u8> {
        let mut s = self.server_secret.lock().unwrap_or_else(|e| e.into_inner());
        std::mem::take(&mut *s)
    }
}

impl rustls::KeyLog for SecretCapture {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        match label {
            "CLIENT_TRAFFIC_SECRET_0" => {
                if let Ok(mut s) = self.client_secret.lock() {
                    s.zeroize();
                    s.clear();
                    s.extend_from_slice(secret);
                }
            }
            "SERVER_TRAFFIC_SECRET_0" => {
                if let Ok(mut s) = self.server_secret.lock() {
                    s.zeroize();
                    s.clear();
                    s.extend_from_slice(secret);
                }
            }
            _ => {}
        }
        if let Some(ref fl) = self.file_log {
            fl.log(label, client_random, secret);
        }
    }
}

// ---------------------------------------------------------------------------
// poll()-based I/O helpers for non-blocking fd compatibility.
//
// After RestoreNonBlock is called, the socket fd is in O_NONBLOCK mode
// while Rust's RecordReader may still be actively reading. These helpers
// handle EAGAIN by calling poll(2) to wait for readiness, then retrying.
// ---------------------------------------------------------------------------

/// Read exactly `buf.len()` bytes from `fd`, handling EAGAIN via poll(2).
/// Handles EINTR from both read() and poll() (SA_RESTART does not apply to poll on Linux).
fn timeout_deadline(timeout_ms: i64) -> Option<Instant> {
    if timeout_ms < 0 {
        return None;
    }
    Some(Instant::now() + Duration::from_millis(timeout_ms as u64))
}

fn remaining_poll_timeout(deadline: Option<Instant>) -> std::io::Result<i32> {
    let Some(deadline) = deadline else {
        return Ok(-1);
    };
    let now = Instant::now();
    if now >= deadline {
        return Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
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

fn read_exact_with_poll_deadline(
    fd: std::os::unix::io::RawFd,
    buf: &mut [u8],
    deadline: Option<Instant>,
) -> std::io::Result<()> {
    let mut filled = 0;
    while filled < buf.len() {
        let ret = unsafe {
            libc::read(
                fd,
                buf[filled..].as_mut_ptr() as *mut libc::c_void,
                buf.len() - filled,
            )
        };
        if ret > 0 {
            filled += ret as usize;
        } else if ret == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "read_exact_with_poll: unexpected EOF",
            ));
        } else {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                poll_readable(fd, deadline)?;
                continue;
            }
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
    }
    Ok(())
}

fn read_some_with_poll_deadline(
    fd: std::os::unix::io::RawFd,
    buf: &mut [u8],
    deadline: Option<Instant>,
) -> std::io::Result<usize> {
    loop {
        let ret = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if ret > 0 {
            return Ok(ret as usize);
        }
        if ret == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "read_some_with_poll: unexpected EOF",
            ));
        }
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::WouldBlock {
            poll_readable(fd, deadline)?;
            continue;
        }
        if err.kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        return Err(err);
    }
}

fn read_exact_with_poll(fd: std::os::unix::io::RawFd, buf: &mut [u8]) -> std::io::Result<()> {
    read_exact_with_poll_deadline(fd, buf, None)
}

/// Block until `fd` is readable, handling EINTR and edge cases.
fn poll_readable(fd: std::os::unix::io::RawFd, deadline: Option<Instant>) -> std::io::Result<()> {
    loop {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let timeout_ms = remaining_poll_timeout(deadline)?;
        let pret = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
        if pret < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue; // EINTR — retry poll
            }
            return Err(err);
        }
        if pret == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "deferred read poll timeout exceeded",
            ));
        }
        if pfd.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "poll_readable: poll error",
            ));
        }
        // POLLHUP with POLLIN means data available before hangup — let read() drain it.
        // POLLHUP alone (no POLLIN) means peer closed without data.
        if pfd.revents & libc::POLLHUP != 0 && pfd.revents & libc::POLLIN == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "poll_readable: peer hangup",
            ));
        }
        return Ok(());
    }
}

// ---------------------------------------------------------------------------
// RecordReader — reads exactly one TLS record at a time from the socket.
// Prevents rustls from over-reading past the current record boundary,
// which would cause data loss when kTLS takes over the socket.
// ---------------------------------------------------------------------------

pub(crate) struct RecordReader {
    pub(crate) tcp: TcpStream,
    buf: Vec<u8>,
    pos: usize,
    len: usize,
    record_target: usize,
    first_record_hash: Option<[u8; 32]>,
    record_count: usize,
}

impl RecordReader {
    pub(crate) fn new(tcp: TcpStream) -> Self {
        Self {
            tcp,
            buf: Vec::new(),
            pos: 0,
            len: 0,
            record_target: 0,
            first_record_hash: None,
            record_count: 0,
        }
    }

    /// Read exactly one TLS record from the socket into the internal buffer,
    /// then serve it incrementally via the `Read` trait.
    fn fill_record(&mut self) -> std::io::Result<()> {
        fn map_timeout(err: std::io::Error) -> std::io::Error {
            if err.kind() == std::io::ErrorKind::WouldBlock {
                return std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "native TLS handshake timeout",
                );
            }
            err
        }

        // Read 5-byte TLS record header
        let mut header = [0u8; 5];
        self.tcp.read_exact(&mut header).map_err(map_timeout)?;

        let payload_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        if payload_len > 16384 + 256 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("TLS record too large: {}", payload_len),
            ));
        }

        // Assemble full record: header + payload
        self.buf.clear();
        self.buf.reserve(5 + payload_len);
        self.buf.extend_from_slice(&header);
        self.buf.resize(5 + payload_len, 0);
        self.tcp
            .read_exact(&mut self.buf[5..])
            .map_err(map_timeout)?;
        self.pos = 0;
        self.len = 5 + payload_len;
        self.record_target = 0;

        // Capture SHA-256 hash of the first record consumed (for TOCTOU verification)
        if self.record_count == 0 {
            let hash = ring::digest::digest(&ring::digest::SHA256, &self.buf[..self.len]);
            let mut h = [0u8; 32];
            h.copy_from_slice(hash.as_ref());
            self.first_record_hash = Some(h);
        }
        self.record_count += 1;
        Ok(())
    }

    /// Returns the SHA-256 hash of the first TLS record consumed from the socket.
    /// Used to verify that peeked data (MSG_PEEK) matches what was actually consumed.
    pub(crate) fn first_record_hash(&self) -> Option<&[u8; 32]> {
        self.first_record_hash.as_ref()
    }

    /// Read one complete TLS record from the socket and return it as a Vec<u8>.
    /// Drains any leftover buffered bytes from the handshake phase first.
    /// Used by DeferredSession's split-lock read path: socket I/O happens
    /// under the reader lock, then the returned bytes are fed to rustls under
    /// the tls lock via Cursor.
    ///
    /// Uses poll()-based reads to handle EAGAIN after RestoreNonBlock restores
    /// O_NONBLOCK on the fd while this reader is still active.
    pub(crate) fn read_one_record(&mut self) -> std::io::Result<Vec<u8>> {
        self.read_one_record_deadline(None)
    }

    pub(crate) fn read_one_record_deadline(
        &mut self,
        deadline: Option<Instant>,
    ) -> std::io::Result<Vec<u8>> {
        use std::os::unix::io::AsRawFd;

        // Drain leftover buffered bytes from handshake phase
        if self.record_target == 0 && self.pos < self.len {
            let leftover = self.buf[self.pos..self.len].to_vec();
            self.pos = self.len;
            return Ok(leftover);
        }
        let fd = self.tcp.as_raw_fd();
        if self.record_target == 0 {
            self.buf.clear();
            self.buf.resize(5, 0);
            self.pos = 0;
            self.len = 0;
            self.record_target = 5;
        }
        while self.len < self.record_target {
            let n = read_some_with_poll_deadline(
                fd,
                &mut self.buf[self.len..self.record_target],
                deadline,
            )?;
            self.len += n;
            if self.record_target == 5 && self.len == 5 {
                let payload_len = u16::from_be_bytes([self.buf[3], self.buf[4]]) as usize;
                if payload_len > 16384 + 256 {
                    self.buf.clear();
                    self.pos = 0;
                    self.len = 0;
                    self.record_target = 0;
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("TLS record too large: {}", payload_len),
                    ));
                }
                self.buf.resize(5 + payload_len, 0);
                self.record_target = 5 + payload_len;
            }
        }
        let record = self.buf[..self.record_target].to_vec();
        self.buf.clear();
        self.pos = 0;
        self.len = 0;
        self.record_target = 0;
        Ok(record)
    }

    /// Push back unconsumed bytes into the reader's buffer.
    /// Used by DeferredSession's split-lock read path: after `read_tls` from a
    /// Cursor, any bytes the Cursor didn't consume must be pushed back so the
    /// next `read_one_record()` call returns them before reading from the socket.
    pub(crate) fn push_back(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        // Replace buf with the pushback data, positioned at start
        self.buf.clear();
        self.buf.extend_from_slice(data);
        self.pos = 0;
        self.len = data.len();
        self.record_target = 0;
    }

    /// Return bytes already read from the socket but not yet consumed by rustls.
    /// These bytes are required when Vision strips the outer TLS layer.
    pub(crate) fn take_pending_bytes(&mut self) -> Vec<u8> {
        if self.pos >= self.len {
            self.buf.clear();
            self.pos = 0;
            self.len = 0;
            self.record_target = 0;
            return Vec::new();
        }
        let pending = self.buf[self.pos..self.len].to_vec();
        self.buf.clear();
        self.pos = 0;
        self.len = 0;
        self.record_target = 0;
        pending
    }
}

impl Read for RecordReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // If we have buffered data from the current record, serve it
        if self.pos < self.len {
            let n = (self.len - self.pos).min(buf.len());
            buf[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
            self.pos += n;
            return Ok(n);
        }
        // Read the next record from the socket
        self.fill_record()?;
        let n = (self.len - self.pos).min(buf.len());
        buf[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

/// Drain any plaintext rustls buffered internally during the handshake.
/// With RecordReader this should always be empty, but provides defense-in-depth.
pub(crate) fn drain_plaintext<S: rustls::SideData>(
    conn: &mut rustls::ConnectionCommon<S>,
) -> Vec<u8> {
    let mut drained = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match conn.reader().read(&mut buf) {
            Ok(0) => break,
            Ok(n) => drained.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
    }
    drained
}

/// Consume post-handshake TLS records (e.g., NewSessionTicket) from the
/// server before extracting secrets for kTLS installation.
///
/// In TLS 1.3, the server sends NewSessionTicket(s) as encrypted records
/// AFTER the handshake completes. These increment the server's TX sequence
/// counter. The client must consume them so that `dangerous_extract_secrets()`
/// returns the correct RX sequence number for kTLS. Without this, the client
/// installs kTLS RX with seq=0 while the server's kTLS TX starts at seq=1+,
/// causing AEAD authentication failures (EBADMSG/EIO) on every subsequent read.
///
/// Uses a short (200ms) SO_RCVTIMEO to avoid blocking indefinitely if no
/// post-handshake records are pending.
fn consume_post_handshake_records(conn: &mut ClientConnection, reader: &mut RecordReader) {
    // Save the current SO_RCVTIMEO and set a short timeout for draining.
    let fd = {
        use std::os::unix::io::AsRawFd;
        reader.tcp.as_raw_fd()
    };
    let mut old_tv: libc::timeval = unsafe { std::mem::zeroed() };
    let mut old_len = std::mem::size_of::<libc::timeval>() as libc::socklen_t;
    let got_old = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &mut old_tv as *mut _ as *mut std::ffi::c_void,
            &mut old_len,
        )
    } == 0;

    // Set 200ms timeout for post-handshake drain
    let drain_tv = libc::timeval {
        tv_sec: 0,
        tv_usec: 200_000,
    };
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &drain_tv as *const _ as *const std::ffi::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }

    let mut _count = 0u32;
    loop {
        match conn.read_tls(reader) {
            Ok(0) => break,
            Ok(_) => match conn.process_new_packets() {
                Ok(_) => {
                    _count += 1;
                }
                Err(_) => break,
            },
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                break
            }
            Err(_) => break,
        }
    }

    #[cfg(debug_assertions)]
    if _count > 0 {
        eprintln!(
            "consume_post_handshake: drained {} post-handshake record(s)",
            _count
        );
    }

    // Restore original SO_RCVTIMEO
    if got_old {
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &old_tv as *const _ as *const std::ffi::c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Internal handshake logic
// ---------------------------------------------------------------------------

fn build_protocol_versions(
    min: Option<u16>,
    max: Option<u16>,
) -> Result<Vec<&'static rustls::SupportedProtocolVersion>, String> {
    let mut versions = Vec::new();

    let validate = |v: u16, label: &str| match v {
        0x0303 | 0x0304 => Ok(v),
        _ => Err(format!(
            "{label} {:#06x} unsupported (allowed: TLS1.2=0x0303, TLS1.3=0x0304)",
            v
        )),
    };

    let lo = match min {
        Some(v) => validate(v, "min_version")?,
        None => 0x0303, // default TLS 1.2
    };
    let hi = match max {
        Some(v) => validate(v, "max_version")?,
        None => 0x0304, // default TLS 1.3
    };

    if lo > hi {
        return Err(format!(
            "min_version ({:#06x}) is greater than max_version ({:#06x})",
            lo, hi
        ));
    }

    if lo <= 0x0303 && hi >= 0x0303 {
        versions.push(&rustls::version::TLS12);
    }
    if lo <= 0x0304 && hi >= 0x0304 {
        versions.push(&rustls::version::TLS13);
    }

    if versions.is_empty() {
        return Err("no supported TLS versions remain after filtering".into());
    }

    Ok(versions)
}

#[cfg(test)]
mod protocol_version_tests {
    use super::*;

    #[test]
    fn defaults_allow_tls12_and_tls13() {
        let versions = build_protocol_versions(None, None).expect("default versions");
        assert_eq!(
            versions,
            vec![&rustls::version::TLS12, &rustls::version::TLS13]
        );
    }

    #[test]
    fn min_tls13_limits_to_tls13() {
        let versions = build_protocol_versions(Some(0x0304), None).expect("tls13 only");
        assert_eq!(versions, vec![&rustls::version::TLS13]);
    }

    #[test]
    fn rejects_unknown_versions() {
        assert!(build_protocol_versions(Some(0x0302), None).is_err());
        assert!(build_protocol_versions(None, Some(0x0305)).is_err());
    }

    #[test]
    fn rejects_inverted_range() {
        assert!(build_protocol_versions(Some(0x0304), Some(0x0303)).is_err());
    }
}

/// Output of a TLS handshake — replaces the previous 9-element tuple.
pub(crate) struct HandshakeOutput {
    pub tls_version: u16,
    pub tx_secrets: ConnectionTrafficSecrets,
    pub rx_secrets: ConnectionTrafficSecrets,
    pub tx_seq: u64,
    pub rx_seq: u64,
    pub negotiated_alpn: Vec<u8>,
    pub tx_base_secret: Zeroizing<Vec<u8>>,
    pub rx_base_secret: Zeroizing<Vec<u8>>,
    pub drained: Vec<u8>,
}

/// Intermediate result from the server handshake — handshake complete but
/// secrets not yet extracted and kTLS not installed.  Used by both the
/// immediate path (`do_handshake`) and the deferred path.
pub(crate) struct ServerHandshakeCore {
    pub conn: ServerConnection,
    pub capture: Arc<SecretCapture>,
    pub tls_version: u16,
    pub negotiated_alpn: Vec<u8>,
}

/// Perform the server-side TLS handshake core: build ServerConfig, create
/// ServerConnection, drive the handshake.  Returns a live `ServerConnection`
/// without extracting secrets or installing kTLS.
fn do_server_handshake_core(
    pipeline: &mut crate::fdutil::HandshakePipeline,
    cfg: &TlsConfig,
) -> Result<ServerHandshakeCore, String> {
    let versions = build_protocol_versions(cfg.min_version, cfg.max_version)?;
    let provider = cached_provider();

    if cfg.certs.is_empty() {
        return Err("server requires at least one certificate".into());
    }
    let (certs, key) = &cfg.certs[0];
    let mut sc = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&versions)
        .map_err(|e| format!("protocol version: {}", e))?
        .with_no_client_auth()
        .with_single_cert(certs.clone(), key.clone_key())
        .map_err(|e| format!("server cert: {}", e))?;

    if !cfg.alpn_protocols.is_empty() {
        sc.alpn_protocols = cfg.alpn_protocols.clone();
    }
    sc.enable_secret_extraction = true;
    let capture = Arc::new(SecretCapture::new(cfg.key_log_path.as_deref()));
    sc.key_log = capture.clone();

    let mut conn =
        ServerConnection::new(Arc::new(sc)).map_err(|e| format!("server connection: {}", e))?;

    // Drive handshake record-by-record (reader borrows from pipeline)
    drive_handshake!(&mut conn, pipeline.reader_mut()).map_err(|e| format!("handshake: {}", e))?;

    let tls_version = conn
        .protocol_version()
        .map(|v| match v {
            rustls::ProtocolVersion::TLSv1_2 => 0x0303u16,
            rustls::ProtocolVersion::TLSv1_3 => 0x0304u16,
            _ => 0u16,
        })
        .unwrap_or(0);

    let negotiated_alpn: Vec<u8> = conn.alpn_protocol().map(|a| a.to_vec()).unwrap_or_default();

    Ok(ServerHandshakeCore {
        conn,
        capture,
        tls_version,
        negotiated_alpn,
    })
}

/// Perform a server TLS handshake and return a `DeferredSession` that holds the
/// live rustls connection.  kTLS is NOT installed — the caller decides later via
/// `DeferredSession::enable_ktls()` or drops the session (Vision flows).
pub(crate) fn tls_server_handshake_deferred(
    pipeline: crate::fdutil::HandshakePipeline,
    cfg: &TlsConfig,
) -> Result<Box<crate::reality::DeferredSession>, String> {
    let mut pipeline = pipeline;
    let core = do_server_handshake_core(&mut pipeline, cfg)?;

    // Extract SNI from rustls ServerConnection
    let sni = core.conn.server_name().unwrap_or("").to_string();

    // Map negotiated cipher suite to IANA u16
    let cipher_suite = core
        .conn
        .negotiated_cipher_suite()
        .map(|cs| match cs.suite() {
            rustls::CipherSuite::TLS13_AES_128_GCM_SHA256 => 0x1301u16,
            rustls::CipherSuite::TLS13_AES_256_GCM_SHA384 => 0x1302,
            rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 => 0x1303,
            // TLS 1.2 cipher suites (kTLS supports these too)
            _ => 0,
        })
        .unwrap_or(0);

    // Clear handshake timeout for data-transfer phase
    pipeline.clear_handshake_timeout();

    let session = crate::reality::DeferredSession::new(
        core.conn,
        pipeline,
        core.capture,
        cipher_suite,
        core.tls_version,
        core.negotiated_alpn,
        sni,
    )
    .map_err(|e| format!("deferred session init: {}", e))?;
    Ok(Box::new(session))
}

fn do_handshake(
    pipeline: &mut crate::fdutil::HandshakePipeline,
    cfg: &TlsConfig,
) -> Result<HandshakeOutput, String> {
    if cfg.is_server {
        // --- Server path (delegates to shared core) ---
        let core = do_server_handshake_core(pipeline, cfg)?;
        let mut conn = core.conn;
        let capture = core.capture;
        let tls_version = core.tls_version;
        let negotiated_alpn = core.negotiated_alpn;

        // Drain any plaintext rustls buffered (should be empty with RecordReader)
        let drained = drain_plaintext(&mut conn);

        // Reader stays alive in pipeline — dup'd fd NOT closed yet.
        // This ensures kTLS install (by the caller) sees ESTABLISHED state.

        let secrets = conn
            .dangerous_extract_secrets()
            .map_err(|e| format!("extract secrets: {}", e))?;

        let (tx_seq, tx_secrets) = secrets.tx;
        let (rx_seq, rx_secrets) = secrets.rx;

        // Server: TX = server secret, RX = client secret
        let tx_out = capture.take_server_secret();
        let rx_out = capture.take_client_secret();

        Ok(HandshakeOutput {
            tls_version,
            tx_secrets,
            rx_secrets,
            tx_seq,
            rx_seq,
            negotiated_alpn,
            tx_base_secret: Zeroizing::new(tx_out),
            rx_base_secret: Zeroizing::new(rx_out),
            drained,
        })
    } else {
        // --- Client path ---
        let versions = build_protocol_versions(cfg.min_version, cfg.max_version)?;
        let provider = cached_provider();

        let sni: ServerName<'static> = cfg
            .server_name
            .as_deref()
            .unwrap_or("localhost")
            .to_string()
            .try_into()
            .map_err(|_| "invalid server name")?;

        let mut root_store = rustls::RootCertStore::empty();

        // Add custom CAs
        for ca in &cfg.root_cas {
            root_store
                .add(ca.clone())
                .map_err(|e| format!("add CA: {}", e))?;
        }

        // Add system roots
        if cfg.use_system_roots || (cfg.root_cas.is_empty() && !cfg.insecure_skip_verify) {
            let native = rustls_native_certs::load_native_certs();
            for cert in native.certs {
                let _ = root_store.add(cert);
            }
            // Also add webpki roots as fallback
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }

        let builder = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&versions)
            .map_err(|e| format!("protocol version: {}", e))?;

        let mut cc = if cfg.insecure_skip_verify {
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(verifier::AllowInsecure))
                .with_no_client_auth()
        } else if !cfg.verify_names.is_empty() {
            let verify_roots = Arc::new(root_store.clone());
            let webpki_verifier = rustls::client::WebPkiServerVerifier::builder(verify_roots)
                .build()
                .map_err(|e| format!("build verifier: {}", e))?;
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(verifier::VerifyByName {
                    names: cfg.verify_names.clone(),
                    hashes: cfg.pinned_cert_sha256.clone(),
                    verifier: webpki_verifier,
                }))
                .with_no_client_auth()
        } else if !cfg.pinned_cert_sha256.is_empty() {
            let verify_roots = Arc::new(root_store.clone());
            let webpki_verifier = rustls::client::WebPkiServerVerifier::builder(verify_roots)
                .build()
                .map_err(|e| format!("build verifier: {}", e))?;
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(verifier::PinnedCertSha256 {
                    hashes: cfg.pinned_cert_sha256.clone(),
                    verifier: webpki_verifier,
                }))
                .with_no_client_auth()
        } else {
            builder
                .with_root_certificates(root_store)
                .with_no_client_auth()
        };

        if !cfg.alpn_protocols.is_empty() {
            cc.alpn_protocols = cfg.alpn_protocols.clone();
        }
        cc.enable_secret_extraction = true;
        let capture = Arc::new(SecretCapture::new(cfg.key_log_path.as_deref()));
        cc.key_log = capture.clone();

        let mut conn = ClientConnection::new(Arc::new(cc), sni)
            .map_err(|e| format!("client connection: {}", e))?;

        // Drive handshake record-by-record (reader borrows from pipeline)
        drive_handshake!(&mut conn, pipeline.reader_mut())
            .map_err(|e| format!("handshake: {}", e))?;

        // Consume post-handshake records (NewSessionTicket) so that
        // dangerous_extract_secrets() returns the correct RX sequence for kTLS.
        consume_post_handshake_records(&mut conn, pipeline.reader_mut());

        // Drain any plaintext rustls buffered (should be empty with RecordReader)
        let drained = drain_plaintext(&mut conn);

        let tls_version = conn
            .protocol_version()
            .map(|v| match v {
                rustls::ProtocolVersion::TLSv1_2 => 0x0303u16,
                rustls::ProtocolVersion::TLSv1_3 => 0x0304u16,
                _ => 0u16,
            })
            .unwrap_or(0);

        let negotiated_alpn: Vec<u8> = conn.alpn_protocol().map(|a| a.to_vec()).unwrap_or_default();

        // Reader stays alive in pipeline — dup'd fd NOT closed yet.

        let secrets = conn
            .dangerous_extract_secrets()
            .map_err(|e| format!("extract secrets: {}", e))?;

        let (tx_seq, tx_secrets) = secrets.tx;
        let (rx_seq, rx_secrets) = secrets.rx;

        // Client: TX = client secret, RX = server secret
        let tx_out = capture.take_client_secret();
        let rx_out = capture.take_server_secret();

        Ok(HandshakeOutput {
            tls_version,
            tx_secrets,
            rx_secrets,
            tx_seq,
            rx_seq,
            negotiated_alpn,
            tx_base_secret: Zeroizing::new(tx_out),
            rx_base_secret: Zeroizing::new(rx_out),
            drained,
        })
    }
}

// ===========================================================================
// FFI EXPORTS — Config builder
// ===========================================================================

#[no_mangle]
pub extern "C" fn xray_tls_config_new(is_server: bool) -> *mut TlsConfig {
    ffi_catch_ptr!({
        Box::into_raw(Box::new(TlsConfig {
            is_server,
            server_name: None,
            certs: Vec::new(),
            root_cas: Vec::new(),
            use_system_roots: false,
            alpn_protocols: Vec::new(),
            min_version: None,
            max_version: None,
            insecure_skip_verify: false,
            pinned_cert_sha256: Vec::new(),
            verify_names: Vec::new(),
            key_log_path: None,
        }))
    })
}

#[no_mangle]
pub extern "C" fn xray_tls_config_set_server_name(
    cfg: *mut TlsConfig,
    name_ptr: *const u8,
    name_len: usize,
) {
    ffi_catch_void!({
        if cfg.is_null() {
            return;
        }
        let cfg = unsafe { &mut *cfg };
        let name = if name_ptr.is_null() || name_len == 0 {
            &[] as &[u8]
        } else {
            unsafe { std::slice::from_raw_parts(name_ptr, name_len) }
        };
        cfg.server_name = String::from_utf8(name.to_vec()).ok();
    })
}

#[no_mangle]
pub extern "C" fn xray_tls_config_add_cert_pem(
    cfg: *mut TlsConfig,
    cert_ptr: *const u8,
    cert_len: usize,
    key_ptr: *const u8,
    key_len: usize,
) -> i32 {
    ffi_catch_i32!({
        if cfg.is_null() {
            return -1;
        }
        let cfg = unsafe { &mut *cfg };
        if cert_ptr.is_null() || cert_len == 0 || key_ptr.is_null() || key_len == 0 {
            return -1;
        }
        let cert_pem = unsafe { std::slice::from_raw_parts(cert_ptr, cert_len) };
        let key_pem = unsafe { std::slice::from_raw_parts(key_ptr, key_len) };

        let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem)
            .filter_map(|r| r.ok())
            .collect();

        if certs.is_empty() {
            return -1;
        }

        match PrivateKeyDer::from_pem_slice(key_pem) {
            Ok(k) => {
                cfg.certs.push((certs, k));
                0
            }
            Err(_) => -2,
        }
    })
}

#[no_mangle]
pub extern "C" fn xray_tls_config_add_root_ca_pem(
    cfg: *mut TlsConfig,
    ca_ptr: *const u8,
    ca_len: usize,
) -> i32 {
    ffi_catch_i32!({
        if cfg.is_null() {
            return -1;
        }
        let cfg = unsafe { &mut *cfg };
        if ca_ptr.is_null() || ca_len == 0 {
            return -1;
        }
        let ca_pem = unsafe { std::slice::from_raw_parts(ca_ptr, ca_len) };

        let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(ca_pem)
            .filter_map(|r| r.ok())
            .collect();

        if certs.is_empty() {
            return -1;
        }

        cfg.root_cas.extend(certs);
        0
    })
}

#[no_mangle]
pub extern "C" fn xray_tls_config_use_system_roots(cfg: *mut TlsConfig) {
    ffi_catch_void!({
        if cfg.is_null() {
            return;
        }
        let cfg = unsafe { &mut *cfg };
        cfg.use_system_roots = true;
    })
}

#[no_mangle]
pub extern "C" fn xray_tls_config_set_alpn(
    cfg: *mut TlsConfig,
    protos_ptr: *const u8,
    protos_len: usize,
) {
    ffi_catch_void!({
        if cfg.is_null() {
            return;
        }
        let cfg = unsafe { &mut *cfg };
        let data = if protos_ptr.is_null() || protos_len == 0 {
            &[] as &[u8]
        } else {
            unsafe { std::slice::from_raw_parts(protos_ptr, protos_len) }
        };

        // Parse length-prefixed TLS wire format
        cfg.alpn_protocols.clear();
        let mut pos = 0;
        while pos < data.len() {
            let len = data[pos] as usize;
            pos += 1;
            if len == 0 {
                continue;
            }
            if pos + len > data.len() {
                break;
            }
            cfg.alpn_protocols.push(data[pos..pos + len].to_vec());
            pos += len;
        }
    })
}

#[no_mangle]
pub extern "C" fn xray_tls_config_set_versions(cfg: *mut TlsConfig, min: u16, max: u16) {
    ffi_catch_void!({
        if cfg.is_null() {
            return;
        }
        let cfg = unsafe { &mut *cfg };
        cfg.min_version = Some(min);
        cfg.max_version = Some(max);
    })
}

#[no_mangle]
pub extern "C" fn xray_tls_config_set_insecure_skip_verify(cfg: *mut TlsConfig, skip: bool) {
    ffi_catch_void!({
        if cfg.is_null() {
            return;
        }
        let cfg = unsafe { &mut *cfg };
        cfg.insecure_skip_verify = skip;
    })
}

#[no_mangle]
pub extern "C" fn xray_tls_config_pin_cert_sha256(
    cfg: *mut TlsConfig,
    hash_ptr: *const u8,
    hash_len: usize,
) {
    ffi_catch_void!({
        if cfg.is_null() {
            return;
        }
        let cfg = unsafe { &mut *cfg };
        if hash_ptr.is_null() || hash_len == 0 {
            return;
        }
        let hash = unsafe { std::slice::from_raw_parts(hash_ptr, hash_len) };
        cfg.pinned_cert_sha256.push(hash.to_vec());
    })
}

#[no_mangle]
pub extern "C" fn xray_tls_config_add_verify_name(
    cfg: *mut TlsConfig,
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
            cfg.verify_names.push(s);
        }
    })
}

#[no_mangle]
pub extern "C" fn xray_tls_config_set_key_log_path(
    cfg: *mut TlsConfig,
    path_ptr: *const u8,
    path_len: usize,
) {
    ffi_catch_void!({
        if cfg.is_null() {
            return;
        }
        let cfg = unsafe { &mut *cfg };
        let path = if path_ptr.is_null() || path_len == 0 {
            &[] as &[u8]
        } else {
            unsafe { std::slice::from_raw_parts(path_ptr, path_len) }
        };
        cfg.key_log_path = String::from_utf8(path.to_vec()).ok();
    })
}

#[no_mangle]
pub extern "C" fn xray_tls_config_free(cfg: *mut TlsConfig) {
    ffi_catch_void!({
        if !cfg.is_null() {
            let _ = unsafe { Box::from_raw(cfg) };
        }
    })
}

// ===========================================================================
// FFI EXPORTS — Handshake + kTLS
// ===========================================================================

#[no_mangle]
pub extern "C" fn xray_tls_handshake(
    fd: i32,
    cfg: *const TlsConfig,
    is_client: bool,
    handshake_timeout_ms: u32,
    out: *mut XrayTlsResult,
) -> i32 {
    xray_tls_handshake_into(
        fd,
        cfg,
        is_client,
        handshake_timeout_ms,
        out,
        std::ptr::null_mut(),
        0,
    )
}

#[no_mangle]
pub extern "C" fn xray_tls_handshake_into(
    fd: i32,
    cfg: *const TlsConfig,
    _is_client: bool,
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

        let handshake_timeout = handshake_timeout_from_ms(handshake_timeout_ms);

        // Create pipeline (dup + clear O_NONBLOCK + enforce timeout)
        let mut pipeline = match crate::fdutil::HandshakePipeline::new(fd, handshake_timeout) {
            Ok(p) => p,
            Err(e) => {
                out.set_error(1, &format!("pipeline: {}", e));
                return 1;
            }
        };

        // Perform TLS handshake (reader stays alive inside pipeline)
        let output = match do_handshake(&mut pipeline, cfg) {
            Ok(v) => v,
            Err(e) => {
                out.set_error(1, &e);
                return 1;
            }
        };
        let tx_secret = output.tx_base_secret;
        let rx_secret = output.rx_base_secret;

        out.version = output.tls_version;
        out.cipher_suite = cipher_suite_to_u16(&output.tx_secrets);

        // Copy ALPN
        let alpn_len = output.negotiated_alpn.len().min(31);
        out.alpn[..alpn_len].copy_from_slice(&output.negotiated_alpn[..alpn_len]);

        // Install kTLS (dup'd fd still alive — guaranteed by pipeline ownership).
        // Native mode requires full TX/RX kTLS offload because Go will use raw
        // socket I/O via RustConn after handshake.
        let (tx, rx) = match pipeline.install_ktls_and_finish(
            output.tls_version,
            &output.tx_secrets,
            output.tx_seq,
            &output.rx_secrets,
            output.rx_seq,
        ) {
            Ok(r) if r.tx_ok && r.rx_ok => (true, true),
            Ok(r) => {
                let msg = format!(
                    "kTLS requires both TX and RX offload (tx={}, rx={}, tx_err={}, rx_err={})",
                    r.tx_ok,
                    r.rx_ok,
                    r.tx_err.as_deref().unwrap_or("none"),
                    r.rx_err.as_deref().unwrap_or("none"),
                );
                out.set_error(2, &msg);
                return 2;
            }
            Err(e) => {
                out.set_error(2, &e);
                return 2;
            }
        };
        // Pipeline dropped: dup'd fd closed, O_NONBLOCK restored.
        out.ktls_tx = tx;
        out.ktls_rx = rx;
        out.rx_seq_start = output.rx_seq;

        // Create TlsState (metadata only — KeyUpdate is handled on the Go side)
        let state = Box::new(TlsState::new(fd, out.cipher_suite));
        out.state_handle = Box::into_raw(state) as *mut c_void;

        // Copy base traffic secrets for Go-side KeyUpdate handler
        if !tx_secret.is_empty() {
            let len = tx_secret.len().min(48);
            out.tx_secret[..len].copy_from_slice(&tx_secret[..len]);
            out.secret_len = len as u8;
        }
        if !rx_secret.is_empty() {
            let len = rx_secret.len().min(48);
            out.rx_secret[..len].copy_from_slice(&rx_secret[..len]);
        }

        // Forward drained data to Go (Go buffer first, Rust allocation fallback)
        unsafe { write_drained_to_result(out, output.drained, drained_buf, drained_cap) };

        0
    })
}

/// Perform a TLS server handshake via rustls but do NOT install kTLS.
/// Returns a DeferredSession handle via XrayDeferredResult — reuses the same
/// struct and read/write/enable_ktls/free FFI as the REALITY deferred path.
#[no_mangle]
pub extern "C" fn xray_tls_server_deferred(
    fd: i32,
    cfg: *const TlsConfig,
    handshake_timeout_ms: u32,
    out: *mut crate::reality::XrayDeferredResult,
) -> i32 {
    ffi_catch_i32!({
        if out.is_null() {
            return -1;
        }
        if cfg.is_null() {
            let out = unsafe { &mut *out };
            *out = crate::reality::XrayDeferredResult::new();
            out.set_error(-1, "null config pointer");
            return -1;
        }
        let out = unsafe { &mut *out };
        *out = crate::reality::XrayDeferredResult::new();
        let cfg = unsafe { &*cfg };

        let handshake_timeout = handshake_timeout_from_ms(handshake_timeout_ms);

        let pipeline = match crate::fdutil::HandshakePipeline::new(fd, handshake_timeout) {
            Ok(p) => p,
            Err(e) => {
                out.set_error(1, &format!("pipeline: {}", e));
                return 1;
            }
        };

        match tls_server_handshake_deferred(pipeline, cfg) {
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
            Err(msg) => {
                out.set_error(1, &msg);
                1
            }
        }
    })
}

#[no_mangle]
pub extern "C" fn xray_tls_key_update(state: *mut TlsState) -> i32 {
    ffi_catch_i32!({
        if state.is_null() {
            return -1;
        }
        let _state = unsafe { &mut *state };
        // TLS 1.3 KeyUpdate requires re-deriving traffic keys from the
        // current application traffic secret. Native Rust key updates are
        // not implemented yet, so fail explicitly instead of returning
        // success and silently skipping rotation.
        eprintln!("xray_tls_key_update: unsupported — key rotation not implemented");
        -2
    })
}

#[no_mangle]
pub extern "C" fn xray_tls_state_free(state: *mut TlsState) {
    ffi_catch_void!({
        if !state.is_null() {
            let _ = unsafe { Box::from_raw(state) };
        }
    })
}

/// Free a drained-data buffer previously returned in XrayTlsResult.
/// Go calls this after copying the bytes via C.GoBytes().
#[no_mangle]
pub extern "C" fn xray_tls_drained_free(ptr: *mut u8, len: usize) {
    ffi_catch_void!({
        if !ptr.is_null() && len > 0 {
            let drained = unsafe { std::slice::from_raw_parts_mut(ptr, len) };
            drained.zeroize();
            let _ = unsafe { Box::from_raw(drained) };
        }
    })
}

// ===========================================================================
// kTLS Self-Test
//
// Tests kTLS TX/RX at the kernel level, independent of the TLS handshake
// pipeline. Uses a TCP loopback pair with synthetic keys to verify that
// the kernel can correctly encrypt/decrypt AES-128-GCM and AES-256-GCM
// records under TLS 1.3.
//
// Run on the target kernel:
//   cargo test -p xray-rust -- ktls_selftest --nocapture
// ===========================================================================

#[cfg(test)]
mod ktls_selftest {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};

    /// Create a connected TCP pair via loopback.
    fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let client = TcpStream::connect(addr).expect("connect");
        let (server, _) = listener.accept().expect("accept");
        // Disable Nagle so small writes flush immediately
        client.set_nodelay(true).expect("client nodelay");
        server.set_nodelay(true).expect("server nodelay");
        (client, server)
    }

    /// Install ULP "tls" on a socket fd. Returns Ok or Err with errno.
    fn install_ulp(fd: i32) -> std::io::Result<()> {
        let ulp = b"tls\0";
        let ret = unsafe {
            libc::setsockopt(
                fd,
                SOL_TCP,
                TCP_ULP,
                ulp.as_ptr() as *const c_void,
                ulp.len() as libc::socklen_t,
            )
        };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// Install kTLS AES-128-GCM crypto info for one direction.
    fn install_aes128gcm(
        fd: i32,
        direction: i32,
        key: &[u8; 16],
        salt: &[u8; 4],
        iv: &[u8; 8],
        rec_seq: u64,
    ) -> std::io::Result<()> {
        let info = TlsCryptoInfoAesGcm128 {
            version: TLS_1_3_VERSION,
            cipher_type: TLS_CIPHER_AES_GCM_128,
            iv: *iv,
            key: *key,
            salt: *salt,
            rec_seq: rec_seq.to_be_bytes(),
        };
        let ret = unsafe {
            libc::setsockopt(
                fd,
                SOL_TLS,
                direction,
                &info as *const _ as *const c_void,
                std::mem::size_of::<TlsCryptoInfoAesGcm128>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// Install kTLS AES-256-GCM crypto info for one direction.
    fn install_aes256gcm(
        fd: i32,
        direction: i32,
        key: &[u8; 32],
        salt: &[u8; 4],
        iv: &[u8; 8],
        rec_seq: u64,
    ) -> std::io::Result<()> {
        let info = TlsCryptoInfoAesGcm256 {
            version: TLS_1_3_VERSION,
            cipher_type: TLS_CIPHER_AES_GCM_256,
            iv: *iv,
            key: *key,
            salt: *salt,
            rec_seq: rec_seq.to_be_bytes(),
        };
        let ret = unsafe {
            libc::setsockopt(
                fd,
                SOL_TLS,
                direction,
                &info as *const _ as *const c_void,
                std::mem::size_of::<TlsCryptoInfoAesGcm256>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    fn fd_of(s: &TcpStream) -> i32 {
        use std::os::unix::io::AsRawFd;
        s.as_raw_fd()
    }

    // -----------------------------------------------------------------------
    // Test 1: AES-128-GCM, seq=0, basic round-trip
    // -----------------------------------------------------------------------
    #[test]
    fn ktls_aes128gcm_seq0_roundtrip() {
        let (mut a, mut b) = tcp_pair();
        let a_fd = fd_of(&a);
        let b_fd = fd_of(&b);

        // Synthetic key material (all deterministic — fine for a self-test)
        let key: [u8; 16] = [0x01; 16];
        let salt: [u8; 4] = [0xAA, 0xBB, 0xCC, 0xDD];
        let iv: [u8; 8] = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80];

        install_ulp(a_fd).expect("ULP on A");
        install_ulp(b_fd).expect("ULP on B");

        // A TX → B RX (same key material)
        install_aes128gcm(a_fd, TLS_TX, &key, &salt, &iv, 0).expect("TX on A");
        install_aes128gcm(b_fd, TLS_RX, &key, &salt, &iv, 0).expect("RX on B");

        // Write from A, read from B
        let payload = b"Hello kTLS AES-128-GCM seq=0!";
        a.write_all(payload).expect("write A→B");
        a.flush().expect("flush A");

        let mut buf = vec![0u8; 256];
        let n = b.read(&mut buf).expect("read B");
        assert_eq!(&buf[..n], payload, "AES-128-GCM seq=0 round-trip mismatch");
        eprintln!("[PASS] AES-128-GCM seq=0 round-trip: {} bytes", n);
    }

    // -----------------------------------------------------------------------
    // Test 2: AES-128-GCM, seq=1 TX / seq=0 RX (matches production pattern)
    // -----------------------------------------------------------------------
    #[test]
    fn ktls_aes128gcm_seq1tx_seq0rx() {
        let (mut a, mut b) = tcp_pair();
        let a_fd = fd_of(&a);
        let b_fd = fd_of(&b);

        // "Server" key material: TX uses server key, RX uses client key
        let server_key: [u8; 16] = [0x11; 16];
        let server_salt: [u8; 4] = [0xAA, 0xBB, 0xCC, 0xDD];
        let server_iv: [u8; 8] = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80];

        let client_key: [u8; 16] = [0x22; 16];
        let client_salt: [u8; 4] = [0xEE, 0xFF, 0x00, 0x11];
        let client_iv: [u8; 8] = [0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0x01];

        install_ulp(a_fd).expect("ULP on A (server)");
        install_ulp(b_fd).expect("ULP on B (client)");

        // Server socket A: TX=server_key@seq=1, RX=client_key@seq=0
        install_aes128gcm(a_fd, TLS_TX, &server_key, &server_salt, &server_iv, 1)
            .expect("TX on A seq=1");
        install_aes128gcm(a_fd, TLS_RX, &client_key, &client_salt, &client_iv, 0)
            .expect("RX on A seq=0");

        // Client socket B: TX=client_key@seq=0, RX=server_key@seq=1
        install_aes128gcm(b_fd, TLS_TX, &client_key, &client_salt, &client_iv, 0)
            .expect("TX on B seq=0");
        install_aes128gcm(b_fd, TLS_RX, &server_key, &server_salt, &server_iv, 1)
            .expect("RX on B seq=1");

        // Server → Client
        let msg1 = b"Server says hello (tx_seq=1)";
        a.write_all(msg1).expect("write A→B");
        a.flush().expect("flush A");
        let mut buf = vec![0u8; 256];
        let n = b.read(&mut buf).expect("read B (server→client)");
        assert_eq!(&buf[..n], msg1, "server→client mismatch");
        eprintln!("[PASS] Server→Client tx_seq=1: {} bytes", n);

        // Client → Server
        let msg2 = b"Client says hello (tx_seq=0)";
        b.write_all(msg2).expect("write B→A");
        b.flush().expect("flush B");
        let n = a.read(&mut buf).expect("read A (client→server)");
        assert_eq!(&buf[..n], msg2, "client→server mismatch");
        eprintln!("[PASS] Client→Server tx_seq=0: {} bytes", n);

        // Multiple records to test seq increment
        for i in 0..5 {
            let msg = format!("multi-record server→client #{}", i);
            a.write_all(msg.as_bytes()).expect("write multi");
            a.flush().expect("flush multi");
            let n = b.read(&mut buf).expect("read multi");
            assert_eq!(&buf[..n], msg.as_bytes(), "multi-record mismatch at #{}", i);
        }
        eprintln!("[PASS] 5 additional server→client records OK");

        for i in 0..5 {
            let msg = format!("multi-record client→server #{}", i);
            b.write_all(msg.as_bytes()).expect("write multi c→s");
            b.flush().expect("flush multi c→s");
            let n = a.read(&mut buf).expect("read multi c→s");
            assert_eq!(
                &buf[..n],
                msg.as_bytes(),
                "multi-record c→s mismatch at #{}",
                i
            );
        }
        eprintln!("[PASS] 5 additional client→server records OK");
    }

    // -----------------------------------------------------------------------
    // Test 3: AES-256-GCM, seq=0
    // -----------------------------------------------------------------------
    #[test]
    fn ktls_aes256gcm_seq0_roundtrip() {
        let (mut a, mut b) = tcp_pair();
        let a_fd = fd_of(&a);
        let b_fd = fd_of(&b);

        let key: [u8; 32] = [0x42; 32];
        let salt: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];
        let iv: [u8; 8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

        install_ulp(a_fd).expect("ULP on A");
        install_ulp(b_fd).expect("ULP on B");

        install_aes256gcm(a_fd, TLS_TX, &key, &salt, &iv, 0).expect("TX-256 on A");
        install_aes256gcm(b_fd, TLS_RX, &key, &salt, &iv, 0).expect("RX-256 on B");

        let payload = b"Hello kTLS AES-256-GCM seq=0!";
        a.write_all(payload).expect("write A→B");
        a.flush().expect("flush A");

        let mut buf = vec![0u8; 256];
        let n = b.read(&mut buf).expect("read B");
        assert_eq!(&buf[..n], payload, "AES-256-GCM round-trip mismatch");
        eprintln!("[PASS] AES-256-GCM seq=0 round-trip: {} bytes", n);
    }

    // -----------------------------------------------------------------------
    // Test 4: Large payload (multiple MTU-sized writes)
    // -----------------------------------------------------------------------
    #[test]
    fn ktls_aes128gcm_large_payload() {
        let (mut a, mut b) = tcp_pair();
        let a_fd = fd_of(&a);
        let b_fd = fd_of(&b);

        let key: [u8; 16] = [0x55; 16];
        let salt: [u8; 4] = [0x01, 0x02, 0x03, 0x04];
        let iv: [u8; 8] = [0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8];

        install_ulp(a_fd).expect("ULP on A");
        install_ulp(b_fd).expect("ULP on B");

        install_aes128gcm(a_fd, TLS_TX, &key, &salt, &iv, 0).expect("TX on A");
        install_aes128gcm(b_fd, TLS_RX, &key, &salt, &iv, 0).expect("RX on B");

        // 64KB payload — will span multiple TLS records (max record ~16KB)
        let payload: Vec<u8> = (0..65536).map(|i| (i % 251) as u8).collect();

        // Write in a background thread so we don't deadlock
        let payload_clone = payload.clone();
        let writer = std::thread::spawn(move || {
            a.write_all(&payload_clone).expect("write large");
            a.flush().expect("flush large");
            a // return ownership so it doesn't drop
        });

        // Read all bytes
        let mut received = Vec::new();
        let mut buf = [0u8; 8192];
        while received.len() < payload.len() {
            let n = b.read(&mut buf).expect("read large");
            if n == 0 {
                break;
            }
            received.extend_from_slice(&buf[..n]);
        }

        let _a = writer.join().expect("writer thread");
        assert_eq!(
            received.len(),
            payload.len(),
            "large payload length mismatch"
        );
        assert_eq!(received, payload, "large payload content mismatch");
        eprintln!(
            "[PASS] AES-128-GCM large payload: {} bytes OK",
            received.len()
        );
    }

    // -----------------------------------------------------------------------
    // Test 5: Bidirectional simultaneous traffic
    // -----------------------------------------------------------------------
    #[test]
    fn ktls_aes128gcm_bidirectional() {
        let (a, b) = tcp_pair();
        let a_fd = fd_of(&a);
        let b_fd = fd_of(&b);

        let key_ab: [u8; 16] = [0x33; 16];
        let salt_ab: [u8; 4] = [0x01, 0x02, 0x03, 0x04];
        let iv_ab: [u8; 8] = [0x10; 8];

        let key_ba: [u8; 16] = [0x44; 16];
        let salt_ba: [u8; 4] = [0x05, 0x06, 0x07, 0x08];
        let iv_ba: [u8; 8] = [0x20; 8];

        install_ulp(a_fd).expect("ULP A");
        install_ulp(b_fd).expect("ULP B");

        // A→B direction
        install_aes128gcm(a_fd, TLS_TX, &key_ab, &salt_ab, &iv_ab, 0).expect("TX A");
        install_aes128gcm(b_fd, TLS_RX, &key_ab, &salt_ab, &iv_ab, 0).expect("RX B");
        // B→A direction
        install_aes128gcm(b_fd, TLS_TX, &key_ba, &salt_ba, &iv_ba, 0).expect("TX B");
        install_aes128gcm(a_fd, TLS_RX, &key_ba, &salt_ba, &iv_ba, 0).expect("RX A");

        // Simultaneous writes from both sides
        let mut a = a;
        let mut b = b;

        let t1 = std::thread::spawn(move || {
            let msg = b"from A to B via kTLS";
            a.write_all(msg).expect("write a→b");
            a.flush().expect("flush a");
            let mut buf = [0u8; 128];
            let n = a.read(&mut buf).expect("read a←b");
            assert_eq!(&buf[..n], b"from B to A via kTLS", "a←b mismatch");
            eprintln!("[PASS] Bidirectional A side OK");
        });

        let t2 = std::thread::spawn(move || {
            let msg = b"from B to A via kTLS";
            b.write_all(msg).expect("write b→a");
            b.flush().expect("flush b");
            let mut buf = [0u8; 128];
            let n = b.read(&mut buf).expect("read b←a");
            assert_eq!(&buf[..n], b"from A to B via kTLS", "b←a mismatch");
            eprintln!("[PASS] Bidirectional B side OK");
        });

        t1.join().expect("thread A");
        t2.join().expect("thread B");
    }

    // -----------------------------------------------------------------------
    // Test 6: Struct size verification against kernel expectations
    // -----------------------------------------------------------------------
    #[test]
    fn ktls_struct_sizes() {
        // AES-128-GCM: version(2) + cipher_type(2) + iv(8) + key(16) + salt(4) + rec_seq(8) = 40
        assert_eq!(
            std::mem::size_of::<TlsCryptoInfoAesGcm128>(),
            40,
            "AES-128-GCM struct size must be 40"
        );
        // AES-256-GCM: version(2) + cipher_type(2) + iv(8) + key(32) + salt(4) + rec_seq(8) = 56
        assert_eq!(
            std::mem::size_of::<TlsCryptoInfoAesGcm256>(),
            56,
            "AES-256-GCM struct size must be 56"
        );
        // ChaCha20-Poly1305: version(2) + cipher_type(2) + iv(12) + key(32) + rec_seq(8) = 56
        assert_eq!(
            std::mem::size_of::<TlsCryptoInfoChacha20Poly1305>(),
            56,
            "ChaCha20-Poly1305 struct size must be 56"
        );
        eprintln!("[PASS] All kTLS struct sizes correct");
    }

    // -----------------------------------------------------------------------
    // Test 7: dup() pattern — mirrors production REALITY handshake lifecycle
    //
    // This is the critical test: production uses dup(fd), runs TLS handshake
    // through the dup'd fd, installs kTLS on the ORIGINAL fd, then closes
    // the dup'd fd. If there's a kernel regression where close(dup_fd)
    // interferes with kTLS state on the shared socket, this test catches it.
    // -----------------------------------------------------------------------
    #[test]
    fn ktls_dup_fd_lifecycle() {
        let (mut a, mut b) = tcp_pair();
        let a_fd = fd_of(&a);
        let b_fd = fd_of(&b);

        // dup the "server" fd (socket A), mimicking HandshakePipeline::new
        let dup_fd = unsafe { libc::dup(a_fd) };
        assert!(
            dup_fd >= 0,
            "dup failed: {}",
            std::io::Error::last_os_error()
        );

        // Clear O_NONBLOCK on dup_fd (as BlockingGuard does)
        let old_flags = unsafe { libc::fcntl(dup_fd, libc::F_GETFL) };
        if old_flags >= 0 && (old_flags & libc::O_NONBLOCK) != 0 {
            unsafe { libc::fcntl(dup_fd, libc::F_SETFL, old_flags & !libc::O_NONBLOCK) };
        }

        // Simulate: "handshake" writes/reads go through dup_fd
        // (In production, rustls sends ServerHello etc through dup_fd and reads
        //  ClientHello through dup_fd. We'll just send a small payload as a
        //  stand-in, then read it on the other end.)
        let hs_msg = b"fake-handshake-data";
        let written =
            unsafe { libc::write(dup_fd, hs_msg.as_ptr() as *const c_void, hs_msg.len()) };
        assert_eq!(written as usize, hs_msg.len(), "dup_fd write failed");
        let mut hs_buf = [0u8; 64];
        let n = b.read(&mut hs_buf).expect("read handshake from B");
        assert_eq!(&hs_buf[..n], hs_msg);

        // Install kTLS on the ORIGINAL fd (not dup_fd) — just like production
        install_ulp(a_fd).expect("ULP on original fd");
        install_ulp(b_fd).expect("ULP on B");

        let key: [u8; 16] = [0x77; 16];
        let salt: [u8; 4] = [0x11, 0x22, 0x33, 0x44];
        let iv: [u8; 8] = [0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0x01, 0x02];

        install_aes128gcm(a_fd, TLS_TX, &key, &salt, &iv, 1).expect("TX on original fd, seq=1");
        install_aes128gcm(b_fd, TLS_RX, &key, &salt, &iv, 1).expect("RX on B, seq=1");

        // NOW close the dup'd fd — this is the critical step.
        // In production, HandshakePipeline drops RecordReader (which wraps dup_fd),
        // closing it AFTER kTLS is installed on the original fd.
        let rc = unsafe { libc::close(dup_fd) };
        assert_eq!(
            rc,
            0,
            "close(dup_fd) failed: {}",
            std::io::Error::last_os_error()
        );

        // Restore O_NONBLOCK on original fd (as BlockingGuard does)
        if old_flags >= 0 && (old_flags & libc::O_NONBLOCK) != 0 {
            unsafe { libc::fcntl(a_fd, libc::F_SETFL, old_flags) };
        }

        // NOW try to use kTLS on the original fd — this is where EIO shows up in production
        let payload = b"post-handshake kTLS data via original fd";
        a.write_all(payload).expect("write via kTLS on original fd");
        a.flush().expect("flush original fd");

        let mut buf = vec![0u8; 256];
        let n = b.read(&mut buf).expect("read kTLS data on B");
        assert_eq!(&buf[..n], payload, "kTLS data mismatch after dup close");
        eprintln!(
            "[PASS] dup fd lifecycle: kTLS works after close(dup_fd), {} bytes",
            n
        );

        // Multiple records after dup close to verify seq increments correctly
        for i in 0..10 {
            let msg = format!("record #{} after dup close", i);
            a.write_all(msg.as_bytes()).expect("write multi after dup");
            a.flush().expect("flush multi after dup");
            let n = b.read(&mut buf).expect("read multi after dup");
            assert_eq!(&buf[..n], msg.as_bytes(), "multi-record mismatch #{}", i);
        }
        eprintln!("[PASS] 10 additional records after dup close OK");
    }

    // -----------------------------------------------------------------------
    // Test 8: kTLS with data already in TCP receive buffer before install
    //
    // In production, the client's first application data record may arrive
    // in the kernel's TCP receive buffer BEFORE kTLS RX is installed. The
    // kernel must correctly handle this pre-buffered encrypted data.
    // -----------------------------------------------------------------------
    #[test]
    fn ktls_prebuffered_data() {
        let (mut a, mut b) = tcp_pair();
        let a_fd = fd_of(&a);
        let b_fd = fd_of(&b);

        // Install kTLS on A (sender) first
        install_ulp(a_fd).expect("ULP A");
        let key: [u8; 16] = [0x88; 16];
        let salt: [u8; 4] = [0x55, 0x66, 0x77, 0x88];
        let iv: [u8; 8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        install_aes128gcm(a_fd, TLS_TX, &key, &salt, &iv, 0).expect("TX A");

        // Send data through kTLS TX BEFORE installing kTLS RX on B.
        // This encrypted record sits in B's TCP receive buffer.
        let payload = b"pre-buffered encrypted record";
        a.write_all(payload).expect("write pre-buffer");
        a.flush().expect("flush pre-buffer");

        // Small delay to ensure data arrives at B
        std::thread::sleep(std::time::Duration::from_millis(50));

        // NOW install kTLS RX on B — with data already in the buffer
        install_ulp(b_fd).expect("ULP B");
        install_aes128gcm(b_fd, TLS_RX, &key, &salt, &iv, 0).expect("RX B");

        // Read should still work — kernel should decrypt the buffered record
        let mut buf = vec![0u8; 256];
        let n = b.read(&mut buf).expect("read pre-buffered data");
        assert_eq!(&buf[..n], payload, "pre-buffered data mismatch");
        eprintln!("[PASS] Pre-buffered kTLS data: {} bytes", n);
    }

    // =======================================================================
    // Integration Tests — Real TLS handshake → kTLS takeover
    //
    // These tests reproduce the exact production flow:
    //   1. Generate a self-signed certificate
    //   2. Perform a real TLS 1.3 handshake via rustls
    //   3. Extract traffic secrets with dangerous_extract_secrets()
    //   4. Install kTLS using the extracted secrets
    //   5. Send/receive multiple records through kTLS
    //
    // If these fail on a specific kernel but the synthetic-key tests pass,
    // the bug is in the handshake-to-kTLS transition, not kTLS itself.
    // =======================================================================

    /// Generate a self-signed certificate and private key for testing.
    fn generate_test_cert() -> (
        Vec<rustls::pki_types::CertificateDer<'static>>,
        rustls::pki_types::PrivateKeyDer<'static>,
    ) {
        let key_pair = rcgen::KeyPair::generate().expect("generate key pair");
        let params =
            rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("cert params");
        let cert = params.self_signed(&key_pair).expect("self-signed cert");
        let cert_der = rustls::pki_types::CertificateDer::from(cert.der().to_vec());
        let key_der = rustls::pki_types::PrivateKeyDer::try_from(key_pair.serialize_der())
            .expect("parse private key DER");
        (vec![cert_der], key_der)
    }

    /// Run a TLS 1.3 handshake on a TCP pair using the dup'd-fd + RecordReader
    /// pattern (identical to production), extract secrets, install kTLS.
    /// Returns the raw TCP streams with kTLS active on both sides.
    fn handshake_and_install_ktls(
        server_tcp: TcpStream,
        client_tcp: TcpStream,
    ) -> (TcpStream, TcpStream, u16, u64, u64, u64, u64) {
        use rustls::pki_types::ServerName;
        use rustls::{ClientConfig, ClientConnection, ServerConfig, ServerConnection};
        use std::os::unix::io::{AsRawFd, FromRawFd};

        let (certs, key) = generate_test_cert();
        let provider = cached_provider();

        // --- Build server config ---
        let mut sc = ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("server protocol versions")
            .with_no_client_auth()
            .with_single_cert(certs.clone(), key)
            .expect("server cert");
        sc.enable_secret_extraction = true;

        // --- Build client config ---
        let mut cc = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("client protocol versions")
            .dangerous()
            .with_custom_certificate_verifier(std::sync::Arc::new(super::verifier::AllowInsecure))
            .with_no_client_auth();
        cc.enable_secret_extraction = true;

        let sni: ServerName<'static> = "localhost".to_string().try_into().unwrap();
        let mut server_conn = ServerConnection::new(std::sync::Arc::new(sc)).expect("server conn");
        let mut client_conn =
            ClientConnection::new(std::sync::Arc::new(cc), sni).expect("client conn");

        let server_fd = server_tcp.as_raw_fd();
        let client_fd = client_tcp.as_raw_fd();

        // --- dup + RecordReader for server side (mirrors HandshakePipeline) ---
        let server_dup_fd = unsafe { libc::dup(server_fd) };
        assert!(server_dup_fd >= 0, "dup server failed");
        // Clear O_NONBLOCK on dup (as BlockingGuard does)
        let server_old_flags = unsafe { libc::fcntl(server_dup_fd, libc::F_GETFL) };
        if server_old_flags >= 0 && (server_old_flags & libc::O_NONBLOCK) != 0 {
            unsafe {
                libc::fcntl(
                    server_dup_fd,
                    libc::F_SETFL,
                    server_old_flags & !libc::O_NONBLOCK,
                )
            };
        }
        let server_dup_tcp = unsafe { TcpStream::from_raw_fd(server_dup_fd) };
        let mut server_reader = RecordReader::new(server_dup_tcp);

        // --- dup + RecordReader for client side ---
        let client_dup_fd = unsafe { libc::dup(client_fd) };
        assert!(client_dup_fd >= 0, "dup client failed");
        let client_old_flags = unsafe { libc::fcntl(client_dup_fd, libc::F_GETFL) };
        if client_old_flags >= 0 && (client_old_flags & libc::O_NONBLOCK) != 0 {
            unsafe {
                libc::fcntl(
                    client_dup_fd,
                    libc::F_SETFL,
                    client_old_flags & !libc::O_NONBLOCK,
                )
            };
        }
        let client_dup_tcp = unsafe { TcpStream::from_raw_fd(client_dup_fd) };
        let mut client_reader = RecordReader::new(client_dup_tcp);

        // --- Drive handshake for both sides concurrently ---
        // Run client in a thread, server inline
        let client_handle = std::thread::spawn(move || {
            // Drive client handshake
            loop {
                while client_conn.wants_write() {
                    client_conn
                        .write_tls(&mut client_reader.tcp)
                        .expect("client write_tls");
                }
                client_reader.tcp.flush().expect("client flush");
                if !client_conn.is_handshaking() {
                    break;
                }
                if client_conn.wants_read() {
                    client_conn
                        .read_tls(&mut client_reader)
                        .expect("client read_tls");
                    client_conn.process_new_packets().expect("client process");
                }
            }
            // Final flush
            while client_conn.wants_write() {
                client_conn
                    .write_tls(&mut client_reader.tcp)
                    .expect("client final write_tls");
            }
            client_reader.tcp.flush().expect("client final flush");

            // CRITICAL: Read the server's NewSessionTicket record(s).
            // The server sends NST after the handshake completes, so the
            // client's handshake loop exits before these arrive. We must
            // consume them so that dangerous_extract_secrets() returns the
            // correct rx_seq for kTLS installation.
            //
            // Set a short read timeout so we don't block forever waiting
            // for records that may not come.
            client_reader
                .tcp
                .set_read_timeout(Some(std::time::Duration::from_millis(200)))
                .expect("set client read timeout");
            loop {
                match client_conn.read_tls(&mut client_reader) {
                    Ok(0) => break,
                    Ok(_) => {
                        client_conn
                            .process_new_packets()
                            .expect("client process post-hs");
                        eprintln!("Client: consumed post-handshake record");
                    }
                    Err(e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        break
                    }
                    Err(e) => panic!("client post-handshake read: {}", e),
                }
            }
            // Restore no-timeout
            client_reader
                .tcp
                .set_read_timeout(None)
                .expect("clear client read timeout");

            // Drain any buffered plaintext
            let drained = drain_plaintext(&mut client_conn);

            let secrets = client_conn
                .dangerous_extract_secrets()
                .expect("client extract secrets");
            (client_reader, secrets, drained)
        });

        // Drive server handshake
        loop {
            while server_conn.wants_write() {
                server_conn
                    .write_tls(&mut server_reader.tcp)
                    .expect("server write_tls");
            }
            server_reader.tcp.flush().expect("server flush");
            if !server_conn.is_handshaking() {
                break;
            }
            if server_conn.wants_read() {
                server_conn
                    .read_tls(&mut server_reader)
                    .expect("server read_tls");
                server_conn.process_new_packets().expect("server process");
            }
        }
        // Final flush
        while server_conn.wants_write() {
            server_conn
                .write_tls(&mut server_reader.tcp)
                .expect("server final write_tls");
        }
        server_reader.tcp.flush().expect("server final flush");

        // Drain any buffered plaintext
        let server_drained = drain_plaintext(&mut server_conn);

        let server_secrets = server_conn
            .dangerous_extract_secrets()
            .expect("server extract secrets");
        let (server_tx_seq, server_tx_secrets) = server_secrets.tx;
        let (server_rx_seq, server_rx_secrets) = server_secrets.rx;

        let server_cipher = cipher_suite_to_u16(&server_tx_secrets);
        eprintln!(
            "Server: cipher=0x{:04x} tx_seq={} rx_seq={} drained={} bytes",
            server_cipher,
            server_tx_seq,
            server_rx_seq,
            server_drained.len()
        );

        // Install kTLS on server's ORIGINAL fd
        setup_ulp(server_fd).expect("server ULP");
        install_ktls(server_fd, TLS_TX, 0x0304, &server_tx_secrets, server_tx_seq)
            .expect("server kTLS TX");
        install_ktls(server_fd, TLS_RX, 0x0304, &server_rx_secrets, server_rx_seq)
            .expect("server kTLS RX");

        // Close server dup'd fd (RecordReader drops, closing it)
        drop(server_reader);

        // Restore O_NONBLOCK on server original fd
        if server_old_flags >= 0 && (server_old_flags & libc::O_NONBLOCK) != 0 {
            unsafe { libc::fcntl(server_fd, libc::F_SETFL, server_old_flags) };
        }

        // Wait for client handshake
        let (client_reader, client_secrets, client_drained) =
            client_handle.join().expect("client thread");
        let (client_tx_seq, client_tx_secrets) = client_secrets.tx;
        let (client_rx_seq, client_rx_secrets) = client_secrets.rx;

        let client_cipher = cipher_suite_to_u16(&client_tx_secrets);
        eprintln!(
            "Client: cipher=0x{:04x} tx_seq={} rx_seq={} drained={} bytes",
            client_cipher,
            client_tx_seq,
            client_rx_seq,
            client_drained.len()
        );

        // Install kTLS on client's ORIGINAL fd
        setup_ulp(client_fd).expect("client ULP");
        install_ktls(client_fd, TLS_TX, 0x0304, &client_tx_secrets, client_tx_seq)
            .expect("client kTLS TX");
        install_ktls(client_fd, TLS_RX, 0x0304, &client_rx_secrets, client_rx_seq)
            .expect("client kTLS RX");

        // Close client dup'd fd
        drop(client_reader);

        // Restore O_NONBLOCK on client original fd
        if client_old_flags >= 0 && (client_old_flags & libc::O_NONBLOCK) != 0 {
            unsafe { libc::fcntl(client_fd, libc::F_SETFL, client_old_flags) };
        }

        (
            server_tcp,
            client_tcp,
            server_cipher,
            server_tx_seq,
            server_rx_seq,
            client_tx_seq,
            client_rx_seq,
        )
    }

    // -----------------------------------------------------------------------
    // Test 9: Full TLS 1.3 handshake → kTLS → multi-record data transfer
    //
    // This is THE critical integration test. It reproduces the exact
    // production flow: real rustls handshake through dup'd fd with
    // RecordReader, secret extraction, kTLS install on original fd,
    // dup close, then data transfer.
    //
    // If this test fails on a kernel where the synthetic tests pass,
    // the bug is in the handshake-to-kTLS transition.
    // -----------------------------------------------------------------------
    #[test]
    fn ktls_real_handshake_roundtrip() {
        let (server_tcp, client_tcp) = tcp_pair();
        let (mut server, mut client, cipher, srv_tx_seq, srv_rx_seq, cli_tx_seq, cli_rx_seq) =
            handshake_and_install_ktls(server_tcp, client_tcp);

        eprintln!(
            "kTLS active: cipher=0x{:04x} server(tx={},rx={}) client(tx={},rx={})",
            cipher, srv_tx_seq, srv_rx_seq, cli_tx_seq, cli_rx_seq
        );

        // --- Server → Client: single record ---
        let msg1 = b"Hello from server via kTLS after real TLS handshake!";
        server.write_all(msg1).expect("server write");
        server.flush().expect("server flush");
        let mut buf = vec![0u8; 256];
        let n = client.read(&mut buf).expect("client read");
        assert_eq!(&buf[..n], msg1, "server→client mismatch");
        eprintln!("[PASS] Server→Client single record: {} bytes", n);

        // --- Client → Server: single record ---
        let msg2 = b"Hello from client via kTLS after real TLS handshake!";
        client.write_all(msg2).expect("client write");
        client.flush().expect("client flush");
        let n = server.read(&mut buf).expect("server read");
        assert_eq!(&buf[..n], msg2, "client→server mismatch");
        eprintln!("[PASS] Client→Server single record: {} bytes", n);

        // --- Multiple records server → client ---
        for i in 0..20 {
            let msg = format!("server→client record #{} (post-handshake kTLS)", i);
            server.write_all(msg.as_bytes()).expect("write multi s→c");
            server.flush().expect("flush multi s→c");
            let n = client.read(&mut buf).expect("read multi s→c");
            assert_eq!(&buf[..n], msg.as_bytes(), "s→c multi mismatch #{}", i);
        }
        eprintln!("[PASS] 20 server→client records OK");

        // --- Multiple records client → server ---
        for i in 0..20 {
            let msg = format!("client→server record #{} (post-handshake kTLS)", i);
            client.write_all(msg.as_bytes()).expect("write multi c→s");
            client.flush().expect("flush multi c→s");
            let n = server.read(&mut buf).expect("read multi c→s");
            assert_eq!(&buf[..n], msg.as_bytes(), "c→s multi mismatch #{}", i);
        }
        eprintln!("[PASS] 20 client→server records OK");

        eprintln!("[PASS] Full TLS 1.3 handshake → kTLS integration test PASSED");
    }

    // -----------------------------------------------------------------------
    // Test 10: Real handshake → kTLS with large payload (multi-record TLS)
    //
    // Sends 128KB through kTLS after a real handshake — the payload spans
    // multiple TLS records (~8 records at 16KB max). This catches any
    // sequence number tracking bugs that only manifest after several records.
    // -----------------------------------------------------------------------
    #[test]
    fn ktls_real_handshake_large_payload() {
        let (server_tcp, client_tcp) = tcp_pair();
        let (mut server, mut client, cipher, ..) =
            handshake_and_install_ktls(server_tcp, client_tcp);

        eprintln!("Large payload test: cipher=0x{:04x}", cipher);

        // 128KB payload — will be split into ~8 TLS records
        let payload: Vec<u8> = (0u32..131072).map(|i| (i % 251) as u8).collect();

        // Write in background thread to avoid deadlock
        let payload_clone = payload.clone();
        let writer = std::thread::spawn(move || {
            server
                .write_all(&payload_clone)
                .expect("write large payload");
            server.flush().expect("flush large");
            server
        });

        // Read all bytes
        let mut received = Vec::with_capacity(payload.len());
        let mut buf = [0u8; 8192];
        while received.len() < payload.len() {
            let n = client.read(&mut buf).expect("read large payload");
            if n == 0 {
                break;
            }
            received.extend_from_slice(&buf[..n]);
        }

        let _server = writer.join().expect("writer thread");
        assert_eq!(
            received.len(),
            payload.len(),
            "large payload length mismatch"
        );
        assert_eq!(received, payload, "large payload content mismatch");
        eprintln!(
            "[PASS] 128KB payload after real handshake: {} bytes OK",
            received.len()
        );
    }

    // -----------------------------------------------------------------------
    // Test 11: Real handshake → kTLS with server NewSessionTicket
    //
    // By default rustls sends NewSessionTicket(s) after the handshake.
    // These are application-data records sent by the server BEFORE any
    // actual application data. The server tx_seq reflects these records.
    // This test explicitly verifies that the tx_seq from
    // dangerous_extract_secrets() is correctly passed to kTLS.
    // -----------------------------------------------------------------------
    #[test]
    fn ktls_real_handshake_verify_seq() {
        let (server_tcp, client_tcp) = tcp_pair();
        let (_server, _client, cipher, srv_tx_seq, srv_rx_seq, cli_tx_seq, cli_rx_seq) =
            handshake_and_install_ktls(server_tcp, client_tcp);

        eprintln!("Sequence numbers after handshake: cipher=0x{:04x}", cipher);
        eprintln!("  Server: tx_seq={}, rx_seq={}", srv_tx_seq, srv_rx_seq);
        eprintln!("  Client: tx_seq={}, rx_seq={}", cli_tx_seq, cli_rx_seq);

        // TLS 1.3: server sends NewSessionTicket(s) after handshake,
        // so server tx_seq >= 1. Client tx_seq should be 0 (no app data sent yet).
        // Client rx_seq should match server tx_seq (client received the NST records).
        assert!(
            srv_tx_seq >= 1,
            "Expected server tx_seq >= 1 (NewSessionTicket), got {}",
            srv_tx_seq
        );
        assert_eq!(
            cli_tx_seq, 0,
            "Expected client tx_seq = 0, got {}",
            cli_tx_seq
        );
        // server's tx_seq should equal client's rx_seq (they see the same records)
        assert_eq!(
            srv_tx_seq, cli_rx_seq,
            "server tx_seq ({}) should match client rx_seq ({})",
            srv_tx_seq, cli_rx_seq
        );
        // client's tx_seq should equal server's rx_seq
        assert_eq!(
            cli_tx_seq, srv_rx_seq,
            "client tx_seq ({}) should match server rx_seq ({})",
            cli_tx_seq, srv_rx_seq
        );
        eprintln!(
            "[PASS] Sequence numbers verified: server_tx={} client_rx={}",
            srv_tx_seq, cli_rx_seq
        );
    }

    #[test]
    fn test_read_exact_with_poll_basic() {
        // Test read_exact_with_poll on a Unix socket pair
        use std::os::unix::io::AsRawFd;
        let (reader, writer) = std::os::unix::net::UnixStream::pair().unwrap();
        let data = b"test data for read_exact_with_poll";
        let mut w = writer;
        std::io::Write::write_all(&mut w, data).unwrap();

        let fd = reader.as_raw_fd();
        let mut buf = vec![0u8; data.len()];
        read_exact_with_poll(fd, &mut buf).unwrap();
        assert_eq!(&buf, data);
    }

    #[test]
    fn test_read_exact_with_poll_nonblocking_fd() {
        // Verify read_exact_with_poll works on a non-blocking fd
        use std::os::unix::io::AsRawFd;
        let (reader, writer) = std::os::unix::net::UnixStream::pair().unwrap();
        reader.set_nonblocking(true).unwrap();

        let data = b"nonblocking read test";
        let fd_r = reader.as_raw_fd();

        // Write in a separate thread to exercise the poll path
        let handle = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(10));
            let mut w = writer;
            std::io::Write::write_all(&mut w, data).unwrap();
        });

        let mut buf = vec![0u8; data.len()];
        read_exact_with_poll(fd_r, &mut buf).unwrap();
        assert_eq!(&buf, &data[..]);
        handle.join().unwrap();
    }

    #[test]
    fn test_read_exact_with_poll_deadline_times_out() {
        use std::os::unix::io::AsRawFd;

        let (reader, _writer) = std::os::unix::net::UnixStream::pair().unwrap();
        reader.set_nonblocking(true).unwrap();

        let fd = reader.as_raw_fd();
        let mut buf = [0u8; 1];
        let start = Instant::now();
        let err = read_exact_with_poll_deadline(
            fd,
            &mut buf,
            Some(Instant::now() + Duration::from_millis(20)),
        )
        .unwrap_err();

        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        assert!(
            start.elapsed() >= Duration::from_millis(15),
            "timeout fired too early: {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn test_record_reader_deadline_preserves_partial_record() {
        use std::io::Write;
        use std::net::{TcpListener, TcpStream};

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let client = std::thread::spawn(move || TcpStream::connect(addr).unwrap());
        let (reader_stream, _) = listener.accept().unwrap();
        let mut writer = client.join().unwrap();
        reader_stream.set_nonblocking(true).unwrap();

        let mut reader = RecordReader::new(reader_stream);
        let record = [0x17u8, 0x03, 0x03, 0x00, 0x03, 0xAA, 0xBB, 0xCC];

        writer.write_all(&record[..2]).unwrap();

        let err = reader
            .read_one_record_deadline(Some(Instant::now() + Duration::from_millis(20)))
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);

        writer.write_all(&record[2..]).unwrap();

        let got = reader
            .read_one_record_deadline(Some(Instant::now() + Duration::from_millis(200)))
            .unwrap();
        assert_eq!(got, record);
    }
}
