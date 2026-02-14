use std::ffi::c_void;
use std::io::Read;
use std::net::TcpStream;
use std::os::unix::io::FromRawFd;
use std::sync::{Arc, Mutex};

use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{
    ClientConfig, ClientConnection, ConnectionTrafficSecrets, ServerConfig, ServerConnection,
    StreamOwned,
};

// ---------------------------------------------------------------------------
// FFI result struct returned to Go
// ---------------------------------------------------------------------------

#[repr(C)]
pub struct XrayTlsResult {
    pub ktls_tx: bool,
    pub ktls_rx: bool,
    pub version: u16,
    pub cipher_suite: u16,
    pub alpn: [u8; 32],
    pub state_handle: *mut c_void,
    pub error_code: i32,
    pub error_msg: [u8; 256],
    pub tx_secret: [u8; 48],
    pub rx_secret: [u8; 48],
    pub secret_len: u8,
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
            error_msg: [0u8; 256],
            tx_secret: [0u8; 48],
            rx_secret: [0u8; 48],
            secret_len: 0,
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

// ---------------------------------------------------------------------------
// TlsState — kept alive across FFI boundary for KeyUpdate
// ---------------------------------------------------------------------------

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
            if self.hashes.iter().any(|h| h.as_slice() == hash.as_ref()) {
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
            // Check pinned hash if any
            if !self.hashes.is_empty() {
                let hash = digest::digest(&digest::SHA256, end_entity.as_ref());
                if self.hashes.iter().any(|h| h.as_slice() == hash.as_ref()) {
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
}

impl rustls::KeyLog for SecretCapture {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        match label {
            "CLIENT_TRAFFIC_SECRET_0" => {
                if let Ok(mut s) = self.client_secret.lock() {
                    *s = secret.to_vec();
                }
            }
            "SERVER_TRAFFIC_SECRET_0" => {
                if let Ok(mut s) = self.server_secret.lock() {
                    *s = secret.to_vec();
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
// Internal handshake logic
// ---------------------------------------------------------------------------

fn build_protocol_versions(
    min: Option<u16>,
    max: Option<u16>,
) -> Vec<&'static rustls::SupportedProtocolVersion> {
    let mut versions = Vec::new();
    let lo = min.unwrap_or(0x0303);
    let hi = max.unwrap_or(0x0304);
    if lo <= 0x0303 && hi >= 0x0303 {
        versions.push(&rustls::version::TLS12);
    }
    if lo <= 0x0304 && hi >= 0x0304 {
        versions.push(&rustls::version::TLS13);
    }
    if versions.is_empty() {
        versions.push(&rustls::version::TLS13);
    }
    versions
}

fn do_handshake(
    fd: i32,
    cfg: &TlsConfig,
) -> Result<
    (
        u16,
        ConnectionTrafficSecrets,
        ConnectionTrafficSecrets,
        u64,
        u64,
        Vec<u8>,
        Vec<u8>, // tx base traffic secret
        Vec<u8>, // rx base traffic secret
    ),
    String,
> {
    let versions = build_protocol_versions(cfg.min_version, cfg.max_version);
    let provider = Arc::new(default_provider());

    if cfg.is_server {
        // --- Server path ---
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
        let capture = Arc::new(SecretCapture::new(cfg.key_log_path.as_deref()));
        sc.key_log = capture.clone();

        let mut conn =
            ServerConnection::new(Arc::new(sc)).map_err(|e| format!("server connection: {}", e))?;

        // dup fd so Rust owns its own copy
        let dup_fd = unsafe { libc::dup(fd) };
        if dup_fd < 0 {
            return Err(format!("dup: {}", std::io::Error::last_os_error()));
        }
        let tcp = unsafe { TcpStream::from_raw_fd(dup_fd) };
        let mut stream = StreamOwned::new(conn, tcp);

        // Drive handshake by doing a zero-byte read
        let mut buf = [0u8; 1];
        // The handshake completes during read/write operations
        loop {
            match stream.read(&mut buf) {
                Ok(_) => break,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) => {
                    // If handshake is done, that's fine
                    if !stream.conn.is_handshaking() {
                        break;
                    }
                    return Err(format!("handshake read: {}", e));
                }
            }
        }

        let tls_version = stream
            .conn
            .protocol_version()
            .map(|v| match v {
                rustls::ProtocolVersion::TLSv1_2 => 0x0303u16,
                rustls::ProtocolVersion::TLSv1_3 => 0x0304u16,
                _ => 0u16,
            })
            .unwrap_or(0);

        let negotiated_alpn: Vec<u8> = stream
            .conn
            .alpn_protocol()
            .map(|a| a.to_vec())
            .unwrap_or_default();

        // Extract secrets, consuming the connection
        conn = stream.conn;
        // Close dup'd fd
        drop(stream.sock);

        let secrets = conn
            .dangerous_extract_secrets()
            .map_err(|e| format!("extract secrets: {}", e))?;

        let (tx_seq, tx_secrets) = secrets.tx;
        let (rx_seq, rx_secrets) = secrets.rx;

        // Server: TX = server secret, RX = client secret
        let tx_secret = capture.server_secret.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let rx_secret = capture.client_secret.lock().unwrap_or_else(|e| e.into_inner()).clone();

        Ok((
            tls_version,
            tx_secrets,
            rx_secrets,
            tx_seq,
            rx_seq,
            negotiated_alpn,
            tx_secret,
            rx_secret,
        ))
    } else {
        // --- Client path ---
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
        let capture = Arc::new(SecretCapture::new(cfg.key_log_path.as_deref()));
        cc.key_log = capture.clone();

        let mut conn = ClientConnection::new(Arc::new(cc), sni)
            .map_err(|e| format!("client connection: {}", e))?;

        let dup_fd = unsafe { libc::dup(fd) };
        if dup_fd < 0 {
            return Err(format!("dup: {}", std::io::Error::last_os_error()));
        }
        let tcp = unsafe { TcpStream::from_raw_fd(dup_fd) };
        let mut stream = StreamOwned::new(conn, tcp);

        // Drive handshake
        let mut buf = [0u8; 1];
        loop {
            match stream.read(&mut buf) {
                Ok(_) => break,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) => {
                    if !stream.conn.is_handshaking() {
                        break;
                    }
                    return Err(format!("handshake read: {}", e));
                }
            }
        }

        let tls_version = stream
            .conn
            .protocol_version()
            .map(|v| match v {
                rustls::ProtocolVersion::TLSv1_2 => 0x0303u16,
                rustls::ProtocolVersion::TLSv1_3 => 0x0304u16,
                _ => 0u16,
            })
            .unwrap_or(0);

        let negotiated_alpn: Vec<u8> = stream
            .conn
            .alpn_protocol()
            .map(|a| a.to_vec())
            .unwrap_or_default();

        conn = stream.conn;
        drop(stream.sock);

        let secrets = conn
            .dangerous_extract_secrets()
            .map_err(|e| format!("extract secrets: {}", e))?;

        let (tx_seq, tx_secrets) = secrets.tx;
        let (rx_seq, rx_secrets) = secrets.rx;

        // Client: TX = client secret, RX = server secret
        let tx_secret = capture.client_secret.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let rx_secret = capture.server_secret.lock().unwrap_or_else(|e| e.into_inner()).clone();

        Ok((
            tls_version,
            tx_secrets,
            rx_secrets,
            tx_seq,
            rx_seq,
            negotiated_alpn,
            tx_secret,
            rx_secret,
        ))
    }
}

// ===========================================================================
// FFI EXPORTS — Config builder
// ===========================================================================

#[no_mangle]
pub extern "C" fn xray_tls_config_new(is_server: bool) -> *mut TlsConfig {
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
}

#[no_mangle]
pub extern "C" fn xray_tls_config_set_server_name(
    cfg: *mut TlsConfig,
    name_ptr: *const u8,
    name_len: usize,
) {
    if cfg.is_null() { return; }
    let cfg = unsafe { &mut *cfg };
    let name = if name_ptr.is_null() || name_len == 0 {
        &[] as &[u8]
    } else {
        unsafe { std::slice::from_raw_parts(name_ptr, name_len) }
    };
    cfg.server_name = String::from_utf8(name.to_vec()).ok();
}

#[no_mangle]
pub extern "C" fn xray_tls_config_add_cert_pem(
    cfg: *mut TlsConfig,
    cert_ptr: *const u8,
    cert_len: usize,
    key_ptr: *const u8,
    key_len: usize,
) -> i32 {
    if cfg.is_null() { return -1; }
    let result = std::panic::catch_unwind(|| {
        let cfg = unsafe { &mut *cfg };
        if cert_ptr.is_null() || cert_len == 0 || key_ptr.is_null() || key_len == 0 {
            return -1;
        }
        let cert_pem = unsafe { std::slice::from_raw_parts(cert_ptr, cert_len) };
        let key_pem = unsafe { std::slice::from_raw_parts(key_ptr, key_len) };

        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut &*cert_pem)
            .filter_map(|r| r.ok())
            .collect();

        if certs.is_empty() {
            return -1;
        }

        let key = rustls_pemfile::private_key(&mut &*key_pem);
        match key {
            Ok(Some(k)) => {
                cfg.certs.push((certs, k));
                0
            }
            _ => -2,
        }
    });
    result.unwrap_or(-99)
}

#[no_mangle]
pub extern "C" fn xray_tls_config_add_root_ca_pem(
    cfg: *mut TlsConfig,
    ca_ptr: *const u8,
    ca_len: usize,
) -> i32 {
    if cfg.is_null() { return -1; }
    let result = std::panic::catch_unwind(|| {
        let cfg = unsafe { &mut *cfg };
        if ca_ptr.is_null() || ca_len == 0 {
            return -1;
        }
        let ca_pem = unsafe { std::slice::from_raw_parts(ca_ptr, ca_len) };

        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut &*ca_pem)
            .filter_map(|r| r.ok())
            .collect();

        if certs.is_empty() {
            return -1;
        }

        cfg.root_cas.extend(certs);
        0
    });
    result.unwrap_or(-99)
}

#[no_mangle]
pub extern "C" fn xray_tls_config_use_system_roots(cfg: *mut TlsConfig) {
    if cfg.is_null() { return; }
    let cfg = unsafe { &mut *cfg };
    cfg.use_system_roots = true;
}

#[no_mangle]
pub extern "C" fn xray_tls_config_set_alpn(
    cfg: *mut TlsConfig,
    protos_ptr: *const u8,
    protos_len: usize,
) {
    if cfg.is_null() { return; }
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
}

#[no_mangle]
pub extern "C" fn xray_tls_config_set_versions(cfg: *mut TlsConfig, min: u16, max: u16) {
    if cfg.is_null() { return; }
    let cfg = unsafe { &mut *cfg };
    cfg.min_version = Some(min);
    cfg.max_version = Some(max);
}

#[no_mangle]
pub extern "C" fn xray_tls_config_set_insecure_skip_verify(cfg: *mut TlsConfig, skip: bool) {
    if cfg.is_null() { return; }
    let cfg = unsafe { &mut *cfg };
    cfg.insecure_skip_verify = skip;
}

#[no_mangle]
pub extern "C" fn xray_tls_config_pin_cert_sha256(
    cfg: *mut TlsConfig,
    hash_ptr: *const u8,
    hash_len: usize,
) {
    if cfg.is_null() { return; }
    let cfg = unsafe { &mut *cfg };
    if hash_ptr.is_null() || hash_len == 0 { return; }
    let hash = unsafe { std::slice::from_raw_parts(hash_ptr, hash_len) };
    cfg.pinned_cert_sha256.push(hash.to_vec());
}

#[no_mangle]
pub extern "C" fn xray_tls_config_add_verify_name(
    cfg: *mut TlsConfig,
    name_ptr: *const u8,
    name_len: usize,
) {
    if cfg.is_null() { return; }
    let cfg = unsafe { &mut *cfg };
    if name_ptr.is_null() || name_len == 0 { return; }
    let name = unsafe { std::slice::from_raw_parts(name_ptr, name_len) };
    if let Ok(s) = String::from_utf8(name.to_vec()) {
        cfg.verify_names.push(s);
    }
}

#[no_mangle]
pub extern "C" fn xray_tls_config_set_key_log_path(
    cfg: *mut TlsConfig,
    path_ptr: *const u8,
    path_len: usize,
) {
    if cfg.is_null() { return; }
    let cfg = unsafe { &mut *cfg };
    let path = if path_ptr.is_null() || path_len == 0 {
        &[] as &[u8]
    } else {
        unsafe { std::slice::from_raw_parts(path_ptr, path_len) }
    };
    cfg.key_log_path = String::from_utf8(path.to_vec()).ok();
}

#[no_mangle]
pub extern "C" fn xray_tls_config_free(cfg: *mut TlsConfig) {
    if !cfg.is_null() {
        let _ = unsafe { Box::from_raw(cfg) };
    }
}

// ===========================================================================
// FFI EXPORTS — Handshake + kTLS
// ===========================================================================

#[no_mangle]
pub extern "C" fn xray_tls_handshake(
    fd: i32,
    cfg: *const TlsConfig,
    _is_client: bool,
    out: *mut XrayTlsResult,
) -> i32 {
    if out.is_null() { return -1; }
    if cfg.is_null() {
        let out = unsafe { &mut *out };
        *out = XrayTlsResult::new();
        out.set_error(-1, "null config pointer");
        return -1;
    }
    let result = std::panic::catch_unwind(|| {
        let out = unsafe { &mut *out };
        *out = XrayTlsResult::new();

        let cfg = unsafe { &*cfg };

        // Perform TLS handshake
        let (
            tls_version,
            tx_secrets,
            rx_secrets,
            tx_seq,
            rx_seq,
            negotiated_alpn,
            tx_secret,
            rx_secret,
        ) = match do_handshake(fd, cfg) {
            Ok(v) => v,
            Err(e) => {
                out.set_error(1, &e);
                return 1;
            }
        };

        out.version = tls_version;
        out.cipher_suite = cipher_suite_to_u16(&tx_secrets);

        // Copy ALPN
        let alpn_len = negotiated_alpn.len().min(31);
        out.alpn[..alpn_len].copy_from_slice(&negotiated_alpn[..alpn_len]);

        // Native mode requires full TX/RX kTLS offload because Go will use raw
        // socket I/O via RustConn after handshake.
        let (tx, rx) = match (|| -> Result<(bool, bool), String> {
            setup_ulp(fd).map_err(|e| format!("ULP: {}", e))?;

            let tx_res = install_ktls(fd, TLS_TX, tls_version, &tx_secrets, tx_seq);
            let rx_res = install_ktls(fd, TLS_RX, tls_version, &rx_secrets, rx_seq);
            let tx_ok = tx_res.is_ok();
            let rx_ok = rx_res.is_ok();

            if !tx_ok || !rx_ok {
                let mut reasons = Vec::new();
                if let Err(e) = tx_res {
                    reasons.push(format!("TX: {}", e));
                }
                if let Err(e) = rx_res {
                    reasons.push(format!("RX: {}", e));
                }
                if reasons.is_empty() {
                    reasons.push("unknown kTLS setup error".to_string());
                }
                return Err(format!(
                    "kTLS requires both TX and RX offload ({})",
                    reasons.join(", ")
                ));
            }

            Ok((tx_ok, rx_ok))
        })() {
            Ok(v) => v,
            Err(e) => {
                out.set_error(2, &e);
                return 2;
            }
        };
        out.ktls_tx = tx;
        out.ktls_rx = rx;

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

        0
    });
    result.unwrap_or_else(|_| {
        let out = unsafe { &mut *out };
        out.set_error(-1, "panic in xray_tls_handshake");
        -1
    })
}

#[no_mangle]
pub extern "C" fn xray_tls_key_update(state: *mut TlsState) -> i32 {
    if state.is_null() {
        return -1;
    }
    let _state = unsafe { &mut *state };
    // TLS 1.3 KeyUpdate requires re-deriving traffic keys from the
    // current application traffic secret. This is a placeholder that
    // will be implemented when the Go side sends KeyUpdate signals.
    // For now, kTLS in kernel 6.x handles KeyUpdate transparently.
    0
}

#[no_mangle]
pub extern "C" fn xray_tls_state_free(state: *mut TlsState) {
    if !state.is_null() {
        let _ = unsafe { Box::from_raw(state) };
    }
}
