#![allow(dead_code)]

#[macro_use]
pub mod ffi;

pub mod aead;
mod blake3_ffi;
#[cfg(feature = "ebpf-bytecode")]
pub mod ebpf;
#[cfg(not(feature = "ebpf-bytecode"))]
#[path = "ebpf_stub.rs"]
pub mod ebpf;
pub mod geodata;
mod geoip;
mod mph;
pub mod reality;
pub mod tls;
/// SAFETY: This module is pub(crate) by design. The TLS 1.3 engine
/// skips CertificateVerify and is ONLY safe under REALITY authentication.
pub(crate) mod tls13;
pub mod vision;
pub mod vmess;
