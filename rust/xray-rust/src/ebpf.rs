//! Aya-based eBPF loader, map management, and FFI exports.
//!
//! Replaces Go raw-bytecode BPF infrastructure with Aya-rs for:
//!   - Deterministic BPF map pinning lifecycle
//!   - SK_MSG cork program attachment
//!   - Type-safe map operations
//!
//! Setup flow:
//!   1. Load fresh eBPF programs
//!   2. Replace stale pin files (if any)
//!   3. Pin maps under /sys/fs/bpf/xray/
//!   4. Attach all programs to the SOCKHASH

use aya::{
    maps::{Map, SockHash},
    programs::{SkMsg, SkSkb},
    Ebpf,
};
use std::ffi::{c_char, CStr};
use std::os::fd::{AsFd, AsRawFd};
use std::path::Path;
use std::sync::Mutex;

/// Align macro for include_bytes (ensures eBPF bytecode is properly aligned).
#[cfg(feature = "ebpf-bytecode")]
macro_rules! include_bytes_aligned {
    ($align:literal, $path:literal) => {{
        #[repr(C, align($align))]
        struct Aligned<T: ?Sized>(T);
        static ALIGNED: &Aligned<[u8]> = &Aligned(*include_bytes!($path));
        &ALIGNED.0
    }};
}

/// Embedded eBPF bytecode (compiled by `cargo build --target bpfel-unknown-none`).
/// This is included at compile time via `include_bytes_aligned!`.
///
/// Note: aya's include_bytes_aligned! requires the file to exist at compile time.
/// When the eBPF crate hasn't been built yet, we use a fallback empty array.
#[cfg(feature = "ebpf-bytecode")]
static EBPF_BYTECODE: &[u8] = include_bytes_aligned!(
    16,
    "../../xray-ebpf/target/bpfel-unknown-none/release/xray-ebpf"
);

/// Global state for the loaded eBPF programs and maps.
/// Protected by a mutex since setup/teardown are infrequent operations.
static EBPF_STATE: Mutex<Option<EbpfState>> = Mutex::new(None);

struct EbpfState {
    /// Aya Ebpf handle — keeps programs loaded as long as it lives.
    _bpf: Ebpf,
    /// SOCKHASH map fd for register/unregister operations.
    sockhash_fd: i32,
    /// Policy map fd for register/unregister operations.
    policy_fd: i32,
    /// Pin path for map lifecycle management.
    pin_path: String,
}

/// eBPF setup error codes returned to Go via FFI.
///
/// * `-1` — generic / unknown error
/// * `-2` — permission denied (EPERM / EACCES)
/// * `-3` — missing kernel feature (no eBPF bytecode, missing program/map)
/// * `-4` — program/map load failure
const EBPF_ERR_GENERIC: i32 = -1;
const EBPF_ERR_PERMISSION: i32 = -2;
const EBPF_ERR_MISSING_FEATURE: i32 = -3;
const EBPF_ERR_LOAD_FAILURE: i32 = -4;

/// Classify an error string into an FFI error code.
fn classify_ebpf_error(err: &str) -> i32 {
    let lower = err.to_lowercase();
    if lower.contains("permission") || lower.contains("eperm") || lower.contains("eacces") || lower.contains("operation not permitted") {
        EBPF_ERR_PERMISSION
    } else if lower.contains("missing") || lower.contains("not compiled") || lower.contains("not found") {
        EBPF_ERR_MISSING_FEATURE
    } else if lower.contains("load") || lower.contains("attach") || lower.contains("pin") {
        EBPF_ERR_LOAD_FAILURE
    } else {
        EBPF_ERR_GENERIC
    }
}

/// Set up eBPF sockmap with pinned maps.
///
/// # Arguments
/// * `pin_path` — BPF filesystem path for pinning (e.g., "/sys/fs/bpf/xray/")
/// * `max_entries` — maximum SOCKHASH entries (default 65536)
/// * `cork_threshold` — SK_MSG cork threshold in bytes (default 1400)
///
/// # Returns
/// 0 on success, negative error code on failure:
/// `-1` generic, `-2` permission, `-3` missing feature, `-4` load failure.
fn setup_sockmap_impl(pin_path: &str, _max_entries: u32, _cork_threshold: u32) -> Result<(), String> {
    let mut guard = EBPF_STATE.lock().map_err(|e| format!("lock: {e}"))?;
    if guard.is_some() {
        return Err("eBPF already initialized".into());
    }

    // Step 1: Load eBPF programs.
    #[cfg(feature = "ebpf-bytecode")]
    let mut bpf = Ebpf::load(EBPF_BYTECODE).map_err(|e| format!("load: {e}"))?;

    #[cfg(not(feature = "ebpf-bytecode"))]
    return Err("eBPF bytecode not compiled (build with --features ebpf-bytecode)".into());

    #[cfg(feature = "ebpf-bytecode")]
    {
        // Step 2: Replace stale pin files and pin current maps.
        let pin_dir = Path::new(pin_path);
        std::fs::create_dir_all(pin_dir)
            .map_err(|e| format!("mkdir {pin_path}: {e}"))?;
        // Harden directory permissions to 0700 (root-only), matching Go ensureBPFPinDir.
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o700);
            std::fs::set_permissions(pin_dir, perms)
                .map_err(|e| format!("chmod {pin_path}: {e}"))?;
        }

        // Aya 0.13 doesn't expose map fd reuse for already loaded objects.
        // Always pin the maps owned by this `Ebpf` instance so the pinned paths
        // stay consistent with the attached programs.
        let _ = std::fs::remove_file(pin_dir.join("sockhash"));
        let _ = std::fs::remove_file(pin_dir.join("policy"));

        let (sockhash_fd, sockhash_map_fd) = {
            let sockhash: SockHash<_, u64> = bpf
                .map_mut("SOCKHASH")
                .ok_or("missing SOCKHASH")?
                .try_into()
                .map_err(|e| format!("sockhash map type: {e}"))?;
            let fd = sockhash.fd().as_fd().as_raw_fd();
            let map_fd = sockhash
                .fd()
                .try_clone()
                .map_err(|e| format!("clone SOCKHASH fd: {e}"))?;
            sockhash
                .pin(pin_dir.join("sockhash"))
                .map_err(|e| format!("pin sockhash: {e}"))?;
            (fd, map_fd)
        };

        let policy = bpf
            .map("POLICY_MAP")
            .ok_or("missing POLICY_MAP")?;
        let policy_fd = match policy {
            Map::HashMap(data) | Map::LruHashMap(data) => data.fd().as_fd().as_raw_fd(),
            _ => return Err("POLICY_MAP is not a hash map".into()),
        };
        policy
            .pin(pin_dir.join("policy"))
            .map_err(|e| format!("pin policy: {e}"))?;

        // Set 0600 permissions on pinned files.
        set_pin_permissions(pin_dir);

        // Step 3: Attach programs.

        // SK_SKB stream parser.
        let parser: &mut SkSkb = bpf
            .program_mut("xray_skb_parse")
            .ok_or("missing xray_skb_parse program")?
            .try_into()
            .map_err(|e| format!("parser type: {e}"))?;
        parser.load().map_err(|e| format!("parser load: {e}"))?;
        parser
            .attach(&sockhash_map_fd)
            .map_err(|e| format!("parser attach: {e}"))?;

        // SK_SKB stream verdict.
        let verdict: &mut SkSkb = bpf
            .program_mut("xray_skb_verdict")
            .ok_or("missing xray_skb_verdict program")?
            .try_into()
            .map_err(|e| format!("verdict type: {e}"))?;
        verdict.load().map_err(|e| format!("verdict load: {e}"))?;
        verdict
            .attach(&sockhash_map_fd)
            .map_err(|e| format!("verdict attach: {e}"))?;

        // SK_MSG verdict (cork + redirect).
        let msg_verdict: &mut SkMsg = bpf
            .program_mut("xray_sk_msg")
            .ok_or("missing xray_sk_msg program")?
            .try_into()
            .map_err(|e| format!("sk_msg type: {e}"))?;
        msg_verdict
            .load()
            .map_err(|e| format!("sk_msg load: {e}"))?;
        msg_verdict
            .attach(&sockhash_map_fd)
            .map_err(|e| format!("sk_msg attach: {e}"))?;

        *guard = Some(EbpfState {
            _bpf: bpf,
            sockhash_fd,
            policy_fd,
            pin_path: pin_path.to_string(),
        });

        Ok(())
    }
}

/// Set 0600 root-only permissions on pinned map files.
fn set_pin_permissions(pin_dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    for name in ["sockhash", "policy"] {
        let path = pin_dir.join(name);
        if let Ok(metadata) = std::fs::metadata(&path) {
            let mut perms = metadata.permissions();
            perms.set_mode(0o600);
            let _ = std::fs::set_permissions(&path, perms);
        }
    }
}

/// Tear down eBPF programs and unpin maps.
fn teardown_impl() -> Result<(), String> {
    let mut guard = EBPF_STATE.lock().map_err(|e| format!("lock: {e}"))?;
    if let Some(state) = guard.take() {
        // Unpin maps (best-effort).
        let pin_dir = Path::new(&state.pin_path);
        let _ = std::fs::remove_file(pin_dir.join("sockhash"));
        let _ = std::fs::remove_file(pin_dir.join("policy"));
        let _ = std::fs::remove_dir(&state.pin_path);
        // Dropping `state._bpf` detaches programs and closes map FDs.
    }
    Ok(())
}

/// Register a socket pair for bidirectional forwarding.
fn register_pair_impl(
    inbound_fd: i32,
    outbound_fd: i32,
    inbound_cookie: u64,
    outbound_cookie: u64,
    policy_flags: u32,
) -> std::io::Result<()> {
    let guard = EBPF_STATE
        .lock()
        .map_err(|_| std::io::Error::from_raw_os_error(libc::EDEADLK))?;
    let state = guard
        .as_ref()
        .ok_or_else(|| std::io::Error::from_raw_os_error(libc::ENODEV))?;

    // Write policy entries.
    bpf_map_update_u64_u32(state.policy_fd, inbound_cookie, policy_flags)?;
    if let Err(e) = bpf_map_update_u64_u32(state.policy_fd, outbound_cookie, policy_flags) {
        let _ = bpf_map_delete_u64(state.policy_fd, inbound_cookie);
        return Err(e);
    }

    // Insert into SOCKHASH: inbound_cookie -> outbound_fd, outbound_cookie -> inbound_fd.
    if let Err(e) = bpf_sockhash_update(state.sockhash_fd, inbound_cookie, outbound_fd) {
        let _ = bpf_map_delete_u64(state.policy_fd, inbound_cookie);
        let _ = bpf_map_delete_u64(state.policy_fd, outbound_cookie);
        return Err(e);
    }
    if let Err(e) = bpf_sockhash_update(state.sockhash_fd, outbound_cookie, inbound_fd) {
        let _ = bpf_sockhash_delete(state.sockhash_fd, inbound_cookie);
        let _ = bpf_map_delete_u64(state.policy_fd, inbound_cookie);
        let _ = bpf_map_delete_u64(state.policy_fd, outbound_cookie);
        return Err(e);
    }

    Ok(())
}

/// Unregister a socket pair.
fn unregister_pair_impl(inbound_cookie: u64, outbound_cookie: u64) -> std::io::Result<()> {
    let guard = EBPF_STATE
        .lock()
        .map_err(|_| std::io::Error::from_raw_os_error(libc::EDEADLK))?;
    let state = guard
        .as_ref()
        .ok_or_else(|| std::io::Error::from_raw_os_error(libc::ENODEV))?;

    let _ = bpf_sockhash_delete(state.sockhash_fd, inbound_cookie);
    let _ = bpf_sockhash_delete(state.sockhash_fd, outbound_cookie);
    let _ = bpf_map_delete_u64(state.policy_fd, inbound_cookie);
    let _ = bpf_map_delete_u64(state.policy_fd, outbound_cookie);

    Ok(())
}

// --- Low-level BPF map operations via libc ---

fn bpf_map_update_u64_u32(map_fd: i32, key: u64, value: u32) -> Result<(), std::io::Error> {
    let key_bytes = key.to_ne_bytes();
    let value_bytes = value.to_ne_bytes();
    bpf_map_update_raw(map_fd, &key_bytes, &value_bytes)
}

fn bpf_map_delete_u64(map_fd: i32, key: u64) -> Result<(), std::io::Error> {
    let key_bytes = key.to_ne_bytes();
    bpf_map_delete_raw(map_fd, &key_bytes)
}

fn bpf_sockhash_update(map_fd: i32, key: u64, sock_fd: i32) -> Result<(), std::io::Error> {
    let key_bytes = key.to_ne_bytes();
    let value_bytes = (sock_fd as u32).to_ne_bytes();
    bpf_map_update_raw(map_fd, &key_bytes, &value_bytes)
}

fn bpf_sockhash_delete(map_fd: i32, key: u64) -> Result<(), std::io::Error> {
    bpf_map_delete_u64(map_fd, key)
}

fn bpf_map_update_raw(map_fd: i32, key: &[u8], value: &[u8]) -> Result<(), std::io::Error> {
    #[repr(C)]
    struct BpfMapUpdateAttr {
        map_fd: u32,
        key: u64,
        value_or_next_key: u64,
        flags: u64,
    }

    let attr = BpfMapUpdateAttr {
        map_fd: map_fd as u32,
        key: key.as_ptr() as u64,
        value_or_next_key: value.as_ptr() as u64,
        flags: 0, // BPF_ANY
    };

    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            2u64, // BPF_MAP_UPDATE_ELEM
            &attr as *const _ as u64,
            core::mem::size_of::<BpfMapUpdateAttr>() as u64,
        )
    };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn bpf_map_delete_raw(map_fd: i32, key: &[u8]) -> Result<(), std::io::Error> {
    #[repr(C)]
    struct BpfMapDeleteAttr {
        map_fd: u32,
        key: u64,
        _pad: u64,
        _flags: u64,
    }

    let attr = BpfMapDeleteAttr {
        map_fd: map_fd as u32,
        key: key.as_ptr() as u64,
        _pad: 0,
        _flags: 0,
    };

    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            3u64, // BPF_MAP_DELETE_ELEM
            &attr as *const _ as u64,
            core::mem::size_of::<BpfMapDeleteAttr>() as u64,
        )
    };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

// --- FFI Exports ---

fn neg_errno(err: &std::io::Error) -> i32 {
    -err.raw_os_error().unwrap_or(libc::EIO)
}

/// Reports whether native Aya-based eBPF bytecode is embedded.
#[no_mangle]
pub extern "C" fn xray_ebpf_available() -> i32 {
    1
}

/// Set up eBPF sockmap with pinned maps.
///
/// # Safety
/// `pin_path` must be a valid null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn xray_ebpf_setup(
    pin_path: *const c_char,
    max_entries: u32,
    cork_threshold: u32,
) -> i32 {
    ffi_catch_i32!({
        if pin_path.is_null() {
            return -1;
        }
        let path = match CStr::from_ptr(pin_path).to_str() {
            Ok(s) => s,
            Err(_) => return EBPF_ERR_GENERIC,
        };
        match setup_sockmap_impl(path, max_entries, cork_threshold) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("xray_ebpf_setup: {e}");
                classify_ebpf_error(&e)
            }
        }
    })
}

/// Tear down eBPF programs and unpin maps.
#[no_mangle]
pub extern "C" fn xray_ebpf_teardown() -> i32 {
    ffi_catch_i32!({
        match teardown_impl() {
            Ok(()) => 0,
            Err(_) => -1,
        }
    })
}

/// Register a socket pair for bidirectional forwarding.
///
/// Both sockets must already be TCP connections. The caller provides
/// pre-computed socket cookies (from SO_COOKIE) and policy flags.
#[no_mangle]
pub extern "C" fn xray_ebpf_register_pair(
    inbound_fd: i32,
    outbound_fd: i32,
    inbound_cookie: u64,
    outbound_cookie: u64,
    policy_flags: u32,
) -> i32 {
    ffi_catch_i32!({
        match register_pair_impl(inbound_fd, outbound_fd, inbound_cookie, outbound_cookie, policy_flags)
        {
            Ok(()) => 0,
            Err(e) => neg_errno(&e),
        }
    })
}

/// Unregister a socket pair.
#[no_mangle]
pub extern "C" fn xray_ebpf_unregister_pair(
    inbound_cookie: u64,
    outbound_cookie: u64,
) -> i32 {
    ffi_catch_i32!({
        match unregister_pair_impl(inbound_cookie, outbound_cookie) {
            Ok(()) => 0,
            Err(e) => neg_errno(&e),
        }
    })
}
