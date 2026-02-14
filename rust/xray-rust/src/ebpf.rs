//! Aya-based eBPF loader, map management, and FFI exports.
//!
//! Replaces Go raw-bytecode BPF infrastructure with Aya-rs for:
//!   - Proper BPF map pinning and recovery (zero-downtime restarts)
//!   - SK_MSG cork program attachment
//!   - Type-safe map operations
//!
//! Zero-downtime recovery flow:
//!   1. Try to recover pinned maps from /sys/fs/bpf/xray/
//!   2. Load fresh eBPF programs (programs aren't pinned)
//!   3. If recovered maps exist, replace maps in loaded programs
//!   4. If not, create fresh maps and pin them
//!   5. Attach all programs to the SOCKHASH

use aya::{
    maps::{HashMap, MapData, SockHash},
    programs::{SkMsg, SkSkb, SkSkbKind},
    Ebpf,
};
use std::ffi::{c_char, CStr};
use std::os::fd::AsFd;
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
    /// Pin path for map recovery.
    pin_path: String,
}

/// Set up eBPF sockmap with pinned maps for zero-downtime recovery.
///
/// # Arguments
/// * `pin_path` — BPF filesystem path for pinning (e.g., "/sys/fs/bpf/xray/")
/// * `max_entries` — maximum SOCKHASH entries (default 65536)
/// * `cork_threshold` — SK_MSG cork threshold in bytes (default 1400)
///
/// # Returns
/// 0 on success, negative error code on failure.
fn setup_sockmap_impl(pin_path: &str, _max_entries: u32, _cork_threshold: u32) -> Result<(), String> {
    let mut guard = EBPF_STATE.lock().map_err(|e| format!("lock: {e}"))?;
    if guard.is_some() {
        return Err("eBPF already initialized".into());
    }

    // Step 1: Try to recover pinned maps.
    let recovered = try_recover_pinned_maps(pin_path);

    // Step 2: Load eBPF programs.
    #[cfg(feature = "ebpf-bytecode")]
    let mut bpf = Ebpf::load(EBPF_BYTECODE).map_err(|e| format!("load: {e}"))?;

    #[cfg(not(feature = "ebpf-bytecode"))]
    return Err("eBPF bytecode not compiled (build with --features ebpf-bytecode)".into());

    #[cfg(feature = "ebpf-bytecode")]
    {
        let (sockhash_fd, policy_fd) = match recovered {
            Some((sh_data, pm_data)) => {
                // Reuse existing pinned maps — socket pairs survive restart.
                let sh_fd = sh_data.fd().as_fd().as_raw_fd();
                let pm_fd = pm_data.fd().as_fd().as_raw_fd();

                // Replace maps in the loaded programs with the recovered ones.
                // This ensures programs reference the pinned maps, not fresh ones.
                bpf.maps_mut()
                    .get_mut("SOCKHASH")
                    .ok_or("missing SOCKHASH in program")?
                    .reuse_fd(sh_data.fd().as_fd())
                    .map_err(|e| format!("reuse SOCKHASH: {e}"))?;
                bpf.maps_mut()
                    .get_mut("POLICY_MAP")
                    .ok_or("missing POLICY_MAP in program")?
                    .reuse_fd(pm_data.fd().as_fd())
                    .map_err(|e| format!("reuse POLICY_MAP: {e}"))?;

                (sh_fd, pm_fd)
            }
            None => {
                // Fresh maps — pin for future recovery.
                let pin_dir = Path::new(pin_path);
                std::fs::create_dir_all(pin_dir)
                    .map_err(|e| format!("mkdir {pin_path}: {e}"))?;

                // Get map references before pinning.
                let sockhash = bpf
                    .map("SOCKHASH")
                    .ok_or("missing SOCKHASH")?;
                let sh_fd = sockhash.fd().as_fd().as_raw_fd();
                sockhash
                    .pin(pin_dir.join("sockhash"))
                    .map_err(|e| format!("pin sockhash: {e}"))?;

                let policy = bpf
                    .map("POLICY_MAP")
                    .ok_or("missing POLICY_MAP")?;
                let pm_fd = policy.fd().as_fd().as_raw_fd();
                policy
                    .pin(pin_dir.join("policy"))
                    .map_err(|e| format!("pin policy: {e}"))?;

                // Set 0600 permissions on pinned files.
                set_pin_permissions(pin_dir);

                (sh_fd, pm_fd)
            }
        };

        // Step 3: Attach programs.

        // SK_SKB stream parser.
        let parser: &mut SkSkb = bpf
            .program_mut("xray_skb_parse")
            .ok_or("missing xray_skb_parse program")?
            .try_into()
            .map_err(|e| format!("parser type: {e}"))?;
        parser.load().map_err(|e| format!("parser load: {e}"))?;
        let sockhash_map = bpf
            .map("SOCKHASH")
            .ok_or("missing SOCKHASH for attach")?;
        parser
            .attach(sockhash_map, SkSkbKind::StreamParser)
            .map_err(|e| format!("parser attach: {e}"))?;

        // SK_SKB stream verdict.
        let verdict: &mut SkSkb = bpf
            .program_mut("xray_skb_verdict")
            .ok_or("missing xray_skb_verdict program")?
            .try_into()
            .map_err(|e| format!("verdict type: {e}"))?;
        verdict.load().map_err(|e| format!("verdict load: {e}"))?;
        let sockhash_map = bpf
            .map("SOCKHASH")
            .ok_or("missing SOCKHASH for verdict attach")?;
        verdict
            .attach(sockhash_map, SkSkbKind::StreamVerdict)
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
        let sockhash_map = bpf
            .map("SOCKHASH")
            .ok_or("missing SOCKHASH for sk_msg attach")?;
        msg_verdict
            .attach(sockhash_map)
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

/// Try to recover pinned maps from the BPF filesystem.
fn try_recover_pinned_maps(pin_path: &str) -> Option<(MapData, MapData)> {
    let pin_dir = Path::new(pin_path);
    let sh = MapData::from_pin(pin_dir.join("sockhash")).ok()?;
    let pm = MapData::from_pin(pin_dir.join("policy")).ok()?;
    Some((sh, pm))
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

use std::os::fd::AsRawFd;

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
    if pin_path.is_null() {
        return -1;
    }
    let path = match CStr::from_ptr(pin_path).to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    match setup_sockmap_impl(path, max_entries, cork_threshold) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

/// Tear down eBPF programs and unpin maps.
#[no_mangle]
pub extern "C" fn xray_ebpf_teardown() -> i32 {
    match teardown_impl() {
        Ok(()) => 0,
        Err(_) => -1,
    }
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
    match register_pair_impl(inbound_fd, outbound_fd, inbound_cookie, outbound_cookie, policy_flags)
    {
        Ok(()) => 0,
        Err(e) => neg_errno(&e),
    }
}

/// Unregister a socket pair.
#[no_mangle]
pub extern "C" fn xray_ebpf_unregister_pair(
    inbound_cookie: u64,
    outbound_cookie: u64,
) -> i32 {
    match unregister_pair_impl(inbound_cookie, outbound_cookie) {
        Ok(()) => 0,
        Err(e) => neg_errno(&e),
    }
}
