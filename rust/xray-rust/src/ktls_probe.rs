use std::io;

use libc::{c_void, setsockopt, socketpair, AF_UNIX, SOCK_STREAM};

// Minimal TLS 1.2 AES-128-GCM crypto info structure (matches linux/tls.h)
#[repr(C)]
struct tls12_crypto_info_aes_gcm_128 {
    info: tls_crypto_info,
    iv: [u8; 8],
    key: [u8; 16],
    salt: [u8; 4],
    rec_seq: [u8; 8],
}

#[repr(C)]
struct tls_crypto_info {
    version: u16,
    cipher_type: u16,
}

const TLS_1_2_VERSION: u16 = 0x0303;
const TLS_CIPHER_AES_GCM_128: u16 = 51; // TLS_RSA_WITH_AES_128_GCM_SHA256
const TLS_TX: i32 = 1;
const TLS_RX: i32 = 2;
const SOL_TLS: i32 = 282;

fn mk_dummy_info() -> tls12_crypto_info_aes_gcm_128 {
    tls12_crypto_info_aes_gcm_128 {
        info: tls_crypto_info {
            version: TLS_1_2_VERSION,
            cipher_type: TLS_CIPHER_AES_GCM_128,
        },
        iv: [0; 8],
        key: [0; 16],
        salt: [0; 4],
        rec_seq: [0; 8],
    }
}

fn setsockopt_tls(fd: i32, opt: i32) -> io::Result<()> {
    let info = mk_dummy_info();
    let ret = unsafe {
        setsockopt(
            fd,
            SOL_TLS,
            opt,
            &info as *const _ as *const c_void,
            std::mem::size_of::<tls12_crypto_info_aes_gcm_128>() as u32,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Attempts a minimal kTLS install on a UNIX socketpair.
/// Returns true if both TX and RX setsockopt succeed.
pub fn probe_ktls_support() -> bool {
    let mut fds = [0i32; 2];
    let ret = unsafe { socketpair(AF_UNIX, SOCK_STREAM, 0, fds.as_mut_ptr()) };
    if ret != 0 {
        return false;
    }
    let close_pair = || {
        for fd in fds {
            let _ = unsafe { libc::close(fd) };
        }
    };
    // Set a short timeout to avoid blocking on any stray I/O
    for fd in fds {
        let tv = libc::timeval {
            tv_sec: 0,
            tv_usec: 1000, // 1ms
        };
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const _ as *const c_void,
                std::mem::size_of::<libc::timeval>() as u32,
            );
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_SNDTIMEO,
                &tv as *const _ as *const c_void,
                std::mem::size_of::<libc::timeval>() as u32,
            );
        }
    }
    let res = setsockopt_tls(fds[0], TLS_TX)
        .and_then(|_| setsockopt_tls(fds[0], TLS_RX))
        .is_ok();
    close_pair();
    res
}

#[cfg(test)]
mod tests {
    use super::probe_ktls_support;

    #[test]
    fn probe_runs() {
        // Should not panic; may be false on kernels without kTLS.
        let _ = probe_ktls_support();
    }
}
