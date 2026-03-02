//! Type-safe fd lifecycle management for TLS/REALITY handshakes.
//!
//! Both `reality.rs` and `tls.rs` share a common pattern: dup a socket fd,
//! clear O_NONBLOCK for blocking rustls I/O, drive the handshake, install
//! kTLS, then close the dup and restore O_NONBLOCK. This module encodes
//! that lifecycle in Rust's type system so the ordering is enforced at
//! compile time.

use std::net::TcpStream;
use std::os::unix::io::FromRawFd;
use std::time::Duration;

use rustls::ConnectionTrafficSecrets;

use crate::tls;

/// Result of kTLS installation, carrying per-direction error details.
pub(crate) struct KtlsInstallResult {
    pub tx_ok: bool,
    pub rx_ok: bool,
    pub tx_err: Option<String>,
    pub rx_err: Option<String>,
}

/// Clears O_NONBLOCK on a socket fd, restores on drop.
///
/// Go's runtime sets O_NONBLOCK on accepted sockets for its epoll poller.
/// `dup()` shares the file description, so the dup'd fd is also non-blocking.
/// Rustls requires blocking I/O, so we clear it before handshake.
pub(crate) struct BlockingGuard {
    restore_fd: i32,
    old_flags: i32,
    was_nonblock: bool,
}

impl BlockingGuard {
    /// Clear O_NONBLOCK on `clear_fd`, restore on `restore_fd` when dropped.
    ///
    /// `clear_fd` and `restore_fd` may be different fds pointing to the same
    /// file description (via dup). Since fcntl(F_SETFL) operates on the file
    /// description, clearing on either fd affects both. We restore on
    /// `restore_fd` because `clear_fd` may be closed before the guard drops.
    pub fn clear_nonblock(clear_fd: i32, restore_fd: i32) -> Self {
        let old_flags = unsafe { libc::fcntl(clear_fd, libc::F_GETFL) };
        let was_nonblock = old_flags >= 0 && (old_flags & libc::O_NONBLOCK) != 0;
        if was_nonblock {
            unsafe { libc::fcntl(clear_fd, libc::F_SETFL, old_flags & !libc::O_NONBLOCK) };
        }
        Self {
            restore_fd,
            old_flags,
            was_nonblock,
        }
    }

    /// Restore O_NONBLOCK early (before drop). After calling this, drop
    /// becomes a no-op for O_NONBLOCK restoration.
    /// Used by DeferredSession::drain_and_detach() to restore non-blocking
    /// mode BEFORE setting the detached flag visible to other goroutines.
    pub fn restore_nonblock_early(&mut self) {
        if !self.was_nonblock {
            return;
        }
        self.was_nonblock = false;
        let ret = unsafe { libc::fcntl(self.restore_fd, libc::F_SETFL, self.old_flags) };
        if ret < 0 {
            eprintln!(
                "BlockingGuard: early restore O_NONBLOCK failed on fd={}: {}",
                self.restore_fd,
                std::io::Error::last_os_error()
            );
        }
    }
}

impl Drop for BlockingGuard {
    fn drop(&mut self) {
        if self.was_nonblock {
            let ret = unsafe { libc::fcntl(self.restore_fd, libc::F_SETFL, self.old_flags) };
            if ret < 0 {
                eprintln!(
                    "BlockingGuard: fcntl restore O_NONBLOCK failed on fd={}: {}",
                    self.restore_fd,
                    std::io::Error::last_os_error()
                );
            }
        }
    }
}

/// Sets SO_RCVTIMEO/SO_SNDTIMEO during handshake, restores on drop.
///
/// Rust handshakes run on a dup'd fd in blocking mode. Go's `SetDeadline`
/// does not interrupt those blocking reads, so we enforce an explicit socket
/// timeout here and restore the previous values when the pipeline is dropped.
pub(crate) struct SocketTimeoutGuard {
    restore_fd: i32,
    old_recv: libc::timeval,
    old_send: libc::timeval,
    active: bool,
}

impl SocketTimeoutGuard {
    fn get_timeout(fd: i32, optname: i32) -> std::io::Result<libc::timeval> {
        let mut tv: libc::timeval = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::timeval>() as libc::socklen_t;
        let ret = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                optname,
                &mut tv as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(tv)
    }

    fn set_timeout(fd: i32, optname: i32, tv: &libc::timeval) -> std::io::Result<()> {
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                optname,
                tv as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    fn duration_to_timeval(timeout: Duration) -> libc::timeval {
        let secs = timeout.as_secs().min(i64::MAX as u64) as i64;
        let mut usec = timeout.subsec_micros() as i64;
        if secs == 0 && usec == 0 {
            // timeval {0,0} disables timeout; clamp to 1us minimum.
            usec = 1;
        }
        libc::timeval {
            tv_sec: secs as _,
            tv_usec: usec as _,
        }
    }

    pub fn install(set_fd: i32, restore_fd: i32, timeout: Duration) -> std::io::Result<Self> {
        if timeout.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "handshake timeout must be > 0",
            ));
        }
        let old_recv = Self::get_timeout(set_fd, libc::SO_RCVTIMEO)?;
        let old_send = Self::get_timeout(set_fd, libc::SO_SNDTIMEO)?;
        let tv = Self::duration_to_timeval(timeout);

        Self::set_timeout(set_fd, libc::SO_RCVTIMEO, &tv)?;
        if let Err(e) = Self::set_timeout(set_fd, libc::SO_SNDTIMEO, &tv) {
            let _ = Self::set_timeout(set_fd, libc::SO_RCVTIMEO, &old_recv);
            return Err(e);
        }

        Ok(Self {
            restore_fd,
            old_recv,
            old_send,
            active: true,
        })
    }

    /// Restore the original socket timeouts early (before drop).
    /// After calling this, drop becomes a no-op for timeout restoration.
    /// Used to clear the handshake timeout for the data-transfer phase.
    pub fn restore_timeouts_early(&mut self) {
        if !self.active {
            return;
        }
        self.active = false;
        if let Err(e) = Self::set_timeout(self.restore_fd, libc::SO_RCVTIMEO, &self.old_recv) {
            eprintln!(
                "SocketTimeoutGuard: early restore SO_RCVTIMEO failed on fd={}: {}",
                self.restore_fd, e
            );
        }
        if let Err(e) = Self::set_timeout(self.restore_fd, libc::SO_SNDTIMEO, &self.old_send) {
            eprintln!(
                "SocketTimeoutGuard: early restore SO_SNDTIMEO failed on fd={}: {}",
                self.restore_fd, e
            );
        }
    }
}

impl Drop for SocketTimeoutGuard {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        if let Err(e) = Self::set_timeout(self.restore_fd, libc::SO_RCVTIMEO, &self.old_recv) {
            eprintln!(
                "SocketTimeoutGuard: restore SO_RCVTIMEO failed on fd={}: {}",
                self.restore_fd, e
            );
        }
        if let Err(e) = Self::set_timeout(self.restore_fd, libc::SO_SNDTIMEO, &self.old_send) {
            eprintln!(
                "SocketTimeoutGuard: restore SO_SNDTIMEO failed on fd={}: {}",
                self.restore_fd, e
            );
        }
    }
}

/// Manages the duplicated fd lifecycle for TLS/REALITY handshakes.
///
/// # Fd lifecycle invariants
///
/// 1. `dup(fd)` — Rust owns a separate fd to the same socket
/// 2. `BlockingGuard` clears O_NONBLOCK (Go needs it; rustls needs blocking)
/// 3. Handshake via RecordReader (reads/writes through dup'd fd)
/// 4. `setup_ulp(fd)` + `install_ktls(fd)` — must happen while dup'd fd
///    is alive (closing it may trigger ENOTCONN on some kernels)
/// 5. `drop(pipeline)` — reader closes dup'd fd, timeout/nonblock state restored
///
/// # Drop order
///
/// Struct fields drop in declaration order:
/// - `reader` drops first → closes dup'd fd
/// - `_timeout_guard` drops second → restores SO_RCVTIMEO/SO_SNDTIMEO
/// - `_guard` drops third → restores O_NONBLOCK on original fd (still alive)
pub(crate) struct HandshakePipeline {
    original_fd: i32,
    reader: tls::RecordReader,
    timeout_guard: SocketTimeoutGuard,
    _guard: BlockingGuard,
}

impl HandshakePipeline {
    /// Create a new pipeline: dup fd, clear O_NONBLOCK, prepare RecordReader.
    pub fn new(fd: i32, handshake_timeout: Duration) -> Result<Self, std::io::Error> {
        let dup_fd = unsafe { libc::dup(fd) };
        if dup_fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let guard = BlockingGuard::clear_nonblock(dup_fd, fd);
        let timeout_guard = match SocketTimeoutGuard::install(dup_fd, fd, handshake_timeout) {
            Ok(g) => g,
            Err(e) => {
                let _ = unsafe { libc::close(dup_fd) };
                return Err(e);
            }
        };
        let tcp = unsafe { TcpStream::from_raw_fd(dup_fd) };
        let reader = tls::RecordReader::new(tcp);
        Ok(Self {
            original_fd: fd,
            reader,
            timeout_guard,
            _guard: guard,
        })
    }

    pub fn reader_mut(&mut self) -> &mut tls::RecordReader {
        &mut self.reader
    }

    /// First record hash (for REALITY TOCTOU check).
    pub fn first_record_hash(&self) -> Option<&[u8; 32]> {
        self.reader.first_record_hash()
    }

    /// The original (Go-owned) fd this pipeline operates on.
    pub fn original_fd(&self) -> i32 {
        self.original_fd
    }

    /// Clear the handshake timeout for the data-transfer phase.
    /// After the handshake completes, the 8s timeout must be cleared so
    /// subsequent reads/writes on the deferred session don't time out.
    pub fn clear_handshake_timeout(&mut self) {
        self.timeout_guard.restore_timeouts_early();
    }

    /// Destructure the pipeline into its components for separate ownership.
    /// The write half gets a dup'd TcpStream so reader and writer can be
    /// locked independently. Returns (reader, write_stream, blocking_guard,
    /// timeout_guard, original_fd).
    pub fn into_parts(
        self,
    ) -> Result<
        (
            tls::RecordReader,
            TcpStream,
            BlockingGuard,
            SocketTimeoutGuard,
            i32,
        ),
        std::io::Error,
    > {
        let write_stream = self.reader.tcp.try_clone()?; // dup() for write half
        let original_fd = self.original_fd;
        let HandshakePipeline {
            reader,
            timeout_guard,
            _guard,
            ..
        } = self;
        Ok((reader, write_stream, _guard, timeout_guard, original_fd))
    }

    /// Install kTLS on the original fd, then consume self.
    /// Self drops after this call, closing dup'd fd and restoring O_NONBLOCK.
    pub fn install_ktls_and_finish(
        self,
        tls_version: u16,
        tx_secrets: &ConnectionTrafficSecrets,
        tx_seq: u64,
        rx_secrets: &ConnectionTrafficSecrets,
        rx_seq: u64,
    ) -> Result<KtlsInstallResult, String> {
        #[cfg(debug_assertions)]
        eprintln!(
            "kTLS install: fd={} version=0x{:04x} cipher=0x{:04x} tx_seq={} rx_seq={}",
            self.original_fd,
            tls_version,
            tls::cipher_suite_to_u16(tx_secrets),
            tx_seq,
            rx_seq,
        );

        tls::setup_ulp(self.original_fd).map_err(|e| format!("ULP: {}", e))?;
        let tx_result = tls::install_ktls(
            self.original_fd,
            tls::TLS_TX,
            tls_version,
            tx_secrets,
            tx_seq,
        );
        let rx_result = tls::install_ktls(
            self.original_fd,
            tls::TLS_RX,
            tls_version,
            rx_secrets,
            rx_seq,
        );

        #[cfg(debug_assertions)]
        {
            if let Err(ref e) = tx_result {
                eprintln!("kTLS install TX failed: fd={} err={}", self.original_fd, e);
            }
            if let Err(ref e) = rx_result {
                eprintln!("kTLS install RX failed: fd={} err={}", self.original_fd, e);
            }
        }

        // self drops here: reader closes dup'd fd, guard restores O_NONBLOCK
        Ok(KtlsInstallResult {
            tx_ok: tx_result.is_ok(),
            rx_ok: rx_result.is_ok(),
            tx_err: tx_result.err().map(|e| e.to_string()),
            rx_err: rx_result.err().map(|e| e.to_string()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::SocketTimeoutGuard;
    use std::time::Duration;

    fn get_timeout(fd: i32, optname: i32) -> std::io::Result<libc::timeval> {
        let mut tv: libc::timeval = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::timeval>() as libc::socklen_t;
        let ret = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                optname,
                &mut tv as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(tv)
    }

    fn micros(tv: libc::timeval) -> i64 {
        (tv.tv_sec as i64) * 1_000_000 + (tv.tv_usec as i64)
    }

    #[test]
    fn socket_timeout_guard_restores_on_original_fd_after_dup_closed() {
        let mut fds = [0i32; 2];
        let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
        assert_eq!(
            rc,
            0,
            "socketpair failed: {}",
            std::io::Error::last_os_error()
        );

        let original_fd = fds[0];
        let peer_fd = fds[1];
        let dup_fd = unsafe { libc::dup(original_fd) };
        assert!(
            dup_fd >= 0,
            "dup failed: {}",
            std::io::Error::last_os_error()
        );

        let old_recv = get_timeout(original_fd, libc::SO_RCVTIMEO).expect("read old timeout");

        let guard = SocketTimeoutGuard::install(dup_fd, original_fd, Duration::from_millis(25))
            .expect("install timeout guard");

        let applied_recv =
            get_timeout(original_fd, libc::SO_RCVTIMEO).expect("read applied timeout");
        assert!(
            micros(applied_recv) > micros(old_recv),
            "expected applied timeout to be greater than old timeout (old={}, applied={})",
            micros(old_recv),
            micros(applied_recv)
        );

        // Reproduce pipeline drop ordering where dup'd fd closes before timeout restore.
        let _ = unsafe { libc::close(dup_fd) };
        drop(guard);

        let restored_recv =
            get_timeout(original_fd, libc::SO_RCVTIMEO).expect("read restored timeout");
        assert_eq!(
            micros(restored_recv),
            micros(old_recv),
            "SO_RCVTIMEO should be restored on original fd"
        );

        let _ = unsafe { libc::close(original_fd) };
        let _ = unsafe { libc::close(peer_fd) };
    }
}
