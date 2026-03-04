//! Shared FFI safety macros and error constants.
//!
//! Every `extern "C"` function exposed to Go must be wrapped in one of
//! these macros.
//!
//! - `panic = "unwind"` builds: panic is caught and converted to an FFI error.
//! - `panic = "abort"` builds: body runs directly (no unwind wrapper), and any
//!   panic aborts the process immediately.

// ---------------------------------------------------------------------------
// Error‐code constants (shared between Rust and Go)
// ---------------------------------------------------------------------------

pub const FFI_OK: i32 = 0;
pub const FFI_ERR_APP: i32 = 1;
pub const FFI_ERR_CRYPTO: i32 = 2;
pub const FFI_ERR_NULL: i32 = -1;
pub const FFI_ERR_PANIC: i32 = -99;

// ---------------------------------------------------------------------------
// catch_unwind wrapper macros
// ---------------------------------------------------------------------------

/// Wrap an FFI body that returns `i32`. On panic returns `FFI_ERR_PANIC` (-99).
///
/// **Note:** `return` inside the block exits the closure, not the outer function.
/// The macro must be the tail expression of the enclosing function.
macro_rules! ffi_catch_i32 {
    ($body:block) => {{
        #[cfg(panic = "unwind")]
        {
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| $body)) {
                Ok(v) => v,
                Err(e) => {
                    let msg = e
                        .downcast_ref::<&str>()
                        .copied()
                        .or_else(|| e.downcast_ref::<String>().map(|s| s.as_str()));
                    eprintln!("xray-rust FFI panic (i32): {}", msg.unwrap_or("unknown"));
                    $crate::ffi::FFI_ERR_PANIC
                }
            }
        }
        #[cfg(not(panic = "unwind"))]
        {
            (|| -> i32 { $body })()
        }
    }};
}

/// Wrap an FFI body that returns `*mut T`. On panic returns null.
macro_rules! ffi_catch_ptr {
    ($body:block) => {{
        #[cfg(panic = "unwind")]
        {
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| $body)) {
                Ok(v) => v,
                Err(e) => {
                    let msg = e
                        .downcast_ref::<&str>()
                        .copied()
                        .or_else(|| e.downcast_ref::<String>().map(|s| s.as_str()));
                    eprintln!("xray-rust FFI panic (ptr): {}", msg.unwrap_or("unknown"));
                    std::ptr::null_mut()
                }
            }
        }
        #[cfg(not(panic = "unwind"))]
        {
            (|| $body)()
        }
    }};
}

/// Wrap an FFI body that returns `bool`. On panic returns `false`.
macro_rules! ffi_catch_bool {
    ($body:block) => {{
        #[cfg(panic = "unwind")]
        {
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| $body)) {
                Ok(v) => v,
                Err(e) => {
                    let msg = e
                        .downcast_ref::<&str>()
                        .copied()
                        .or_else(|| e.downcast_ref::<String>().map(|s| s.as_str()));
                    eprintln!("xray-rust FFI panic (bool): {}", msg.unwrap_or("unknown"));
                    false
                }
            }
        }
        #[cfg(not(panic = "unwind"))]
        {
            (|| -> bool { $body })()
        }
    }};
}

/// Wrap an FFI body that returns `u8`. On panic returns `default`.
macro_rules! ffi_catch_u8 {
    ($default:expr, $body:block) => {{
        #[cfg(panic = "unwind")]
        {
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| $body)) {
                Ok(v) => v,
                Err(e) => {
                    let msg = e
                        .downcast_ref::<&str>()
                        .copied()
                        .or_else(|| e.downcast_ref::<String>().map(|s| s.as_str()));
                    eprintln!("xray-rust FFI panic (u8): {}", msg.unwrap_or("unknown"));
                    $default
                }
            }
        }
        #[cfg(not(panic = "unwind"))]
        {
            (|| -> u8 { $body })()
        }
    }};
}

/// Wrap a void FFI body. On panic the error is logged to stderr.
macro_rules! ffi_catch_void {
    ($body:block) => {{
        #[cfg(panic = "unwind")]
        {
            if let Err(e) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| $body)) {
                let msg = e
                    .downcast_ref::<&str>()
                    .copied()
                    .or_else(|| e.downcast_ref::<String>().map(|s| s.as_str()));
                eprintln!("xray-rust FFI panic (void): {}", msg.unwrap_or("unknown"));
            }
        }
        #[cfg(not(panic = "unwind"))]
        {
            (|| $body)();
        }
    }};
}

/// Drive a rustls handshake to completion using a RecordReader.
/// Uses a closure so that `?` returns from the closure, not the caller.
/// Evaluates to `Result<(), std::io::Error>`.
macro_rules! drive_handshake {
    ($conn:expr, $reader:expr) => {
        (|| -> Result<(), std::io::Error> {
            loop {
                // Flush any pending writes first
                while $conn.wants_write() {
                    $conn.write_tls(&mut $reader.tcp)?;
                }
                $reader.tcp.flush()?;

                // Check if handshake is done
                if !$conn.is_handshaking() {
                    break;
                }

                // Read the next record and feed it to rustls
                if $conn.wants_read() {
                    $conn.read_tls($reader)?;
                    $conn
                        .process_new_packets()
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                }
            }
            // Final flush
            while $conn.wants_write() {
                $conn.write_tls(&mut $reader.tcp)?;
            }
            $reader.tcp.flush()?;
            Ok(())
        })()
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #[test]
    fn test_ffi_catch_i32_ok() {
        let r: i32 = ffi_catch_i32!({ 42 });
        assert_eq!(r, 42);
    }

    #[test]
    fn test_ffi_catch_i32_panic() {
        let r: i32 = ffi_catch_i32!({ panic!("boom") });
        assert_eq!(r, super::FFI_ERR_PANIC);
    }

    #[test]
    fn test_ffi_catch_ptr_ok() {
        let mut val = 5u8;
        let p: *mut u8 = ffi_catch_ptr!({ &mut val as *mut u8 });
        assert!(!p.is_null());
    }

    #[test]
    fn test_ffi_catch_ptr_panic() {
        let p: *mut u8 = ffi_catch_ptr!({ panic!("boom") });
        assert!(p.is_null());
    }

    #[test]
    fn test_ffi_catch_bool_ok() {
        let r: bool = ffi_catch_bool!({ true });
        assert!(r);
    }

    #[test]
    fn test_ffi_catch_bool_panic() {
        let r: bool = ffi_catch_bool!({ panic!("boom") });
        assert!(!r);
    }

    #[test]
    fn test_ffi_catch_void_ok() {
        let mut x = 0;
        ffi_catch_void!({ x = 1 });
        assert_eq!(x, 1);
    }

    #[test]
    fn test_ffi_catch_void_panic() {
        // Should not propagate
        ffi_catch_void!({ panic!("boom") });
    }
}
