use ahash::AHashSet;
use aho_corasick::AhoCorasick;
use std::slice;

/// Pattern type constants matching Go's strmatcher.Type.
const PATTERN_FULL: u8 = 0;
const PATTERN_SUBSTR: u8 = 1;
const PATTERN_DOMAIN: u8 = 2;

/// MphTable stores domain/full match patterns in a HashSet and substr patterns
/// in an Aho-Corasick automaton for fast multi-pattern matching.
pub struct MphTable {
    /// Stores full-match and domain-match patterns (AHashSet for faster lookups).
    patterns: AHashSet<String>,
    /// Substr patterns accumulated before build.
    substr_patterns: Vec<String>,
    /// Built Aho-Corasick automaton for substr matching.
    ac: Option<AhoCorasick>,
}

impl MphTable {
    fn new() -> Self {
        MphTable {
            patterns: AHashSet::new(),
            substr_patterns: Vec::new(),
            ac: None,
        }
    }

    fn add_pattern(&mut self, pattern: &str, pattern_type: u8) {
        match pattern_type {
            PATTERN_FULL => {
                self.patterns.insert(pattern.to_ascii_lowercase());
            }
            PATTERN_DOMAIN => {
                let lower = pattern.to_ascii_lowercase();
                self.patterns.insert(format!(".{}", lower));
                self.patterns.insert(lower);
            }
            PATTERN_SUBSTR => {
                self.substr_patterns.push(pattern.to_string());
            }
            _ => {}
        }
    }

    fn build(&mut self) {
        if !self.substr_patterns.is_empty() {
            self.ac = AhoCorasick::builder()
                .ascii_case_insensitive(true)
                .build(&self.substr_patterns)
                .ok();
        }
        self.patterns.shrink_to_fit();
    }

    fn match_input(&self, input: &str) -> bool {
        // 1. Check full match.
        if self.patterns.contains(input) {
            return true;
        }

        // 2. Check domain suffix matches: at each '.', look up the suffix.
        for (i, b) in input.bytes().enumerate() {
            if b == b'.' {
                if self.patterns.contains(&input[i..]) {
                    return true;
                }
            }
        }

        // 3. Check substr via Aho-Corasick automaton.
        if let Some(ref ac) = self.ac {
            if ac.is_match(input) {
                return true;
            }
        }

        false
    }
}

/// Create a new empty MPH table.
#[no_mangle]
pub extern "C" fn xray_mph_new() -> *mut MphTable {
    ffi_catch_ptr!({
        Box::into_raw(Box::new(MphTable::new()))
    })
}

/// Add a pattern to the MPH table.
///
/// pattern_type: 0 = Full, 1 = Substr, 2 = Domain
///
/// # Safety
/// `table` must be a valid pointer from `xray_mph_new`. `pattern`/`pattern_len` must be valid.
#[no_mangle]
pub unsafe extern "C" fn xray_mph_add_pattern(
    table: *mut MphTable,
    pattern: *const u8,
    pattern_len: usize,
    pattern_type: u8,
) {
    ffi_catch_void!({
        let table = &mut *table;
        let pattern = slice::from_raw_parts(pattern, pattern_len);
        let pattern = match std::str::from_utf8(pattern) {
            Ok(s) => s,
            Err(_) => return,
        };
        table.add_pattern(pattern, pattern_type);
    })
}

/// Build the MPH table. Must be called after adding all patterns and before matching.
///
/// # Safety
/// `table` must be a valid pointer from `xray_mph_new`.
#[no_mangle]
pub unsafe extern "C" fn xray_mph_build(table: *mut MphTable) {
    ffi_catch_void!({
        let table = &mut *table;
        table.build();
    })
}

/// Match an input string against the MPH table.
/// Returns true if any pattern matches.
///
/// # Safety
/// `table` must be a valid, built pointer from `xray_mph_new`.
/// `input`/`input_len` must be valid.
#[no_mangle]
pub unsafe extern "C" fn xray_mph_match(
    table: *const MphTable,
    input: *const u8,
    input_len: usize,
) -> bool {
    ffi_catch_bool!({
        let table = &*table;
        let input = slice::from_raw_parts(input, input_len);
        let input = match std::str::from_utf8(input) {
            Ok(s) => s,
            Err(_) => return false,
        };
        table.match_input(input)
    })
}

/// Free an MPH table.
///
/// # Safety
/// `table` must be a valid pointer from `xray_mph_new`, or null. Must not be used after freeing.
#[no_mangle]
pub unsafe extern "C" fn xray_mph_free(table: *mut MphTable) {
    ffi_catch_void!({
        if !table.is_null() {
            drop(Box::from_raw(table));
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- Internal API tests --

    #[test]
    fn test_full_match() {
        let mut t = MphTable::new();
        t.add_pattern("example.com", PATTERN_FULL);
        t.build();
        assert!(t.match_input("example.com"));
        assert!(!t.match_input("sub.example.com"));
        assert!(!t.match_input("notexample.com"));
    }

    #[test]
    fn test_full_match_pattern_lowercased() {
        // Patterns are stored lowercased; inputs are NOT lowered by match_input.
        // Go callers pre-lowercase domain inputs before calling the matcher.
        let mut t = MphTable::new();
        t.add_pattern("Example.COM", PATTERN_FULL);
        t.build();
        assert!(t.match_input("example.com"), "lowered input matches lowered pattern");
        assert!(!t.match_input("EXAMPLE.COM"), "uppercase input does not match (expected)");
    }

    #[test]
    fn test_domain_match() {
        let mut t = MphTable::new();
        t.add_pattern("example.com", PATTERN_DOMAIN);
        t.build();
        assert!(t.match_input("example.com"), "exact domain");
        assert!(t.match_input("sub.example.com"), "subdomain");
        assert!(t.match_input("deep.sub.example.com"), "deep subdomain");
        assert!(!t.match_input("notexample.com"), "suffix without dot");
        assert!(!t.match_input("fakeexample.com"), "no match");
    }

    #[test]
    fn test_substr_match() {
        let mut t = MphTable::new();
        t.add_pattern("evil", PATTERN_SUBSTR);
        t.build();
        assert!(t.match_input("www.evil.com"));
        assert!(t.match_input("evil.org"));
        assert!(t.match_input("some-evil-site.net"));
        assert!(!t.match_input("benign.com"));
    }

    #[test]
    fn test_substr_case_insensitive() {
        let mut t = MphTable::new();
        t.add_pattern("tracker", PATTERN_SUBSTR);
        t.build();
        assert!(t.match_input("TRACKER.example.com"));
        assert!(t.match_input("ad-Tracker.net"));
    }

    #[test]
    fn test_mixed_patterns() {
        let mut t = MphTable::new();
        t.add_pattern("exact.com", PATTERN_FULL);
        t.add_pattern("domain.org", PATTERN_DOMAIN);
        t.add_pattern("ads", PATTERN_SUBSTR);
        t.build();

        assert!(t.match_input("exact.com"));
        assert!(!t.match_input("sub.exact.com"));

        assert!(t.match_input("domain.org"));
        assert!(t.match_input("sub.domain.org"));

        assert!(t.match_input("ads.tracker.com"));
        assert!(t.match_input("no-ads.com"));
        assert!(!t.match_input("benign.example.net"));
    }

    #[test]
    fn test_empty_table() {
        let mut t = MphTable::new();
        t.build();
        assert!(!t.match_input("anything.com"));
        assert!(!t.match_input(""));
    }

    #[test]
    fn test_unknown_pattern_type() {
        let mut t = MphTable::new();
        t.add_pattern("ignored", 99);
        t.build();
        assert!(!t.match_input("ignored"));
    }

    // -- FFI API tests --

    #[test]
    fn test_ffi_lifecycle() {
        unsafe {
            let table = xray_mph_new();
            assert!(!table.is_null());

            let p = b"example.com";
            xray_mph_add_pattern(table, p.as_ptr(), p.len(), PATTERN_DOMAIN);
            xray_mph_build(table);

            let input = b"sub.example.com";
            assert!(xray_mph_match(table, input.as_ptr(), input.len()));

            let miss = b"other.net";
            assert!(!xray_mph_match(table, miss.as_ptr(), miss.len()));

            xray_mph_free(table);
        }
    }

    #[test]
    fn test_ffi_invalid_utf8_pattern() {
        unsafe {
            let table = xray_mph_new();
            let invalid = &[0xFF, 0xFE, 0xFD];
            xray_mph_add_pattern(table, invalid.as_ptr(), invalid.len(), PATTERN_FULL);
            xray_mph_build(table);
            // Invalid UTF-8 pattern silently dropped; nothing matches.
            assert!(!xray_mph_match(table, invalid.as_ptr(), invalid.len()));
            xray_mph_free(table);
        }
    }

    #[test]
    fn test_ffi_invalid_utf8_input() {
        unsafe {
            let table = xray_mph_new();
            let p = b"test.com";
            xray_mph_add_pattern(table, p.as_ptr(), p.len(), PATTERN_FULL);
            xray_mph_build(table);
            let invalid = &[0xFF, 0xFE];
            assert!(!xray_mph_match(table, invalid.as_ptr(), invalid.len()));
            xray_mph_free(table);
        }
    }

    #[test]
    fn test_ffi_free_null() {
        unsafe {
            xray_mph_free(std::ptr::null_mut()); // must not crash
        }
    }
}
