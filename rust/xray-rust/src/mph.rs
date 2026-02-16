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
    Box::into_raw(Box::new(MphTable::new()))
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
    let table = &mut *table;
    let pattern = slice::from_raw_parts(pattern, pattern_len);
    let pattern = match std::str::from_utf8(pattern) {
        Ok(s) => s,
        Err(_) => return,
    };
    table.add_pattern(pattern, pattern_type);
}

/// Build the MPH table. Must be called after adding all patterns and before matching.
///
/// # Safety
/// `table` must be a valid pointer from `xray_mph_new`.
#[no_mangle]
pub unsafe extern "C" fn xray_mph_build(table: *mut MphTable) {
    let table = &mut *table;
    table.build();
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
    let table = &*table;
    let input = slice::from_raw_parts(input, input_len);
    let input = match std::str::from_utf8(input) {
        Ok(s) => s,
        Err(_) => return false,
    };
    table.match_input(input)
}

/// Free an MPH table.
///
/// # Safety
/// `table` must be a valid pointer from `xray_mph_new`, or null. Must not be used after freeing.
#[no_mangle]
pub unsafe extern "C" fn xray_mph_free(table: *mut MphTable) {
    if !table.is_null() {
        drop(Box::from_raw(table));
    }
}
