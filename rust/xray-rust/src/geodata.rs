//! Single-pass geodata (geoip.dat / geosite.dat) loader.
//!
//! Replaces the Go N-pass approach (one `find()` scan per country code) with
//! a single mmap + parse that extracts all requested entries at once.
//! For GeoIP, directly builds `IpSet` handles from parsed CIDR data.
//! For GeoSite, returns domain pattern lists for Go to feed to `MphAddPattern`.

use crate::geoip::IpSet;
use std::collections::HashMap;
use std::slice;

// ── Protobuf wire format helpers ─────────────────────────────────────────

/// Decode a varint from a byte slice. Returns (value, bytes_consumed).
fn decode_varint(data: &[u8]) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    let mut shift: u32 = 0;
    for (i, &byte) in data.iter().enumerate() {
        if i >= 10 {
            return None; // varint too long
        }
        value |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            return Some((value, i + 1));
        }
        shift += 7;
    }
    None // truncated
}

/// Skip a protobuf field based on wire type. Returns bytes consumed.
fn skip_field(wire_type: u8, data: &[u8]) -> Option<usize> {
    match wire_type {
        0 => {
            // Varint
            decode_varint(data).map(|(_, n)| n)
        }
        1 => {
            // 64-bit
            if data.len() >= 8 {
                Some(8)
            } else {
                None
            }
        }
        2 => {
            // Length-delimited
            let (len, n) = decode_varint(data)?;
            let len_usize = usize::try_from(len).ok()?;
            let total = n.checked_add(len_usize)?;
            if data.len() >= total {
                Some(total)
            } else {
                None
            }
        }
        5 => {
            // 32-bit
            if data.len() >= 4 {
                Some(4)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Read a length-delimited field (bytes/string). Returns (content, bytes_consumed).
fn read_bytes_field(data: &[u8]) -> Option<(&[u8], usize)> {
    let (len, n) = decode_varint(data)?;
    let len_usize = usize::try_from(len).ok()?;
    let end = n.checked_add(len_usize)?;
    if data.len() >= end {
        Some((&data[n..end], end))
    } else {
        None
    }
}

// ── GeoIP protobuf parsing ──────────────────────────────────────────────
//
// message CIDR { bytes ip = 1; uint32 prefix = 2; }
// message GeoIP { string country_code = 1; repeated CIDR cidr = 2; }
// message GeoIPList { repeated GeoIP entry = 1; }

struct CidrEntry<'a> {
    ip: &'a [u8],
    prefix: u8,
}

/// Parse a single CIDR message.
fn parse_cidr(data: &[u8]) -> Option<CidrEntry<'_>> {
    let mut ip: &[u8] = &[];
    let mut prefix: u32 = 0;
    let mut pos = 0;

    while pos < data.len() {
        let (tag, n) = decode_varint(&data[pos..])?;
        pos += n;
        let field_number = (tag >> 3) as u32;
        let wire_type = (tag & 0x07) as u8;

        match (field_number, wire_type) {
            (1, 2) => {
                // ip = bytes, field 1
                let (bytes, consumed) = read_bytes_field(&data[pos..])?;
                ip = bytes;
                pos += consumed;
            }
            (2, 0) => {
                // prefix = uint32, field 2 (valid range: 0-128)
                let (val, consumed) = decode_varint(&data[pos..])?;
                prefix = u32::try_from(val).ok()?;
                pos += consumed;
            }
            (_, wt) => {
                pos += skip_field(wt, &data[pos..])?;
            }
        }
    }

    if ip.is_empty() {
        return None;
    }
    Some(CidrEntry {
        ip,
        prefix: prefix as u8,
    })
}

/// Parse a GeoIP entry to extract country_code and build an IpSet.
/// Returns (country_code, IpSet).
fn parse_geoip_entry(data: &[u8]) -> Option<(String, IpSet)> {
    let mut code = String::new();
    let mut ipset = IpSet::new_internal();
    let mut pos = 0;

    while pos < data.len() {
        let (tag, n) = decode_varint(&data[pos..])?;
        pos += n;
        let field_number = (tag >> 3) as u32;
        let wire_type = (tag & 0x07) as u8;

        match (field_number, wire_type) {
            (1, 2) => {
                // country_code = string, field 1
                let (bytes, consumed) = read_bytes_field(&data[pos..])?;
                code = String::from_utf8_lossy(bytes).to_uppercase();
                pos += consumed;
            }
            (2, 2) => {
                // cidr = CIDR message, field 2 (repeated)
                let (cidr_bytes, consumed) = read_bytes_field(&data[pos..])?;
                if let Some(cidr) = parse_cidr(cidr_bytes) {
                    ipset.add_prefix(cidr.ip, cidr.prefix);
                }
                pos += consumed;
            }
            (_, wt) => {
                pos += skip_field(wt, &data[pos..])?;
            }
        }
    }

    if code.is_empty() {
        return None;
    }
    ipset.build();
    Some((code, ipset))
}

/// Parse a GeoIPList and return IpSet handles for requested codes.
fn parse_geoip_list(data: &[u8], codes: &[String]) -> HashMap<String, IpSet> {
    let code_set: std::collections::HashSet<&str> = codes.iter().map(|s| s.as_str()).collect();
    let mut result = HashMap::new();
    let mut pos = 0;

    while pos < data.len() {
        let (tag, n) = match decode_varint(&data[pos..]) {
            Some(v) => v,
            None => break,
        };
        pos += n;
        let field_number = (tag >> 3) as u32;
        let wire_type = (tag & 0x07) as u8;

        if field_number == 1 && wire_type == 2 {
            // GeoIP entry (field 1, length-delimited)
            let (entry_bytes, consumed) = match read_bytes_field(&data[pos..]) {
                Some(v) => v,
                None => break,
            };
            pos += consumed;

            // Quick-check: peek at country_code before full parse
            // to skip entries we don't need.
            if let Some(code) = peek_country_code(entry_bytes) {
                if code_set.contains(code.to_uppercase().as_str()) {
                    if let Some((code, ipset)) = parse_geoip_entry(entry_bytes) {
                        result.insert(code, ipset);
                    }
                }
            }
        } else {
            match skip_field(wire_type, &data[pos..]) {
                Some(skipped) => pos += skipped,
                None => break,
            }
        }
    }

    result
}

/// Peek at the country_code field (field 1) in a GeoIP/GeoSite entry
/// without fully parsing it.
fn peek_country_code(data: &[u8]) -> Option<String> {
    let mut pos = 0;
    while pos < data.len() {
        let (tag, n) = decode_varint(&data[pos..])?;
        pos += n;
        let field_number = (tag >> 3) as u32;
        let wire_type = (tag & 0x07) as u8;

        if field_number == 1 && wire_type == 2 {
            let (bytes, _) = read_bytes_field(&data[pos..])?;
            return Some(String::from_utf8_lossy(bytes).into_owned());
        }
        // Skip other fields
        pos += skip_field(wire_type, &data[pos..])?;
    }
    None
}

// ── GeoSite protobuf parsing ────────────────────────────────────────────
//
// message Domain {
//   enum Type { Plain=0; Regex=1; Domain=2; Full=3; }
//   Type type = 1;
//   string value = 2;
//   repeated Attribute attribute = 3;
// }
// message GeoSite { string country_code = 1; repeated Domain domain = 2; }
// message GeoSiteList { repeated GeoSite entry = 1; }

/// Parse a Domain message and extract type + value.
fn parse_domain(data: &[u8]) -> Option<(u8, String)> {
    let mut dtype: u8 = 0;
    let mut value = String::new();
    let mut pos = 0;

    while pos < data.len() {
        let (tag, n) = decode_varint(&data[pos..])?;
        pos += n;
        let field_number = (tag >> 3) as u32;
        let wire_type = (tag & 0x07) as u8;

        match (field_number, wire_type) {
            (1, 0) => {
                // type = enum (varint), field 1
                let (val, consumed) = decode_varint(&data[pos..])?;
                dtype = val as u8;
                pos += consumed;
            }
            (2, 2) => {
                // value = string, field 2
                let (bytes, consumed) = read_bytes_field(&data[pos..])?;
                value = String::from_utf8_lossy(bytes).into_owned();
                pos += consumed;
            }
            (_, wt) => {
                pos += skip_field(wt, &data[pos..])?;
            }
        }
    }

    if value.is_empty() {
        return None;
    }
    Some((dtype, value))
}

/// Parse a GeoSite entry and return its domains.
fn parse_geosite_entry(data: &[u8]) -> Option<(String, Vec<(u8, String)>)> {
    let mut code = String::new();
    let mut domains = Vec::new();
    let mut pos = 0;

    while pos < data.len() {
        let (tag, n) = decode_varint(&data[pos..])?;
        pos += n;
        let field_number = (tag >> 3) as u32;
        let wire_type = (tag & 0x07) as u8;

        match (field_number, wire_type) {
            (1, 2) => {
                let (bytes, consumed) = read_bytes_field(&data[pos..])?;
                code = String::from_utf8_lossy(bytes).to_uppercase();
                pos += consumed;
            }
            (2, 2) => {
                let (domain_bytes, consumed) = read_bytes_field(&data[pos..])?;
                if let Some(domain) = parse_domain(domain_bytes) {
                    domains.push(domain);
                }
                pos += consumed;
            }
            (_, wt) => {
                pos += skip_field(wt, &data[pos..])?;
            }
        }
    }

    if code.is_empty() {
        return None;
    }
    Some((code, domains))
}

/// Parse a GeoSiteList and return domain lists for requested codes.
fn parse_geosite_list(data: &[u8], codes: &[String]) -> HashMap<String, Vec<(u8, String)>> {
    let code_set: std::collections::HashSet<&str> = codes.iter().map(|s| s.as_str()).collect();
    let mut result = HashMap::new();
    let mut pos = 0;

    while pos < data.len() {
        let (tag, n) = match decode_varint(&data[pos..]) {
            Some(v) => v,
            None => break,
        };
        pos += n;
        let field_number = (tag >> 3) as u32;
        let wire_type = (tag & 0x07) as u8;

        if field_number == 1 && wire_type == 2 {
            let (entry_bytes, consumed) = match read_bytes_field(&data[pos..]) {
                Some(v) => v,
                None => break,
            };
            pos += consumed;

            if let Some(code) = peek_country_code(entry_bytes) {
                if code_set.contains(code.to_uppercase().as_str()) {
                    if let Some((code, domains)) = parse_geosite_entry(entry_bytes) {
                        result.insert(code, domains);
                    }
                }
            }
        } else {
            match skip_field(wire_type, &data[pos..]) {
                Some(skipped) => pos += skipped,
                None => break,
            }
        }
    }

    result
}

// ── FFI: GeoIP loading ──────────────────────────────────────────────────

/// Result of a GeoIP batch load.
#[repr(C)]
pub struct GeoIpResult {
    /// Array of IpSet handle pointers (one per requested code, in same order).
    /// Null pointer for codes not found in the file.
    pub handles: *mut *mut IpSet,
    /// Number of handles (same as num_codes in the request).
    pub count: usize,
    /// 0 on success, negative on error.
    pub error_code: i32,
}

/// Load GeoIP data from a file and build IpSet handles for requested country codes.
///
/// # Safety
/// All pointer/length pairs must be valid. `codes` array must have `num_codes` entries.
#[no_mangle]
pub unsafe extern "C" fn xray_geoip_load(
    path: *const u8,
    path_len: usize,
    codes: *const *const u8,
    code_lens: *const usize,
    num_codes: usize,
    result: *mut GeoIpResult,
) -> i32 {
    ffi_catch_i32!({
        if path.is_null() || result.is_null() {
            return crate::ffi::FFI_ERR_NULL;
        }
        if num_codes == 0 {
            (*result).handles = std::ptr::null_mut();
            (*result).count = 0;
            (*result).error_code = crate::ffi::FFI_OK;
            return crate::ffi::FFI_OK;
        }
        if codes.is_null() || code_lens.is_null() {
            return crate::ffi::FFI_ERR_NULL;
        }
        if num_codes > 65536 {
            return crate::ffi::FFI_ERR_APP;
        }

        // Parse path
        let path_bytes = slice::from_raw_parts(path, path_len);
        let path_str = match std::str::from_utf8(path_bytes) {
            Ok(s) => s,
            Err(_) => return crate::ffi::FFI_ERR_APP,
        };

        // Parse requested codes
        let codes_ptrs = slice::from_raw_parts(codes, num_codes);
        let codes_lens = slice::from_raw_parts(code_lens, num_codes);
        let mut code_list = Vec::with_capacity(num_codes);
        for i in 0..num_codes {
            let code_bytes = slice::from_raw_parts(codes_ptrs[i], codes_lens[i]);
            let code = String::from_utf8_lossy(code_bytes).to_uppercase();
            code_list.push(code);
        }

        // mmap the file
        let file = match std::fs::File::open(path_str) {
            Ok(f) => f,
            Err(_) => return crate::ffi::FFI_ERR_APP,
        };
        let mmap = match memmap2::Mmap::map(&file) {
            Ok(m) => m,
            Err(_) => return crate::ffi::FFI_ERR_APP,
        };

        // Parse all requested GeoIP entries in one pass
        let mut ipsets = parse_geoip_list(&mmap, &code_list);

        // Build result array in requested order
        let handles_layout = match std::alloc::Layout::array::<*mut IpSet>(num_codes) {
            Ok(l) => l,
            Err(_) => return crate::ffi::FFI_ERR_APP,
        };
        let handles_ptr = std::alloc::alloc(handles_layout) as *mut *mut IpSet;
        if handles_ptr.is_null() {
            return crate::ffi::FFI_ERR_APP;
        }

        for (i, code) in code_list.iter().enumerate() {
            if let Some(ipset) = ipsets.remove(code) {
                *handles_ptr.add(i) = Box::into_raw(Box::new(ipset));
            } else {
                *handles_ptr.add(i) = std::ptr::null_mut();
            }
        }

        (*result).handles = handles_ptr;
        (*result).count = num_codes;
        (*result).error_code = crate::ffi::FFI_OK;
        crate::ffi::FFI_OK
    })
}

/// Free a GeoIpResult (including all IpSet handles).
///
/// # Safety
/// `result` must be from `xray_geoip_load`.
#[no_mangle]
pub unsafe extern "C" fn xray_geoip_result_free(result: *mut GeoIpResult) {
    ffi_catch_void!({
        if result.is_null() {
            return;
        }
        let r = &*result;
        if !r.handles.is_null() && r.count > 0 {
            // Note: don't free the IpSet handles themselves — Go owns them
            // via SetFinalizer. Only free the handles array.
            if let Ok(layout) = std::alloc::Layout::array::<*mut IpSet>(r.count) {
                std::alloc::dealloc(r.handles as *mut u8, layout);
            }
        }
        (*result).handles = std::ptr::null_mut();
        (*result).count = 0;
    });
}

// ── FFI: GeoSite loading ────────────────────────────────────────────────

/// A single domain entry returned from GeoSite loading.
#[repr(C)]
pub struct GeoSiteDomain {
    /// Domain type: 0=Plain, 1=Regex, 2=Domain, 3=Full
    pub domain_type: u8,
    /// Pointer to the domain value string (UTF-8, NOT null-terminated).
    pub value: *const u8,
    pub value_len: usize,
}

/// Result for a single country code's domain list.
#[repr(C)]
pub struct GeoSiteCodeResult {
    pub domains: *mut GeoSiteDomain,
    pub domain_count: usize,
}

/// Result of a GeoSite batch load.
#[repr(C)]
pub struct GeoSiteResult {
    /// Array of per-code results (one per requested code, in same order).
    pub entries: *mut GeoSiteCodeResult,
    /// Number of entries (same as num_codes in the request).
    pub count: usize,
    /// 0 on success.
    pub error_code: i32,
    /// Opaque pointer to owned data (strings). Must be freed with result.
    _owned_data: *mut Vec<Vec<(u8, String)>>,
}

/// Load GeoSite data from a file and return domain patterns for requested codes.
///
/// # Safety
/// All pointer/length pairs must be valid.
#[no_mangle]
pub unsafe extern "C" fn xray_geosite_load(
    path: *const u8,
    path_len: usize,
    codes: *const *const u8,
    code_lens: *const usize,
    num_codes: usize,
    result: *mut GeoSiteResult,
) -> i32 {
    ffi_catch_i32!({
        if path.is_null() || result.is_null() {
            return crate::ffi::FFI_ERR_NULL;
        }
        if num_codes == 0 {
            (*result).entries = std::ptr::null_mut();
            (*result).count = 0;
            (*result).error_code = crate::ffi::FFI_OK;
            (*result)._owned_data = std::ptr::null_mut();
            return crate::ffi::FFI_OK;
        }
        if codes.is_null() || code_lens.is_null() {
            return crate::ffi::FFI_ERR_NULL;
        }
        if num_codes > 65536 {
            return crate::ffi::FFI_ERR_APP;
        }

        let path_bytes = slice::from_raw_parts(path, path_len);
        let path_str = match std::str::from_utf8(path_bytes) {
            Ok(s) => s,
            Err(_) => return crate::ffi::FFI_ERR_APP,
        };

        let codes_ptrs = slice::from_raw_parts(codes, num_codes);
        let codes_lens = slice::from_raw_parts(code_lens, num_codes);
        let mut code_list = Vec::with_capacity(num_codes);
        for i in 0..num_codes {
            let code_bytes = slice::from_raw_parts(codes_ptrs[i], codes_lens[i]);
            let code = String::from_utf8_lossy(code_bytes).to_uppercase();
            code_list.push(code);
        }

        let file = match std::fs::File::open(path_str) {
            Ok(f) => f,
            Err(_) => return crate::ffi::FFI_ERR_APP,
        };
        let mmap = match memmap2::Mmap::map(&file) {
            Ok(m) => m,
            Err(_) => return crate::ffi::FFI_ERR_APP,
        };

        let mut domains_map = parse_geosite_list(&mmap, &code_list);

        // Store owned data on the heap so string pointers remain valid
        let mut owned_data: Vec<Vec<(u8, String)>> = Vec::with_capacity(num_codes);
        for code in &code_list {
            let domains = domains_map.remove(code).unwrap_or_default();
            owned_data.push(domains);
        }
        let owned_data_ptr = Box::into_raw(Box::new(owned_data));
        let owned_data_ref = &*owned_data_ptr;

        // Build result arrays
        let entries_layout = match std::alloc::Layout::array::<GeoSiteCodeResult>(num_codes) {
            Ok(l) => l,
            Err(_) => {
                drop(Box::from_raw(owned_data_ptr));
                return crate::ffi::FFI_ERR_APP;
            }
        };
        let entries_ptr = std::alloc::alloc(entries_layout) as *mut GeoSiteCodeResult;
        if entries_ptr.is_null() {
            drop(Box::from_raw(owned_data_ptr));
            return crate::ffi::FFI_ERR_APP;
        }

        for (i, domains) in owned_data_ref.iter().enumerate() {
            if domains.is_empty() {
                let entry = &mut *entries_ptr.add(i);
                entry.domains = std::ptr::null_mut();
                entry.domain_count = 0;
                continue;
            }

            let domain_layout = match std::alloc::Layout::array::<GeoSiteDomain>(domains.len()) {
                Ok(l) => l,
                Err(_) => {
                    for j in 0..i {
                        let prev = &*entries_ptr.add(j);
                        if !prev.domains.is_null() {
                            if let Ok(prev_layout) =
                                std::alloc::Layout::array::<GeoSiteDomain>(prev.domain_count)
                            {
                                std::alloc::dealloc(prev.domains as *mut u8, prev_layout);
                            }
                        }
                    }
                    std::alloc::dealloc(entries_ptr as *mut u8, entries_layout);
                    drop(Box::from_raw(owned_data_ptr));
                    return crate::ffi::FFI_ERR_APP;
                }
            };
            let domain_ptr = std::alloc::alloc(domain_layout) as *mut GeoSiteDomain;
            if domain_ptr.is_null() {
                // Cleanup previously allocated
                for j in 0..i {
                    let prev = &*entries_ptr.add(j);
                    if !prev.domains.is_null() {
                        if let Ok(prev_layout) =
                            std::alloc::Layout::array::<GeoSiteDomain>(prev.domain_count)
                        {
                            std::alloc::dealloc(prev.domains as *mut u8, prev_layout);
                        }
                    }
                }
                std::alloc::dealloc(entries_ptr as *mut u8, entries_layout);
                drop(Box::from_raw(owned_data_ptr));
                return crate::ffi::FFI_ERR_APP;
            }

            for (j, (dtype, value)) in domains.iter().enumerate() {
                let d = &mut *domain_ptr.add(j);
                d.domain_type = *dtype;
                d.value = value.as_ptr();
                d.value_len = value.len();
            }

            let entry = &mut *entries_ptr.add(i);
            entry.domains = domain_ptr;
            entry.domain_count = domains.len();
        }

        (*result).entries = entries_ptr;
        (*result).count = num_codes;
        (*result).error_code = crate::ffi::FFI_OK;
        (*result)._owned_data = owned_data_ptr;
        crate::ffi::FFI_OK
    })
}

/// Free a GeoSiteResult (including all domain data).
///
/// # Safety
/// `result` must be from `xray_geosite_load`.
#[no_mangle]
pub unsafe extern "C" fn xray_geosite_result_free(result: *mut GeoSiteResult) {
    ffi_catch_void!({
        if result.is_null() {
            return;
        }
        let r = &*result;
        if !r.entries.is_null() && r.count > 0 {
            for i in 0..r.count {
                let entry = &*r.entries.add(i);
                if !entry.domains.is_null() && entry.domain_count > 0 {
                    if let Ok(layout) =
                        std::alloc::Layout::array::<GeoSiteDomain>(entry.domain_count)
                    {
                        std::alloc::dealloc(entry.domains as *mut u8, layout);
                    }
                }
            }
            if let Ok(entries_layout) = std::alloc::Layout::array::<GeoSiteCodeResult>(r.count) {
                std::alloc::dealloc(r.entries as *mut u8, entries_layout);
            }
        }
        if !r._owned_data.is_null() {
            drop(Box::from_raw(r._owned_data));
        }
        (*result).entries = std::ptr::null_mut();
        (*result).count = 0;
        (*result)._owned_data = std::ptr::null_mut();
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_varint() {
        assert_eq!(decode_varint(&[0x00]), Some((0, 1)));
        assert_eq!(decode_varint(&[0x01]), Some((1, 1)));
        assert_eq!(decode_varint(&[0x7F]), Some((127, 1)));
        assert_eq!(decode_varint(&[0x80, 0x01]), Some((128, 2)));
        assert_eq!(decode_varint(&[0xAC, 0x02]), Some((300, 2)));
    }

    #[test]
    fn test_parse_cidr() {
        // Manually construct a CIDR protobuf: ip=192.168.0.0, prefix=16
        // Field 1 (bytes): tag=0x0A, len=4, data=[192,168,0,0]
        // Field 2 (varint): tag=0x10, value=16
        let data = [0x0A, 0x04, 192, 168, 0, 0, 0x10, 16];
        let cidr = parse_cidr(&data).unwrap();
        assert_eq!(cidr.ip, &[192, 168, 0, 0]);
        assert_eq!(cidr.prefix, 16);
    }

    #[test]
    fn test_parse_domain() {
        // Field 1 (varint): tag=0x08, value=3 (Full)
        // Field 2 (string): tag=0x12, len=11, "example.com"
        let mut data = vec![0x08, 0x03, 0x12, 0x0B];
        data.extend_from_slice(b"example.com");
        let (dtype, value) = parse_domain(&data).unwrap();
        assert_eq!(dtype, 3);
        assert_eq!(value, "example.com");
    }

    #[test]
    fn test_synthetic_geoip() {
        // Build a synthetic GeoIPList with 2 entries:
        // Entry 1: code="US", cidr=[10.0.0.0/8]
        // Entry 2: code="CN", cidr=[172.16.0.0/12]

        fn encode_varint(val: u64) -> Vec<u8> {
            let mut buf = Vec::new();
            let mut v = val;
            loop {
                if v < 0x80 {
                    buf.push(v as u8);
                    break;
                }
                buf.push((v as u8 & 0x7F) | 0x80);
                v >>= 7;
            }
            buf
        }

        fn encode_bytes(field: u32, data: &[u8]) -> Vec<u8> {
            let tag = (field << 3) | 2;
            let mut buf = encode_varint(tag as u64);
            buf.extend(encode_varint(data.len() as u64));
            buf.extend(data);
            buf
        }

        fn encode_varint_field(field: u32, val: u64) -> Vec<u8> {
            let tag = (field << 3) | 0;
            let mut buf = encode_varint(tag as u64);
            buf.extend(encode_varint(val));
            buf
        }

        // CIDR: 10.0.0.0/8
        let mut cidr1 = encode_bytes(1, &[10, 0, 0, 0]);
        cidr1.extend(encode_varint_field(2, 8));

        // GeoIP: code="US", cidr=[10.0.0.0/8]
        let mut entry1 = encode_bytes(1, b"US");
        entry1.extend(encode_bytes(2, &cidr1));

        // CIDR: 172.16.0.0/12
        let mut cidr2 = encode_bytes(1, &[172, 16, 0, 0]);
        cidr2.extend(encode_varint_field(2, 12));

        // GeoIP: code="CN", cidr=[172.16.0.0/12]
        let mut entry2 = encode_bytes(1, b"CN");
        entry2.extend(encode_bytes(2, &cidr2));

        // GeoIPList: entry=[entry1, entry2]
        let mut geoip_list = encode_bytes(1, &entry1);
        geoip_list.extend(encode_bytes(1, &entry2));

        // Parse requesting only "US"
        let result = parse_geoip_list(&geoip_list, &["US".to_string()]);
        assert_eq!(result.len(), 1);
        assert!(result.contains_key("US"));

        let us_ipset = result.get("US").unwrap();
        assert!(us_ipset.contains_ip(&[10, 0, 0, 1]));
        assert!(us_ipset.contains_ip(&[10, 255, 255, 255]));
        assert!(!us_ipset.contains_ip(&[172, 16, 0, 1]));

        // Parse requesting both
        let result = parse_geoip_list(&geoip_list, &["US".to_string(), "CN".to_string()]);
        assert_eq!(result.len(), 2);

        let cn_ipset = result.get("CN").unwrap();
        assert!(cn_ipset.contains_ip(&[172, 16, 0, 1]));
        assert!(cn_ipset.contains_ip(&[172, 31, 255, 255]));
        assert!(!cn_ipset.contains_ip(&[172, 32, 0, 1]));
    }

    #[test]
    fn test_synthetic_geosite() {
        fn encode_varint(val: u64) -> Vec<u8> {
            let mut buf = Vec::new();
            let mut v = val;
            loop {
                if v < 0x80 {
                    buf.push(v as u8);
                    break;
                }
                buf.push((v as u8 & 0x7F) | 0x80);
                v >>= 7;
            }
            buf
        }

        fn encode_bytes(field: u32, data: &[u8]) -> Vec<u8> {
            let tag = (field << 3) | 2;
            let mut buf = encode_varint(tag as u64);
            buf.extend(encode_varint(data.len() as u64));
            buf.extend(data);
            buf
        }

        fn encode_varint_field(field: u32, val: u64) -> Vec<u8> {
            let tag = (field << 3) | 0;
            let mut buf = encode_varint(tag as u64);
            buf.extend(encode_varint(val));
            buf
        }

        // Domain: type=Full(3), value="google.com"
        let mut dom1 = encode_varint_field(1, 3);
        dom1.extend(encode_bytes(2, b"google.com"));

        // Domain: type=Domain(2), value="youtube.com"
        let mut dom2 = encode_varint_field(1, 2);
        dom2.extend(encode_bytes(2, b"youtube.com"));

        // GeoSite: code="GOOGLE", domains=[dom1, dom2]
        let mut entry = encode_bytes(1, b"GOOGLE");
        entry.extend(encode_bytes(2, &dom1));
        entry.extend(encode_bytes(2, &dom2));

        // GeoSiteList
        let geosite_list = encode_bytes(1, &entry);

        let result = parse_geosite_list(&geosite_list, &["GOOGLE".to_string()]);
        assert_eq!(result.len(), 1);

        let domains = result.get("GOOGLE").unwrap();
        assert_eq!(domains.len(), 2);
        assert_eq!(domains[0], (3, "google.com".to_string()));
        assert_eq!(domains[1], (2, "youtube.com".to_string()));
    }
}
