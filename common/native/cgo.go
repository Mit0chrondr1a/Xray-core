//go:build cgo && linux

package native

/*
#cgo LDFLAGS: -L${SRCDIR}/../../rust/xray-rust/target/release -lxray_rust
#cgo linux LDFLAGS: -lm -lpthread -lunwind

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

// TLS result struct (must match Rust's XrayTlsResult exactly)
struct xray_tls_result {
    bool     ktls_tx;
    bool     ktls_rx;
    uint16_t version;
    uint16_t cipher_suite;
    uint8_t  alpn[32];
    void*    state_handle;
    int32_t  error_code;
    uint8_t  deferred_handle_ownership;
    char     error_msg[256];
    uint8_t  tx_secret[48];
    uint8_t  rx_secret[48];
    uint8_t  secret_len;
    uint8_t* drained_ptr;
    uint32_t drained_len;
    uint64_t rx_seq_start;
};

// TLS config builder
extern void*   xray_tls_config_new(bool is_server);
extern void    xray_tls_config_set_server_name(void* cfg, const uint8_t* name, size_t len);
extern int32_t xray_tls_config_add_cert_pem(void* cfg, const uint8_t* cert, size_t cert_len, const uint8_t* key, size_t key_len);
extern int32_t xray_tls_config_add_root_ca_pem(void* cfg, const uint8_t* ca, size_t len);
extern void    xray_tls_config_use_system_roots(void* cfg);
extern void    xray_tls_config_set_alpn(void* cfg, const uint8_t* protos, size_t len);
extern void    xray_tls_config_set_versions(void* cfg, uint16_t min_ver, uint16_t max_ver);
extern void    xray_tls_config_set_insecure_skip_verify(void* cfg, bool skip);
extern void    xray_tls_config_pin_cert_sha256(void* cfg, const uint8_t* hash, size_t hash_len);
extern void    xray_tls_config_add_verify_name(void* cfg, const uint8_t* name, size_t name_len);
extern void    xray_tls_config_set_key_log_path(void* cfg, const uint8_t* path, size_t path_len);
extern void    xray_tls_config_free(void* cfg);

// TLS handshake + kTLS
extern int32_t xray_tls_handshake(int fd, const void* cfg, bool is_client, uint32_t handshake_timeout_ms, struct xray_tls_result* out);
extern int32_t xray_tls_handshake_into(int fd, const void* cfg, bool is_client, uint32_t handshake_timeout_ms, struct xray_tls_result* out, uint8_t* drained_buf, size_t drained_cap);
extern int32_t xray_tls_key_update(void* state_handle);
extern void    xray_tls_state_free(void* state_handle);
extern void    xray_tls_drained_free(uint8_t* ptr, size_t len);

// REALITY config builder
extern void*   xray_reality_config_new(bool is_client);
extern void    xray_reality_config_set_server_pubkey(void* cfg, const uint8_t* key, size_t len);
extern void    xray_reality_config_set_short_id(void* cfg, const uint8_t* id, size_t len);
extern void    xray_reality_config_set_mldsa65_verify(void* cfg, const uint8_t* key, size_t len);
extern void    xray_reality_config_set_version(void* cfg, uint8_t x, uint8_t y, uint8_t z);
extern void    xray_reality_config_free(void* cfg);
extern void    xray_reality_config_set_private_key(void* cfg, const uint8_t* key, size_t len);
extern void    xray_reality_config_set_server_names(void* cfg, const uint8_t* data, size_t len);
extern void    xray_reality_config_set_short_ids(void* cfg, const uint8_t* data, size_t len);
extern void    xray_reality_config_set_mldsa65_key(void* cfg, const uint8_t* key, size_t len);
extern void    xray_reality_config_set_dest(void* cfg, const uint8_t* addr, size_t len);
extern void    xray_reality_config_set_max_time_diff(void* cfg, uint64_t ms);
extern void    xray_reality_config_set_version_range(void* cfg, uint8_t min_x, uint8_t min_y, uint8_t min_z, uint8_t max_x, uint8_t max_y, uint8_t max_z);
extern void    xray_reality_config_set_tls_cert(void* cfg, const uint8_t* cert, size_t cert_len, const uint8_t* key, size_t key_len);

extern void    xray_reality_config_add_short_id(void* cfg, const uint8_t* id, size_t len);

// REALITY handshake
extern int32_t xray_reality_client_connect(int fd, const uint8_t* client_hello_raw, size_t hello_len, const uint8_t* ecdh_privkey, size_t privkey_len, const void* reality_config, struct xray_tls_result* out);
extern int32_t xray_reality_server_accept(int fd, const void* reality_config, struct xray_tls_result* out);
extern int32_t xray_reality_server_handshake(int fd, const void* reality_config, uint32_t handshake_timeout_ms, struct xray_tls_result* out);
extern int32_t xray_reality_server_handshake_into(int fd, const void* reality_config, uint32_t handshake_timeout_ms, struct xray_tls_result* out, uint8_t* drained_buf, size_t drained_cap);

// Deferred REALITY handshake (no kTLS install)
struct xray_deferred_result {
    void*    handle;
    uint16_t version;
    uint16_t cipher_suite;
    uint8_t  alpn[32];
    uint8_t  sni[256];
    int32_t  error_code;
    char     error_msg[256];
};

extern int32_t xray_reality_server_deferred(int fd, const void* reality_config, uint32_t handshake_timeout_ms, struct xray_deferred_result* out);
extern int32_t xray_tls_server_deferred(int fd, const void* cfg, uint32_t handshake_timeout_ms, struct xray_deferred_result* out);
extern int32_t xray_deferred_read(void* handle, uint8_t* buf, size_t len, size_t* out_n);
extern int32_t xray_deferred_write(void* handle, const uint8_t* buf, size_t len, size_t* out_n);
extern int32_t xray_deferred_drain_and_detach(void* handle, uint8_t** out_plaintext_ptr, size_t* out_plaintext_len, uint8_t** out_raw_ptr, size_t* out_raw_len);
extern int32_t xray_deferred_drain_and_detach_into(
    void* handle,
    uint8_t* plaintext_buf, size_t plaintext_cap, size_t* out_plaintext_len, uint8_t** out_plaintext_ptr,
    uint8_t* raw_buf, size_t raw_cap, size_t* out_raw_len, uint8_t** out_raw_ptr
);
extern int32_t xray_deferred_enable_ktls(void* handle, struct xray_tls_result* out);
extern int32_t xray_deferred_enable_ktls_into(void* handle, struct xray_tls_result* out, uint8_t* drained_buf, size_t drained_cap);
extern int32_t xray_deferred_restore_nonblock(void* handle);
extern void    xray_deferred_free(void* handle);

// Blake3
extern void xray_blake3_derive_key(uint8_t* out, size_t out_len,
    const uint8_t* ctx, size_t ctx_len,
    const uint8_t* key, size_t key_len);
extern void xray_blake3_sum256(uint8_t* out,
    const uint8_t* data, size_t data_len);
extern void xray_blake3_keyed_hash(uint8_t* out, size_t out_len,
    const uint8_t* key,
    const uint8_t* data, size_t data_len);

// MPH
extern void* xray_mph_new();
extern void xray_mph_add_pattern(void* table,
    const uint8_t* pattern, size_t pattern_len, uint8_t pattern_type);
extern void xray_mph_build(void* table);
extern bool xray_mph_match(const void* table,
    const uint8_t* input, size_t input_len);
extern void xray_mph_free(void* table);

// GeoIP
extern void* xray_ipset_new();
extern void xray_ipset_add_prefix(void* ipset,
    const uint8_t* ip_bytes, size_t ip_len, uint8_t prefix_bits);
extern void xray_ipset_build(void* ipset);
extern bool xray_ipset_contains(const void* ipset,
    const uint8_t* ip_bytes, size_t ip_len);
extern uint8_t xray_ipset_max4(const void* ipset);
extern uint8_t xray_ipset_max6(const void* ipset);
extern void xray_ipset_free(void* ipset);

// Vision padding/unpadding
struct xray_vision_unpad_state {
    int32_t remaining_command;
    int32_t remaining_content;
    int32_t remaining_padding;
    int32_t current_command;
};

extern int32_t xray_vision_pad(
    const uint8_t* data, uint32_t data_len,
    uint8_t command,
    const uint8_t* uuid,
    bool long_padding,
    const uint32_t* testseed,
    uint8_t* out_buf, uint32_t out_cap
);

extern int32_t xray_vision_unpad(
    const uint8_t* data, uint32_t data_len,
    struct xray_vision_unpad_state* state,
    const uint8_t* uuid, uint32_t uuid_len,
    uint8_t* out_buf, uint32_t out_cap
);

// Vision TLS filter state (must match Rust's VisionFilterState layout)
struct xray_vision_filter_state {
    int32_t  remaining_server_hello;
    int32_t  number_of_packets_to_filter;
    uint16_t cipher;
    bool     is_tls;
    bool     is_tls12_or_above;
    bool     enable_xtls;
};

extern int32_t xray_vision_filter_tls(
    const uint8_t* data, uint32_t data_len,
    struct xray_vision_filter_state* state
);

extern int32_t xray_vision_is_complete_record(
    const uint8_t* data, uint32_t data_len
);

// AEAD cipher handles
extern void* xray_aead_new(uint8_t algo, const uint8_t* key, size_t key_len);
extern int32_t xray_aead_seal(const void* handle, const uint8_t* nonce, size_t nonce_len, const uint8_t* aad, size_t aad_len, const uint8_t* pt, size_t pt_len, uint8_t* out, size_t out_cap, size_t* out_len);
extern int32_t xray_aead_open(const void* handle, const uint8_t* nonce, size_t nonce_len, const uint8_t* aad, size_t aad_len, const uint8_t* ct, size_t ct_len, uint8_t* out, size_t out_cap, size_t* out_len);
extern int32_t xray_aead_overhead(const void* handle);
extern int32_t xray_aead_nonce_size(const void* handle);
extern void xray_aead_free(void* handle);

// VMess AEAD header seal/open
extern int32_t xray_vmess_seal_header(const uint8_t* cmd_key, const uint8_t* header, size_t header_len, uint8_t* out, size_t out_cap, size_t* out_len);
extern int32_t xray_vmess_open_header(const uint8_t* cmd_key, const uint8_t* authid, const uint8_t* data, size_t data_len, uint8_t* out, size_t out_cap, size_t* out_len);

// Geodata batch loading
struct xray_geoip_result {
    void** handles;
    size_t count;
    int32_t error_code;
};

struct xray_geosite_domain {
    uint8_t domain_type;
    const uint8_t* value;
    size_t value_len;
};

struct xray_geosite_code_result {
    struct xray_geosite_domain* domains;
    size_t domain_count;
};

struct xray_geosite_result {
    struct xray_geosite_code_result* entries;
    size_t count;
    int32_t error_code;
    void* _owned_data;
};

extern int32_t xray_geoip_load(const uint8_t* path, size_t path_len, const uint8_t** codes, const size_t* code_lens, size_t num_codes, struct xray_geoip_result* result);
extern void xray_geoip_result_free(struct xray_geoip_result* result);
extern int32_t xray_geosite_load(const uint8_t* path, size_t path_len, const uint8_t** codes, const size_t* code_lens, size_t num_codes, struct xray_geosite_result* result);
extern void xray_geosite_result_free(struct xray_geosite_result* result);

	// eBPF sockmap management
	extern int32_t xray_ebpf_available();
	extern int32_t xray_ebpf_setup(const char* pin_path, uint32_t max_entries, uint32_t cork_threshold);
	extern int32_t xray_ebpf_teardown();
	extern uint32_t xray_ebpf_max_entries();
	extern int32_t xray_ebpf_register_pair(int32_t inbound_fd, int32_t outbound_fd, uint64_t inbound_cookie, uint64_t outbound_cookie, uint32_t policy_flags);
	extern int32_t xray_ebpf_unregister_pair(uint64_t inbound_cookie, uint64_t outbound_cookie);

	// Pipeline capability summary
	struct xray_capability_summary {
	    bool ktls_supported;
	    bool sockmap_supported;
	    bool splice_supported;
	};
	extern int32_t xray_capabilities_summary(struct xray_capability_summary* out);
*/
import "C"

import (
	"errors"
	"fmt"
	"io"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf8"
	"unsafe"

	"github.com/xtls/xray-core/common/pipeline"
	"lukechampine.com/blake3"
)

func init() {
	if got, want := unsafe.Sizeof(VisionFilterState{}), VisionFilterStateSizeC(); got != want {
		panic("native: VisionFilterState size mismatch: Go=" + fmt.Sprint(got) + " C=" + fmt.Sprint(want))
	}
}

// Available reports whether the native Rust implementations are linked.
func Available() bool {
	return true
}

// CapabilitiesSummary fetches the cached capability view from Rust (one-shot probe later).
func CapabilitiesSummary() pipeline.CapabilitySummary {
	var out C.struct_xray_capability_summary
	rc := C.xray_capabilities_summary(&out)
	if rc != 0 {
		return pipeline.CapabilitySummary{SpliceSupported: true}
	}
	return pipeline.CapabilitySummary{
		KTLSSupported:    bool(out.ktls_supported),
		SockmapSupported: bool(out.sockmap_supported),
		SpliceSupported:  bool(out.splice_supported),
	}
}

// EbpfAvailable reports whether Rust eBPF bytecode support is compiled in.
func EbpfAvailable() bool {
	return C.xray_ebpf_available() != 0
}

// ErrRealityAuthFailed indicates REALITY auth failed and Go should handle fallback.
var ErrRealityAuthFailed = errors.New("REALITY auth failed: needs fallback")

// ErrRealityDeferredPeekTimeout indicates deferred REALITY failed during the
// pre-auth MSG_PEEK phase and callers may safely fall back to Go REALITY.
var ErrRealityDeferredPeekTimeout = errors.New("REALITY deferred peek timeout: needs fallback")

const defaultNativeHandshakeTimeout = 30 * time.Second

func isRealityDeferredPeekTimeoutMsg(msg string) bool {
	m := strings.ToLower(msg)
	return strings.Contains(m, "peek_exact: receive timeout") ||
		strings.Contains(m, "peek_exact: handshake timeout exceeded") ||
		strings.Contains(m, "peek_exact: short read after")
}

// IsRealityDeferredPeekTimeout reports whether err represents a deferred
// REALITY pre-auth MSG_PEEK timeout/short-read condition.
func IsRealityDeferredPeekTimeout(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrRealityDeferredPeekTimeout) {
		return true
	}
	return isRealityDeferredPeekTimeoutMsg(err.Error())
}

func timeoutMillis(timeout time.Duration) C.uint32_t {
	if timeout <= 0 {
		timeout = defaultNativeHandshakeTimeout
	}
	ms := uint64(timeout / time.Millisecond)
	if ms == 0 {
		ms = 1
	}
	if ms > uint64(^uint32(0)) {
		ms = uint64(^uint32(0))
	}
	return C.uint32_t(ms)
}

func cleanupTLSResultOnError(cResult *C.struct_xray_tls_result) {
	if cResult == nil {
		return
	}
	if cResult.state_handle != nil {
		C.xray_tls_state_free(cResult.state_handle)
		cResult.state_handle = nil
	}
	if cResult.drained_ptr != nil {
		C.xray_tls_drained_free(cResult.drained_ptr, C.size_t(cResult.drained_len))
		cResult.drained_ptr = nil
		cResult.drained_len = 0
	}
}

func cleanupDeferredResultOnError(cResult *C.struct_xray_deferred_result) {
	if cResult == nil {
		return
	}
	if cResult.handle != nil {
		C.xray_deferred_free(cResult.handle)
		cResult.handle = nil
	}
}

// emptyCodeSentinel is a non-null address for empty country-code entries
// in GeoIP/GeoSite FFI arrays, preventing UB from NULL in from_raw_parts.
var emptyCodeSentinel byte

const deferredDrainInlineCap = 4 * 1024
const tlsResultDrainedInlineCap = 4 * 1024

// --- TLS Types ---

// TlsConfigHandle is an opaque handle to a Rust TLS config.
type TlsConfigHandle struct {
	ptr unsafe.Pointer
}

// TlsStateHandle is an opaque handle to a Rust TLS state (for KeyUpdate).
type TlsStateHandle struct {
	ptr unsafe.Pointer
}

// DeferredHandleOwnership reports whether xray_deferred_enable_ktls consumed
// the deferred session handle or returned it still live for fallback.
type DeferredHandleOwnership uint8

const (
	DeferredHandleOwnershipUnknown DeferredHandleOwnership = iota
	DeferredHandleOwnershipConsumed
	DeferredHandleOwnershipRetained
)

// TlsResult contains the result of a TLS handshake.
type TlsResult struct {
	KtlsTx                  bool
	KtlsRx                  bool
	Version                 uint16
	CipherSuite             uint16
	ALPN                    string
	RxSeqStart              uint64
	StateHandle             *TlsStateHandle
	DeferredHandleOwnership DeferredHandleOwnership // set by deferred enable_ktls path
	TxSecret                []byte                  // base traffic secret for KeyUpdate (TLS 1.3 only)
	RxSecret                []byte                  // base traffic secret for KeyUpdate (TLS 1.3 only)
	DrainedData             []byte                  // plaintext drained from rustls after handshake
}

// ZeroSecrets zeroes the traffic secret fields after they have been copied.
//
//go:noinline
func (r *TlsResult) ZeroSecrets() {
	for i := range r.TxSecret {
		r.TxSecret[i] = 0
	}
	for i := range r.RxSecret {
		r.RxSecret[i] = 0
	}
	r.TxSecret = nil
	r.RxSecret = nil
}

// --- TLS Config Builder ---

func TlsConfigNew(isServer bool) *TlsConfigHandle {
	ptr := C.xray_tls_config_new(C.bool(isServer))
	if ptr == nil {
		return nil
	}
	h := &TlsConfigHandle{ptr: ptr}
	runtime.SetFinalizer(h, (*TlsConfigHandle).release)
	return h
}

func (h *TlsConfigHandle) release() {
	TlsConfigFree(h)
}

func TlsConfigSetServerName(h *TlsConfigHandle, name string) {
	if h == nil || len(name) == 0 {
		return
	}
	nameBytes := []byte(name)
	if len(nameBytes) == 0 {
		return
	}
	C.xray_tls_config_set_server_name(h.ptr, (*C.uint8_t)(unsafe.Pointer(&nameBytes[0])), C.size_t(len(nameBytes)))
	runtime.KeepAlive(nameBytes)
	runtime.KeepAlive(h)
}

func TlsConfigAddCertPEM(h *TlsConfigHandle, certPEM, keyPEM []byte) error {
	if h == nil || len(certPEM) == 0 || len(keyPEM) == 0 {
		return errors.New("native: nil handle or empty cert/key")
	}
	rc := C.xray_tls_config_add_cert_pem(h.ptr,
		(*C.uint8_t)(unsafe.Pointer(&certPEM[0])), C.size_t(len(certPEM)),
		(*C.uint8_t)(unsafe.Pointer(&keyPEM[0])), C.size_t(len(keyPEM)))
	runtime.KeepAlive(certPEM)
	runtime.KeepAlive(keyPEM)
	runtime.KeepAlive(h)
	if rc != 0 {
		return errors.New("native: failed to add cert PEM")
	}
	return nil
}

func TlsConfigAddRootCAPEM(h *TlsConfigHandle, caPEM []byte) error {
	if h == nil || len(caPEM) == 0 {
		return errors.New("native: nil handle or empty CA PEM")
	}
	rc := C.xray_tls_config_add_root_ca_pem(h.ptr, (*C.uint8_t)(unsafe.Pointer(&caPEM[0])), C.size_t(len(caPEM)))
	runtime.KeepAlive(caPEM)
	runtime.KeepAlive(h)
	if rc != 0 {
		return errors.New("native: failed to add root CA PEM")
	}
	return nil
}

func TlsConfigUseSystemRoots(h *TlsConfigHandle) {
	if h == nil {
		return
	}
	C.xray_tls_config_use_system_roots(h.ptr)
	runtime.KeepAlive(h)
}

func TlsConfigSetALPN(h *TlsConfigHandle, protos []byte) {
	if h == nil || len(protos) == 0 {
		return
	}
	C.xray_tls_config_set_alpn(h.ptr, (*C.uint8_t)(unsafe.Pointer(&protos[0])), C.size_t(len(protos)))
	runtime.KeepAlive(protos)
	runtime.KeepAlive(h)
}

func TlsConfigSetVersions(h *TlsConfigHandle, minVer, maxVer uint16) {
	if h == nil {
		return
	}
	C.xray_tls_config_set_versions(h.ptr, C.uint16_t(minVer), C.uint16_t(maxVer))
	runtime.KeepAlive(h)
}

func TlsConfigSetInsecureSkipVerify(h *TlsConfigHandle, skip bool) {
	if h == nil {
		return
	}
	C.xray_tls_config_set_insecure_skip_verify(h.ptr, C.bool(skip))
	runtime.KeepAlive(h)
}

func TlsConfigPinCertSHA256(h *TlsConfigHandle, hash []byte) {
	if h == nil || len(hash) == 0 {
		return
	}
	C.xray_tls_config_pin_cert_sha256(h.ptr, (*C.uint8_t)(unsafe.Pointer(&hash[0])), C.size_t(len(hash)))
	runtime.KeepAlive(hash)
	runtime.KeepAlive(h)
}

func TlsConfigAddVerifyName(h *TlsConfigHandle, name string) {
	if h == nil {
		return
	}
	nameBytes := []byte(name)
	if len(nameBytes) == 0 {
		return
	}
	C.xray_tls_config_add_verify_name(h.ptr, (*C.uint8_t)(unsafe.Pointer(&nameBytes[0])), C.size_t(len(nameBytes)))
	runtime.KeepAlive(nameBytes)
	runtime.KeepAlive(h)
}

func TlsConfigSetKeyLogPath(h *TlsConfigHandle, path string) {
	if h == nil {
		return
	}
	pathBytes := []byte(path)
	if len(pathBytes) == 0 {
		return
	}
	C.xray_tls_config_set_key_log_path(h.ptr, (*C.uint8_t)(unsafe.Pointer(&pathBytes[0])), C.size_t(len(pathBytes)))
	runtime.KeepAlive(pathBytes)
	runtime.KeepAlive(h)
}

func TlsConfigFree(h *TlsConfigHandle) {
	if h == nil {
		return
	}
	runtime.SetFinalizer(h, nil)
	ptr := atomic.SwapPointer(&h.ptr, nil)
	if ptr != nil {
		C.xray_tls_config_free(ptr)
	}
}

// --- TLS Handshake ---

func TlsHandshake(fd int, cfg *TlsConfigHandle, isClient bool) (*TlsResult, error) {
	return TlsHandshakeWithTimeout(fd, cfg, isClient, defaultNativeHandshakeTimeout)
}

func TlsHandshakeWithTimeout(fd int, cfg *TlsConfigHandle, isClient bool, handshakeTimeout time.Duration) (*TlsResult, error) {
	if cfg == nil {
		return nil, errors.New("native: nil config handle")
	}
	var drainedInline [tlsResultDrainedInlineCap]byte
	var cResult C.struct_xray_tls_result
	rc := C.xray_tls_handshake_into(
		C.int(fd),
		cfg.ptr,
		C.bool(isClient),
		timeoutMillis(handshakeTimeout),
		&cResult,
		(*C.uint8_t)(unsafe.Pointer(&drainedInline[0])),
		C.size_t(tlsResultDrainedInlineCap),
	)
	runtime.KeepAlive(cfg)
	runtime.KeepAlive(drainedInline)
	if rc != 0 {
		cleanupTLSResultOnError(&cResult)
		errMsg := C.GoString(&cResult.error_msg[0])
		return nil, errors.New("native TLS handshake: " + errMsg)
	}
	return extractTlsResultWithInline(&cResult, drainedInline[:]), nil
}

func TlsKeyUpdate(h *TlsStateHandle) error {
	if h == nil {
		return errors.New("native: nil state handle")
	}
	rc := C.xray_tls_key_update(h.ptr)
	runtime.KeepAlive(h)
	if rc != 0 {
		return errors.New("native: key update failed")
	}
	return nil
}

func TlsStateFree(h *TlsStateHandle) {
	if h == nil {
		return
	}
	runtime.SetFinalizer(h, nil)
	ptr := atomic.SwapPointer(&h.ptr, nil)
	if ptr != nil {
		C.xray_tls_state_free(ptr)
	}
}

func (h *TlsStateHandle) release() {
	TlsStateFree(h)
}

// --- REALITY Types ---

type RealityConfigHandle struct {
	ptr unsafe.Pointer
}

// --- REALITY Config Builder ---

func RealityConfigNew(isClient bool) *RealityConfigHandle {
	ptr := C.xray_reality_config_new(C.bool(isClient))
	if ptr == nil {
		return nil
	}
	h := &RealityConfigHandle{ptr: ptr}
	runtime.SetFinalizer(h, (*RealityConfigHandle).release)
	return h
}

func (h *RealityConfigHandle) release() {
	RealityConfigFree(h)
}

func RealityConfigSetServerPubkey(h *RealityConfigHandle, key []byte) {
	if h == nil || len(key) == 0 {
		return
	}
	C.xray_reality_config_set_server_pubkey(h.ptr, (*C.uint8_t)(unsafe.Pointer(&key[0])), C.size_t(len(key)))
	runtime.KeepAlive(key)
	runtime.KeepAlive(h)
}

func RealityConfigSetShortId(h *RealityConfigHandle, id []byte) {
	if h == nil || len(id) == 0 {
		return
	}
	C.xray_reality_config_set_short_id(h.ptr, (*C.uint8_t)(unsafe.Pointer(&id[0])), C.size_t(len(id)))
	runtime.KeepAlive(id)
	runtime.KeepAlive(h)
}

func RealityConfigSetMldsa65Verify(h *RealityConfigHandle, key []byte) {
	if h == nil || len(key) == 0 {
		return
	}
	C.xray_reality_config_set_mldsa65_verify(h.ptr, (*C.uint8_t)(unsafe.Pointer(&key[0])), C.size_t(len(key)))
	runtime.KeepAlive(key)
	runtime.KeepAlive(h)
}

func RealityConfigSetVersion(h *RealityConfigHandle, x, y, z uint8) {
	if h == nil {
		return
	}
	C.xray_reality_config_set_version(h.ptr, C.uint8_t(x), C.uint8_t(y), C.uint8_t(z))
	runtime.KeepAlive(h)
}

func RealityConfigFree(h *RealityConfigHandle) {
	if h == nil {
		return
	}
	runtime.SetFinalizer(h, nil)
	ptr := atomic.SwapPointer(&h.ptr, nil)
	if ptr != nil {
		C.xray_reality_config_free(ptr)
	}
}

func RealityConfigSetPrivateKey(h *RealityConfigHandle, key []byte) {
	if h == nil || len(key) == 0 {
		return
	}
	C.xray_reality_config_set_private_key(h.ptr, (*C.uint8_t)(unsafe.Pointer(&key[0])), C.size_t(len(key)))
	runtime.KeepAlive(key)
	runtime.KeepAlive(h)
}

func RealityConfigSetServerNames(h *RealityConfigHandle, data []byte) {
	if h == nil || len(data) == 0 {
		return
	}
	C.xray_reality_config_set_server_names(h.ptr, (*C.uint8_t)(unsafe.Pointer(&data[0])), C.size_t(len(data)))
	runtime.KeepAlive(data)
	runtime.KeepAlive(h)
}

func RealityConfigSetShortIds(h *RealityConfigHandle, data []byte) {
	if h == nil || len(data) == 0 {
		return
	}
	C.xray_reality_config_set_short_ids(h.ptr, (*C.uint8_t)(unsafe.Pointer(&data[0])), C.size_t(len(data)))
	runtime.KeepAlive(data)
	runtime.KeepAlive(h)
}

func RealityConfigSetMldsa65Key(h *RealityConfigHandle, key []byte) {
	if h == nil || len(key) == 0 {
		return
	}
	C.xray_reality_config_set_mldsa65_key(h.ptr, (*C.uint8_t)(unsafe.Pointer(&key[0])), C.size_t(len(key)))
	runtime.KeepAlive(key)
	runtime.KeepAlive(h)
}

func RealityConfigSetDest(h *RealityConfigHandle, addr string) {
	if h == nil {
		return
	}
	addrBytes := []byte(addr)
	if len(addrBytes) == 0 {
		return
	}
	C.xray_reality_config_set_dest(h.ptr, (*C.uint8_t)(unsafe.Pointer(&addrBytes[0])), C.size_t(len(addrBytes)))
	runtime.KeepAlive(addrBytes)
	runtime.KeepAlive(h)
}

func RealityConfigSetMaxTimeDiff(h *RealityConfigHandle, ms uint64) {
	if h == nil {
		return
	}
	C.xray_reality_config_set_max_time_diff(h.ptr, C.uint64_t(ms))
	runtime.KeepAlive(h)
}

func RealityConfigSetVersionRange(h *RealityConfigHandle, minX, minY, minZ, maxX, maxY, maxZ uint8) {
	if h == nil {
		return
	}
	C.xray_reality_config_set_version_range(h.ptr, C.uint8_t(minX), C.uint8_t(minY), C.uint8_t(minZ), C.uint8_t(maxX), C.uint8_t(maxY), C.uint8_t(maxZ))
	runtime.KeepAlive(h)
}

func RealityConfigSetTLSCert(h *RealityConfigHandle, certPEM, keyPEM []byte) {
	if h == nil || len(certPEM) == 0 || len(keyPEM) == 0 {
		return
	}
	C.xray_reality_config_set_tls_cert(h.ptr,
		(*C.uint8_t)(unsafe.Pointer(&certPEM[0])), C.size_t(len(certPEM)),
		(*C.uint8_t)(unsafe.Pointer(&keyPEM[0])), C.size_t(len(keyPEM)))
	runtime.KeepAlive(certPEM)
	runtime.KeepAlive(keyPEM)
	runtime.KeepAlive(h)
}

func RealityConfigAddShortId(h *RealityConfigHandle, id []byte) {
	if h == nil || len(id) == 0 {
		return
	}
	C.xray_reality_config_add_short_id(h.ptr, (*C.uint8_t)(unsafe.Pointer(&id[0])), C.size_t(len(id)))
	runtime.KeepAlive(id)
	runtime.KeepAlive(h)
}

// --- REALITY Handshake ---

func RealityClientConnect(fd int, clientHelloRaw []byte, ecdhPrivkey []byte, cfg *RealityConfigHandle) (*TlsResult, error) {
	if cfg == nil {
		return nil, errors.New("native: nil reality config handle")
	}
	if len(clientHelloRaw) == 0 {
		return nil, errors.New("native: empty client hello")
	}
	if len(ecdhPrivkey) != 32 {
		return nil, fmt.Errorf("native: invalid reality ecdh privkey length: got %d want 32", len(ecdhPrivkey))
	}
	var cResult C.struct_xray_tls_result
	rc := C.xray_reality_client_connect(
		C.int(fd),
		(*C.uint8_t)(unsafe.Pointer(&clientHelloRaw[0])), C.size_t(len(clientHelloRaw)),
		(*C.uint8_t)(unsafe.Pointer(&ecdhPrivkey[0])), C.size_t(len(ecdhPrivkey)),
		cfg.ptr,
		&cResult,
	)
	runtime.KeepAlive(clientHelloRaw)
	runtime.KeepAlive(ecdhPrivkey)
	runtime.KeepAlive(cfg)
	if rc != 0 {
		cleanupTLSResultOnError(&cResult)
		errMsg := C.GoString(&cResult.error_msg[0])
		code := int32(cResult.error_code)
		if code == 1 {
			return nil, fmt.Errorf("%w: %s", ErrRealityAuthFailed, errMsg)
		}
		return nil, errors.New("native REALITY: " + errMsg)
	}
	return extractTlsResult(&cResult), nil
}

func RealityServerAccept(fd int, cfg *RealityConfigHandle) (*TlsResult, error) {
	if cfg == nil {
		return nil, errors.New("native: nil reality config handle")
	}
	var cResult C.struct_xray_tls_result
	rc := C.xray_reality_server_accept(C.int(fd), cfg.ptr, &cResult)
	runtime.KeepAlive(cfg)
	if rc != 0 {
		cleanupTLSResultOnError(&cResult)
		errMsg := C.GoString(&cResult.error_msg[0])
		code := int32(cResult.error_code)
		if code == 1 {
			return nil, fmt.Errorf("%w: %s", ErrRealityAuthFailed, errMsg)
		}
		return nil, errors.New("native REALITY server: " + errMsg)
	}
	return extractTlsResult(&cResult), nil
}

func RealityServerHandshake(fd int, cfg *RealityConfigHandle) (*TlsResult, error) {
	return RealityServerHandshakeWithTimeout(fd, cfg, defaultNativeHandshakeTimeout)
}

func RealityServerHandshakeWithTimeout(fd int, cfg *RealityConfigHandle, handshakeTimeout time.Duration) (*TlsResult, error) {
	if cfg == nil {
		return nil, errors.New("native: nil reality config handle")
	}
	var drainedInline [tlsResultDrainedInlineCap]byte
	var cResult C.struct_xray_tls_result
	rc := C.xray_reality_server_handshake_into(
		C.int(fd),
		cfg.ptr,
		timeoutMillis(handshakeTimeout),
		&cResult,
		(*C.uint8_t)(unsafe.Pointer(&drainedInline[0])),
		C.size_t(tlsResultDrainedInlineCap),
	)
	runtime.KeepAlive(cfg)
	runtime.KeepAlive(drainedInline)
	if rc != 0 {
		cleanupTLSResultOnError(&cResult)
		errMsg := C.GoString(&cResult.error_msg[0])
		code := int32(cResult.error_code)
		if code == 1 {
			return nil, fmt.Errorf("%w: %s", ErrRealityAuthFailed, errMsg)
		}
		return nil, errors.New("native REALITY server handshake: " + errMsg)
	}
	return extractTlsResultWithInline(&cResult, drainedInline[:]), nil
}

// --- Deferred REALITY Session ---

// DeferredSessionHandle is an opaque handle to a Rust deferred REALITY session.
type DeferredSessionHandle struct {
	ptr unsafe.Pointer
}

// DeferredResult contains the result of a deferred REALITY handshake.
type DeferredResult struct {
	Handle      *DeferredSessionHandle
	Version     uint16
	CipherSuite uint16
	ALPN        string
	SNI         string
}

// RealityServerDeferred performs REALITY auth + handshake without installing kTLS.
// Returns a deferred session that supports Read/Write through rustls.
func RealityServerDeferred(fd int, cfg *RealityConfigHandle, timeout time.Duration) (*DeferredResult, error) {
	if cfg == nil {
		return nil, errors.New("native: nil reality config handle")
	}
	var cResult C.struct_xray_deferred_result
	rc := C.xray_reality_server_deferred(C.int(fd), cfg.ptr, timeoutMillis(timeout), &cResult)
	runtime.KeepAlive(cfg)
	if rc != 0 {
		cleanupDeferredResultOnError(&cResult)
		errMsg := C.GoString(&cResult.error_msg[0])
		code := int32(cResult.error_code)
		if code == 1 {
			return nil, fmt.Errorf("%w: %s", ErrRealityAuthFailed, errMsg)
		}
		if isRealityDeferredPeekTimeoutMsg(errMsg) {
			return nil, fmt.Errorf("%w: %s", ErrRealityDeferredPeekTimeout, errMsg)
		}
		return nil, errors.New("native REALITY deferred: " + errMsg)
	}

	result := &DeferredResult{
		Version:     uint16(cResult.version),
		CipherSuite: uint16(cResult.cipher_suite),
	}
	if cResult.handle != nil {
		result.Handle = &DeferredSessionHandle{ptr: cResult.handle}
	}

	// Extract ALPN (null-terminated string in 32-byte buffer)
	alpnBytes := C.GoBytes(unsafe.Pointer(&cResult.alpn[0]), 32)
	for i, b := range alpnBytes {
		if b == 0 {
			result.ALPN = string(alpnBytes[:i])
			break
		}
	}

	// Extract SNI (null-terminated string in 256-byte buffer)
	sniBytes := C.GoBytes(unsafe.Pointer(&cResult.sni[0]), 256)
	for i, b := range sniBytes {
		if b == 0 {
			result.SNI = string(sniBytes[:i])
			break
		}
	}

	return result, nil
}

// TlsServerDeferred performs a regular TLS server handshake via rustls without
// installing kTLS. Returns a deferred session (same type as REALITY deferred)
// that the protocol handler can later promote to kTLS or keep as rustls.
func TlsServerDeferred(fd int, cfg *TlsConfigHandle, timeout time.Duration) (*DeferredResult, error) {
	if cfg == nil {
		return nil, errors.New("native: nil TLS config handle")
	}
	var cResult C.struct_xray_deferred_result
	rc := C.xray_tls_server_deferred(C.int(fd), cfg.ptr, timeoutMillis(timeout), &cResult)
	runtime.KeepAlive(cfg)
	if rc != 0 {
		cleanupDeferredResultOnError(&cResult)
		errMsg := C.GoString(&cResult.error_msg[0])
		return nil, errors.New("native TLS server deferred: " + errMsg)
	}

	result := &DeferredResult{
		Version:     uint16(cResult.version),
		CipherSuite: uint16(cResult.cipher_suite),
	}
	if cResult.handle != nil {
		result.Handle = &DeferredSessionHandle{ptr: cResult.handle}
	}

	// Extract ALPN (null-terminated string in 32-byte buffer)
	alpnBytes := C.GoBytes(unsafe.Pointer(&cResult.alpn[0]), 32)
	for i, b := range alpnBytes {
		if b == 0 {
			result.ALPN = string(alpnBytes[:i])
			break
		}
	}

	// Extract SNI (null-terminated string in 256-byte buffer)
	sniBytes := C.GoBytes(unsafe.Pointer(&cResult.sni[0]), 256)
	for i, b := range sniBytes {
		if b == 0 {
			result.SNI = string(sniBytes[:i])
			break
		}
	}

	return result, nil
}

// DeferredRead reads decrypted data through the deferred session's rustls connection.
func DeferredRead(handle *DeferredSessionHandle, buf []byte) (int, error) {
	if handle == nil || handle.ptr == nil {
		return 0, errors.New("native: nil deferred session handle")
	}
	if len(buf) == 0 {
		return 0, nil
	}
	var outN C.size_t
	rc := C.xray_deferred_read(
		handle.ptr,
		(*C.uint8_t)(unsafe.Pointer(&buf[0])),
		C.size_t(len(buf)),
		&outN,
	)
	runtime.KeepAlive(handle)
	runtime.KeepAlive(buf)
	if rc != 0 {
		switch rc {
		case 1:
			return int(outN), io.EOF
		case 2:
			return int(outN), io.ErrClosedPipe
		default:
			return 0, errors.New("native: deferred read failed")
		}
	}
	return int(outN), nil
}

// DeferredWrite writes plaintext data through the deferred session's rustls connection.
func DeferredWrite(handle *DeferredSessionHandle, buf []byte) (int, error) {
	if handle == nil || handle.ptr == nil {
		return 0, errors.New("native: nil deferred session handle")
	}
	if len(buf) == 0 {
		return 0, nil
	}
	var outN C.size_t
	rc := C.xray_deferred_write(
		handle.ptr,
		(*C.uint8_t)(unsafe.Pointer(&buf[0])),
		C.size_t(len(buf)),
		&outN,
	)
	runtime.KeepAlive(handle)
	runtime.KeepAlive(buf)
	if rc != 0 {
		switch rc {
		case 1:
			return int(outN), io.EOF
		case 2:
			return int(outN), io.ErrClosedPipe
		default:
			return 0, io.ErrClosedPipe
		}
	}
	return int(outN), nil
}

// DeferredDrainAndDetach drains rustls buffered plaintext and raw read-ahead
// bytes from a deferred session, then detaches the rustls state from the
// socket. On success, the handle remains allocated but detached; callers should
// stop using it and switch to the raw socket.
func DeferredDrainAndDetach(handle *DeferredSessionHandle) ([]byte, []byte, error) {
	if handle == nil || handle.ptr == nil {
		return nil, nil, errors.New("native: nil deferred session handle")
	}
	var plaintextInline [deferredDrainInlineCap]byte
	var rawInline [deferredDrainInlineCap]byte
	var plaintextPtr *C.uint8_t
	var plaintextLen C.size_t
	var rawPtr *C.uint8_t
	var rawLen C.size_t
	rc := C.xray_deferred_drain_and_detach_into(
		handle.ptr,
		(*C.uint8_t)(unsafe.Pointer(&plaintextInline[0])),
		C.size_t(deferredDrainInlineCap),
		&plaintextLen,
		&plaintextPtr,
		(*C.uint8_t)(unsafe.Pointer(&rawInline[0])),
		C.size_t(deferredDrainInlineCap),
		&rawLen,
		&rawPtr,
	)
	runtime.KeepAlive(handle)
	runtime.KeepAlive(plaintextInline)
	runtime.KeepAlive(rawInline)
	if rc != 0 {
		// Defensive cleanup in case Rust returned partially populated outputs.
		if plaintextPtr != nil && plaintextLen > 0 {
			C.xray_tls_drained_free(plaintextPtr, plaintextLen)
		}
		if rawPtr != nil && rawLen > 0 {
			C.xray_tls_drained_free(rawPtr, rawLen)
		}
		return nil, nil, errors.New("native: deferred drain_and_detach failed")
	}
	var plaintext []byte
	if plaintextPtr != nil {
		plaintext = drainBytesFromNative(plaintextPtr, plaintextLen)
	} else if plaintextLen > 0 {
		if int(plaintextLen) > len(plaintextInline) {
			return nil, nil, errors.New("native: deferred drain_and_detach plaintext length overflow")
		}
		n := int(plaintextLen)
		plaintext = plaintextInline[:n:n]
	}

	var rawAhead []byte
	if rawPtr != nil {
		rawAhead = drainBytesFromNative(rawPtr, rawLen)
	} else if rawLen > 0 {
		if int(rawLen) > len(rawInline) {
			return nil, nil, errors.New("native: deferred drain_and_detach raw length overflow")
		}
		n := int(rawLen)
		rawAhead = rawInline[:n:n]
	}
	return plaintext, rawAhead, nil
}

// DeferredEnableKTLS attempts deferred kTLS installation.
// Ownership of handle.ptr is reported by Rust via deferred_handle_ownership:
// consumed => handle must no longer be used; retained => rustls fallback may continue.
func DeferredEnableKTLS(handle *DeferredSessionHandle) (*TlsResult, error) {
	if handle == nil || handle.ptr == nil {
		return nil, errors.New("native: nil deferred session handle")
	}
	ptr := handle.ptr
	var drainedInline [tlsResultDrainedInlineCap]byte
	var cResult C.struct_xray_tls_result
	rc := C.xray_deferred_enable_ktls_into(
		ptr,
		&cResult,
		(*C.uint8_t)(unsafe.Pointer(&drainedInline[0])),
		C.size_t(tlsResultDrainedInlineCap),
	)
	runtime.KeepAlive(drainedInline)
	ownership := DeferredHandleOwnership(cResult.deferred_handle_ownership)
	if rc != 0 {
		cleanupTLSResultOnError(&cResult)
		errMsg := C.GoString(&cResult.error_msg[0])
		if ownership != DeferredHandleOwnershipRetained {
			handle.ptr = nil
		}
		return nil, errors.New("native: deferred enable_ktls: " + errMsg)
	}
	result := extractTlsResultWithInline(&cResult, drainedInline[:])
	// Successful promotion always consumes deferred ownership in Go.
	handle.ptr = nil
	return result, nil
}

// DeferredHandleAlive reports whether the deferred session handle is still usable.
func DeferredHandleAlive(handle *DeferredSessionHandle) bool {
	return handle != nil && handle.ptr != nil
}

// DeferredRestoreNonBlock restores O_NONBLOCK on the deferred session's fd
// without detaching. After this call, Rust's reader/writer handle EAGAIN via
// poll(2), and Go can safely write to the raw socket without blocking.
func DeferredRestoreNonBlock(handle *DeferredSessionHandle) error {
	if handle == nil || handle.ptr == nil {
		return errors.New("native: nil deferred session handle")
	}
	rc := C.xray_deferred_restore_nonblock(handle.ptr)
	runtime.KeepAlive(handle)
	if rc != 0 {
		return errors.New("native: deferred restore_nonblock failed")
	}
	return nil
}

// DeferredFree releases a deferred session without enabling kTLS.
// Used for Vision flows where kTLS is not wanted.
func DeferredFree(handle *DeferredSessionHandle) {
	if handle == nil {
		return
	}
	ptr := handle.ptr
	handle.ptr = nil
	if ptr != nil {
		C.xray_deferred_free(ptr)
	}
}

func drainBytesFromNative(ptr *C.uint8_t, n C.size_t) []byte {
	if ptr == nil || n == 0 {
		return nil
	}
	if n > C.size_t(1<<30) {
		C.xray_tls_drained_free(ptr, n)
		return nil
	}
	out := C.GoBytes(unsafe.Pointer(ptr), C.int(n))
	C.xray_tls_drained_free(ptr, n)
	return out
}

// extractTlsResult populates a TlsResult from the C struct, extracting ALPN,
// state handle, secrets, and drained data. Consolidates duplicated extraction logic.
func extractTlsResult(cResult *C.struct_xray_tls_result) *TlsResult {
	return extractTlsResultWithInline(cResult, nil)
}

// extractTlsResultWithInline is extractTlsResult plus optional inline drained
// bytes that were written directly into a Go-owned buffer by Rust.
func extractTlsResultWithInline(cResult *C.struct_xray_tls_result, drainedInline []byte) *TlsResult {
	result := &TlsResult{
		KtlsTx:                  bool(cResult.ktls_tx),
		KtlsRx:                  bool(cResult.ktls_rx),
		Version:                 uint16(cResult.version),
		CipherSuite:             uint16(cResult.cipher_suite),
		RxSeqStart:              uint64(cResult.rx_seq_start),
		DeferredHandleOwnership: DeferredHandleOwnership(cResult.deferred_handle_ownership),
	}
	// Extract ALPN (null-terminated string in 32-byte buffer)
	alpnBytes := C.GoBytes(unsafe.Pointer(&cResult.alpn[0]), 32)
	for i, b := range alpnBytes {
		if b == 0 {
			result.ALPN = string(alpnBytes[:i])
			break
		}
	}
	if cResult.state_handle != nil {
		result.StateHandle = &TlsStateHandle{ptr: cResult.state_handle}
		runtime.SetFinalizer(result.StateHandle, (*TlsStateHandle).release)
	}
	extractSecrets(result, cResult)
	extractDrained(result, cResult, drainedInline)
	return result
}

// extractSecrets copies base traffic secrets from the C result to the Go TlsResult,
// then zeroes the C-side buffers to prevent secrets from lingering on the stack.
func extractSecrets(result *TlsResult, cResult *C.struct_xray_tls_result) {
	if secretLen := int(cResult.secret_len); secretLen > 0 {
		if secretLen > 48 {
			secretLen = 48 // cap to C array size
		}
		result.TxSecret = C.GoBytes(unsafe.Pointer(&cResult.tx_secret[0]), C.int(secretLen))
		result.RxSecret = C.GoBytes(unsafe.Pointer(&cResult.rx_secret[0]), C.int(secretLen))
		// Zero C-side secret buffers after copying to Go.
		for i := range cResult.tx_secret {
			cResult.tx_secret[i] = 0
		}
		for i := range cResult.rx_secret {
			cResult.rx_secret[i] = 0
		}
		cResult.secret_len = 0
	}
}

// extractDrained copies drained plaintext from the C result and frees the Rust buffer.
func extractDrained(result *TlsResult, cResult *C.struct_xray_tls_result, drainedInline []byte) {
	if cResult.drained_len == 0 {
		return
	}
	if cResult.drained_ptr == nil {
		if len(drainedInline) >= int(cResult.drained_len) {
			n := int(cResult.drained_len)
			result.DrainedData = drainedInline[:n:n]
		}
		return
	}
	if cResult.drained_len > 1<<30 {
		C.xray_tls_drained_free(cResult.drained_ptr, C.size_t(cResult.drained_len))
		cResult.drained_ptr = nil
		cResult.drained_len = 0
		return
	}
	result.DrainedData = C.GoBytes(unsafe.Pointer(cResult.drained_ptr), C.int(cResult.drained_len))
	C.xray_tls_drained_free(cResult.drained_ptr, C.size_t(cResult.drained_len))
	cResult.drained_ptr = nil
	cResult.drained_len = 0
}

// --- Blake3 ---

// Blake3DeriveKey derives a key using BLAKE3's KDF mode.
func Blake3DeriveKey(out []byte, ctx string, key []byte) {
	if len(out) == 0 {
		return
	}
	// Rust's blake3 derive_key API requires UTF-8 context; keep exact Go behavior for
	// binary contexts by falling back to the pure-Go implementation.
	if !utf8.ValidString(ctx) {
		blake3.DeriveKey(out, ctx, key)
		return
	}
	var ctxPtr *C.uint8_t
	if len(ctx) > 0 {
		ctxPtr = (*C.uint8_t)(unsafe.Pointer(unsafe.StringData(ctx)))
	}
	var keyPtr *C.uint8_t
	if len(key) > 0 {
		keyPtr = (*C.uint8_t)(unsafe.Pointer(&key[0]))
	}
	C.xray_blake3_derive_key(
		(*C.uint8_t)(unsafe.Pointer(&out[0])), C.size_t(len(out)),
		ctxPtr, C.size_t(len(ctx)),
		keyPtr, C.size_t(len(key)),
	)
	runtime.KeepAlive(out)
	runtime.KeepAlive(ctx)
	runtime.KeepAlive(key)
}

// Blake3Sum256 computes a 32-byte BLAKE3 hash.
func Blake3Sum256(data []byte) [32]byte {
	var out [32]byte
	var dataPtr *C.uint8_t
	if len(data) > 0 {
		dataPtr = (*C.uint8_t)(unsafe.Pointer(&data[0]))
	}
	C.xray_blake3_sum256((*C.uint8_t)(unsafe.Pointer(&out[0])), dataPtr, C.size_t(len(data)))
	runtime.KeepAlive(data)
	return out
}

// Blake3KeyedHash computes a BLAKE3 keyed hash (MAC mode).
func Blake3KeyedHash(key *[32]byte, data []byte, outLen int) []byte {
	if outLen <= 0 {
		return nil
	}
	out := make([]byte, outLen)
	var dataPtr *C.uint8_t
	if len(data) > 0 {
		dataPtr = (*C.uint8_t)(unsafe.Pointer(&data[0]))
	}
	C.xray_blake3_keyed_hash(
		(*C.uint8_t)(unsafe.Pointer(&out[0])), C.size_t(outLen),
		(*C.uint8_t)(unsafe.Pointer(&key[0])),
		dataPtr, C.size_t(len(data)),
	)
	runtime.KeepAlive(key)
	runtime.KeepAlive(data)
	return out
}

// --- MPH ---

// MphHandle is an opaque handle to a Rust MPH table.
type MphHandle struct {
	ptr unsafe.Pointer
}

// MphNew creates a new MPH table.
func MphNew() *MphHandle {
	ptr := C.xray_mph_new()
	if ptr == nil {
		return nil
	}
	h := &MphHandle{ptr: ptr}
	runtime.SetFinalizer(h, (*MphHandle).release)
	return h
}

func (h *MphHandle) release() {
	MphFree(h)
}

// MphAddPattern adds a pattern. patternType: 0=Full, 1=Substr, 2=Domain.
func MphAddPattern(h *MphHandle, pattern string, patternType byte) {
	if h == nil || h.ptr == nil {
		return
	}
	var p *byte
	if len(pattern) > 0 {
		p = unsafe.StringData(pattern)
	} else {
		var z byte
		p = &z
	}
	C.xray_mph_add_pattern(h.ptr,
		(*C.uint8_t)(unsafe.Pointer(p)), C.size_t(len(pattern)),
		C.uint8_t(patternType))
	runtime.KeepAlive(pattern)
	runtime.KeepAlive(h)
}

// MphBuild builds the MPH table. Must be called after all patterns are added.
func MphBuild(h *MphHandle) {
	if h == nil || h.ptr == nil {
		return
	}
	C.xray_mph_build(h.ptr)
	runtime.KeepAlive(h)
}

// MphMatch tests if input matches any pattern in the table.
func MphMatch(h *MphHandle, input string) bool {
	if h == nil || h.ptr == nil {
		return false
	}
	var p *byte
	if len(input) > 0 {
		p = unsafe.StringData(input)
	} else {
		var z byte
		p = &z
	}
	result := bool(C.xray_mph_match(h.ptr,
		(*C.uint8_t)(unsafe.Pointer(p)), C.size_t(len(input))))
	runtime.KeepAlive(input)
	runtime.KeepAlive(h)
	return result
}

// MphFree releases the MPH table.
func MphFree(h *MphHandle) {
	if h == nil {
		return
	}
	runtime.SetFinalizer(h, nil)
	ptr := atomic.SwapPointer(&h.ptr, nil)
	if ptr != nil {
		C.xray_mph_free(ptr)
	}
}

// --- GeoIP ---

// IpSetHandle is an opaque handle to a Rust IP prefix set.
type IpSetHandle struct {
	ptr unsafe.Pointer
}

// IpSetNew creates a new IP set.
func IpSetNew() *IpSetHandle {
	ptr := C.xray_ipset_new()
	if ptr == nil {
		return nil
	}
	h := &IpSetHandle{ptr: ptr}
	runtime.SetFinalizer(h, (*IpSetHandle).release)
	return h
}

func (h *IpSetHandle) release() {
	IpSetFree(h)
}

// IpSetAddPrefix adds a CIDR prefix. ipBytes must be 4 (IPv4) or 16 (IPv6) bytes.
// prefixBits must be 0-32 for IPv4 or 0-128 for IPv6.
func IpSetAddPrefix(h *IpSetHandle, ipBytes []byte, prefixBits int) {
	if h == nil || h.ptr == nil || len(ipBytes) == 0 {
		return
	}
	// Guard against silent truncation: Go int -> C uint8_t.
	// Max valid prefix is 128 (IPv6). Reject out-of-range values before the cast.
	if prefixBits < 0 || prefixBits > 128 {
		return
	}
	C.xray_ipset_add_prefix(h.ptr,
		(*C.uint8_t)(unsafe.Pointer(&ipBytes[0])), C.size_t(len(ipBytes)),
		C.uint8_t(prefixBits))
	runtime.KeepAlive(ipBytes)
	runtime.KeepAlive(h)
}

// IpSetBuild finalizes the IP set after all prefixes are added.
func IpSetBuild(h *IpSetHandle) {
	if h == nil || h.ptr == nil {
		return
	}
	C.xray_ipset_build(h.ptr)
	runtime.KeepAlive(h)
}

// IpSetContains checks whether an IP is in the set.
func IpSetContains(h *IpSetHandle, ipBytes []byte) bool {
	if h == nil || h.ptr == nil || len(ipBytes) == 0 {
		return false
	}
	result := bool(C.xray_ipset_contains(h.ptr,
		(*C.uint8_t)(unsafe.Pointer(&ipBytes[0])), C.size_t(len(ipBytes))))
	runtime.KeepAlive(ipBytes)
	runtime.KeepAlive(h)
	return result
}

// IpSetMax4 returns the maximum IPv4 prefix length, or 0xff if empty.
func IpSetMax4(h *IpSetHandle) uint8 {
	if h == nil || h.ptr == nil {
		return 0xff
	}
	result := uint8(C.xray_ipset_max4(h.ptr))
	runtime.KeepAlive(h)
	return result
}

// IpSetMax6 returns the maximum IPv6 prefix length, or 0xff if empty.
func IpSetMax6(h *IpSetHandle) uint8 {
	if h == nil || h.ptr == nil {
		return 0xff
	}
	result := uint8(C.xray_ipset_max6(h.ptr))
	runtime.KeepAlive(h)
	return result
}

// IpSetFree releases the IP set.
func IpSetFree(h *IpSetHandle) {
	if h == nil {
		return
	}
	runtime.SetFinalizer(h, nil)
	ptr := atomic.SwapPointer(&h.ptr, nil)
	if ptr != nil {
		C.xray_ipset_free(ptr)
	}
}

// --- Vision Padding FFI ---

// VisionUnpadState is the stateful unpadding parser state (matches Rust's VisionUnpadState).
type VisionUnpadState struct {
	RemainingCommand int32
	RemainingContent int32
	RemainingPadding int32
	CurrentCommand   int32
}

// NewVisionUnpadState returns an initialized unpadding state.
func NewVisionUnpadState() *VisionUnpadState {
	return &VisionUnpadState{
		RemainingCommand: -1,
		RemainingContent: -1,
		RemainingPadding: -1,
		CurrentCommand:   0,
	}
}

// VisionPad pads a plaintext buffer with Vision framing.
// Returns the number of bytes written to out, or an error.
func VisionPad(data []byte, command byte, uuid []byte, longPadding bool, testseed [4]uint32, out []byte) (int, error) {
	if len(out) == 0 {
		return 0, errors.New("native: empty output buffer")
	}
	var dataPtr *C.uint8_t
	if len(data) > 0 {
		dataPtr = (*C.uint8_t)(unsafe.Pointer(&data[0]))
	}
	var uuidPtr *C.uint8_t
	if len(uuid) > 0 {
		uuidPtr = (*C.uint8_t)(unsafe.Pointer(&uuid[0]))
	}
	n := C.xray_vision_pad(
		dataPtr, C.uint32_t(len(data)),
		C.uint8_t(command),
		uuidPtr,
		C.bool(longPadding),
		(*C.uint32_t)(unsafe.Pointer(&testseed[0])),
		(*C.uint8_t)(unsafe.Pointer(&out[0])),
		C.uint32_t(len(out)),
	)
	runtime.KeepAlive(data)
	runtime.KeepAlive(uuid)
	runtime.KeepAlive(out)
	if n < 0 {
		return 0, errors.New("native: vision pad failed")
	}
	return int(n), nil
}

// VisionUnpad removes Vision padding and extracts content.
// Returns the number of content bytes written to out, or an error.
// The state is updated in-place for streaming across multiple calls.
func VisionUnpad(data []byte, state *VisionUnpadState, uuid []byte, out []byte) (int, error) {
	if state == nil || len(data) == 0 || len(out) == 0 {
		return 0, errors.New("native: nil state, empty data, or empty output buffer")
	}
	var uuidPtr *C.uint8_t
	var uuidLen C.uint32_t
	if len(uuid) > 0 {
		uuidPtr = (*C.uint8_t)(unsafe.Pointer(&uuid[0]))
		uuidLen = C.uint32_t(len(uuid))
	}
	n := C.xray_vision_unpad(
		(*C.uint8_t)(unsafe.Pointer(&data[0])), C.uint32_t(len(data)),
		(*C.struct_xray_vision_unpad_state)(unsafe.Pointer(state)),
		uuidPtr, uuidLen,
		(*C.uint8_t)(unsafe.Pointer(&out[0])), C.uint32_t(len(out)),
	)
	runtime.KeepAlive(data)
	runtime.KeepAlive(state)
	runtime.KeepAlive(uuid)
	runtime.KeepAlive(out)
	if n < 0 {
		return 0, errors.New("native: vision unpad failed")
	}
	return int(n), nil
}

// VisionFilterState is the stateful TLS filter state (matches Rust's VisionFilterState).
// Field order matches repr(C) layout: i32, i32, u16, bool, bool, bool.
type VisionFilterState struct {
	RemainingServerHello    int32
	NumberOfPacketsToFilter int32
	Cipher                  uint16
	IsTLS                   bool
	IsTLS12orAbove          bool
	EnableXtls              bool
}

// VisionFilterStateSizeC returns the C-side sizeof(struct xray_vision_filter_state).
func VisionFilterStateSizeC() uintptr {
	var s C.struct_xray_vision_filter_state
	return unsafe.Sizeof(s)
}

// VisionFilterTls filters a single buffer for TLS handshake patterns.
// Returns true if filtering should stop (TLS version determined).
func VisionFilterTls(data []byte, state *VisionFilterState) bool {
	if state == nil || len(data) == 0 {
		return false
	}
	rc := C.xray_vision_filter_tls(
		(*C.uint8_t)(unsafe.Pointer(&data[0])), C.uint32_t(len(data)),
		(*C.struct_xray_vision_filter_state)(unsafe.Pointer(state)),
	)
	runtime.KeepAlive(data)
	runtime.KeepAlive(state)
	return rc == 1
}

// VisionIsCompleteRecord checks if a byte buffer consists entirely of
// well-formed TLS application data records.
func VisionIsCompleteRecord(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	rc := C.xray_vision_is_complete_record(
		(*C.uint8_t)(unsafe.Pointer(&data[0])), C.uint32_t(len(data)),
	)
	runtime.KeepAlive(data)
	return rc == 1
}

// --- AEAD FFI ---

// AEAD algorithm constants.
const (
	AeadAes128Gcm        = 0
	AeadAes256Gcm        = 1
	AeadChacha20Poly1305 = 2
)

// AeadHandle is an opaque handle to a Rust AEAD cipher.
type AeadHandle struct {
	ptr unsafe.Pointer
}

func (h *AeadHandle) release() {
	aeadFree(h)
}

// AeadNew creates a new AEAD handle for the given algorithm and key.
// algo: AeadAes128Gcm (0), AeadAes256Gcm (1), AeadChacha20Poly1305 (2).
func AeadNew(algo byte, key []byte) *AeadHandle {
	if len(key) == 0 {
		return nil
	}
	ptr := C.xray_aead_new(C.uint8_t(algo),
		(*C.uint8_t)(unsafe.Pointer(&key[0])), C.size_t(len(key)))
	runtime.KeepAlive(key)
	if ptr == nil {
		return nil
	}
	h := &AeadHandle{ptr: ptr}
	runtime.SetFinalizer(h, (*AeadHandle).release)
	return h
}

// AeadSeal encrypts and authenticates plaintext.
func AeadSeal(h *AeadHandle, nonce, aad, plaintext []byte) ([]byte, error) {
	if h == nil {
		return nil, errors.New("native: nil AEAD handle")
	}
	ptr := atomic.LoadPointer(&h.ptr)
	if ptr == nil {
		return nil, errors.New("native: nil AEAD handle")
	}
	overhead := int(C.xray_aead_overhead(ptr))
	outCap := len(plaintext) + overhead
	out := make([]byte, outCap)
	var outLen C.size_t

	var noncePtr *C.uint8_t
	if len(nonce) > 0 {
		noncePtr = (*C.uint8_t)(unsafe.Pointer(&nonce[0]))
	}
	var aadPtr *C.uint8_t
	if len(aad) > 0 {
		aadPtr = (*C.uint8_t)(unsafe.Pointer(&aad[0]))
	}
	var ptPtr *C.uint8_t
	if len(plaintext) > 0 {
		ptPtr = (*C.uint8_t)(unsafe.Pointer(&plaintext[0]))
	}

	rc := C.xray_aead_seal(ptr,
		noncePtr, C.size_t(len(nonce)),
		aadPtr, C.size_t(len(aad)),
		ptPtr, C.size_t(len(plaintext)),
		(*C.uint8_t)(unsafe.Pointer(&out[0])), C.size_t(outCap), &outLen)
	runtime.KeepAlive(h)
	runtime.KeepAlive(nonce)
	runtime.KeepAlive(aad)
	runtime.KeepAlive(plaintext)
	runtime.KeepAlive(out)
	if rc != 0 {
		return nil, fmt.Errorf("native: AEAD seal failed (rc=%d)", rc)
	}
	return out[:outLen], nil
}

// AeadOpen decrypts and verifies ciphertext.
func AeadOpen(h *AeadHandle, nonce, aad, ciphertext []byte) ([]byte, error) {
	if h == nil {
		return nil, errors.New("native: nil AEAD handle")
	}
	ptr := atomic.LoadPointer(&h.ptr)
	if ptr == nil {
		return nil, errors.New("native: nil AEAD handle")
	}
	overhead := int(C.xray_aead_overhead(ptr))
	if len(ciphertext) < overhead {
		return nil, errors.New("native: ciphertext too short")
	}
	outCap := len(ciphertext) // plaintext is at most ct_len - overhead, but we need ct_len for in-place
	out := make([]byte, outCap)
	var outLen C.size_t

	var noncePtr *C.uint8_t
	if len(nonce) > 0 {
		noncePtr = (*C.uint8_t)(unsafe.Pointer(&nonce[0]))
	}
	var aadPtr *C.uint8_t
	if len(aad) > 0 {
		aadPtr = (*C.uint8_t)(unsafe.Pointer(&aad[0]))
	}

	rc := C.xray_aead_open(ptr,
		noncePtr, C.size_t(len(nonce)),
		aadPtr, C.size_t(len(aad)),
		(*C.uint8_t)(unsafe.Pointer(&ciphertext[0])), C.size_t(len(ciphertext)),
		(*C.uint8_t)(unsafe.Pointer(&out[0])), C.size_t(outCap), &outLen)
	runtime.KeepAlive(h)
	runtime.KeepAlive(nonce)
	runtime.KeepAlive(aad)
	runtime.KeepAlive(ciphertext)
	runtime.KeepAlive(out)
	if rc != 0 {
		return nil, fmt.Errorf("native: AEAD open failed (rc=%d)", rc)
	}
	return out[:outLen], nil
}

// AeadSealTo encrypts plaintext directly into dst.
// dst must have len >= len(plaintext)+overhead.
// dst may alias plaintext (in-place mutation is supported).
// Returns the number of bytes written.
func AeadSealTo(h *AeadHandle, nonce, aad, plaintext, dst []byte) (int, error) {
	if h == nil {
		return 0, errors.New("native: nil AEAD handle")
	}
	ptr := atomic.LoadPointer(&h.ptr)
	if ptr == nil {
		return 0, errors.New("native: nil AEAD handle")
	}
	if len(dst) == 0 {
		return 0, errors.New("native: empty dst buffer")
	}
	var outLen C.size_t

	var noncePtr *C.uint8_t
	if len(nonce) > 0 {
		noncePtr = (*C.uint8_t)(unsafe.Pointer(&nonce[0]))
	}
	var aadPtr *C.uint8_t
	if len(aad) > 0 {
		aadPtr = (*C.uint8_t)(unsafe.Pointer(&aad[0]))
	}
	var ptPtr *C.uint8_t
	if len(plaintext) > 0 {
		ptPtr = (*C.uint8_t)(unsafe.Pointer(&plaintext[0]))
	}
	var dstPtr *C.uint8_t
	if len(dst) > 0 {
		dstPtr = (*C.uint8_t)(unsafe.Pointer(&dst[0]))
	}

	rc := C.xray_aead_seal(ptr,
		noncePtr, C.size_t(len(nonce)),
		aadPtr, C.size_t(len(aad)),
		ptPtr, C.size_t(len(plaintext)),
		dstPtr, C.size_t(len(dst)), &outLen)
	runtime.KeepAlive(h)
	runtime.KeepAlive(nonce)
	runtime.KeepAlive(aad)
	runtime.KeepAlive(plaintext)
	runtime.KeepAlive(dst)
	if rc != 0 {
		return 0, fmt.Errorf("native: AEAD seal failed (rc=%d)", rc)
	}
	return int(outLen), nil
}

// AeadOpenTo decrypts ciphertext directly into dst.
// dst must have len >= len(ciphertext) (for in-place decryption).
// dst may alias ciphertext (in-place mutation is supported).
// Returns the number of plaintext bytes written.
func AeadOpenTo(h *AeadHandle, nonce, aad, ciphertext, dst []byte) (int, error) {
	if h == nil {
		return 0, errors.New("native: nil AEAD handle")
	}
	ptr := atomic.LoadPointer(&h.ptr)
	if ptr == nil {
		return 0, errors.New("native: nil AEAD handle")
	}
	var outLen C.size_t

	var noncePtr *C.uint8_t
	if len(nonce) > 0 {
		noncePtr = (*C.uint8_t)(unsafe.Pointer(&nonce[0]))
	}
	var aadPtr *C.uint8_t
	if len(aad) > 0 {
		aadPtr = (*C.uint8_t)(unsafe.Pointer(&aad[0]))
	}

	if len(ciphertext) == 0 {
		return 0, errors.New("native: empty ciphertext")
	}
	if len(dst) == 0 {
		return 0, errors.New("native: empty dst buffer")
	}

	ctPtr := (*C.uint8_t)(unsafe.Pointer(&ciphertext[0]))
	dstPtr := (*C.uint8_t)(unsafe.Pointer(&dst[0]))

	rc := C.xray_aead_open(ptr,
		noncePtr, C.size_t(len(nonce)),
		aadPtr, C.size_t(len(aad)),
		ctPtr, C.size_t(len(ciphertext)),
		dstPtr, C.size_t(len(dst)), &outLen)
	runtime.KeepAlive(h)
	runtime.KeepAlive(nonce)
	runtime.KeepAlive(aad)
	runtime.KeepAlive(ciphertext)
	runtime.KeepAlive(dst)
	if rc != 0 {
		return 0, fmt.Errorf("native: AEAD open failed (rc=%d)", rc)
	}
	return int(outLen), nil
}

// AeadOverhead returns the tag size for this AEAD.
func AeadOverhead(h *AeadHandle) int {
	if h == nil {
		return 0
	}
	ptr := atomic.LoadPointer(&h.ptr)
	if ptr == nil {
		return 0
	}
	result := int(C.xray_aead_overhead(ptr))
	runtime.KeepAlive(h)
	return result
}

// AeadNonceSize returns the nonce size for this AEAD.
func AeadNonceSize(h *AeadHandle) int {
	if h == nil {
		return 0
	}
	ptr := atomic.LoadPointer(&h.ptr)
	if ptr == nil {
		return 0
	}
	result := int(C.xray_aead_nonce_size(ptr))
	runtime.KeepAlive(h)
	return result
}

// aeadFree releases an AEAD handle. Unexported to prevent use-after-free
// races — cleanup is driven solely by the GC finalizer on AeadHandle.
func aeadFree(h *AeadHandle) {
	if h == nil {
		return
	}
	runtime.SetFinalizer(h, nil)
	ptr := atomic.SwapPointer(&h.ptr, nil)
	if ptr != nil {
		C.xray_aead_free(ptr)
	}
}

// --- VMess AEAD Header FFI ---

// VMessSealHeader seals a VMess AEAD header in a single FFI call.
// cmdKey must be exactly 16 bytes.
// Returns the sealed output: authid[16] + encrypted_length[18] + nonce[8] + encrypted_header.
func VMessSealHeader(cmdKey [16]byte, header []byte) ([]byte, error) {
	// Total output: 16 (authid) + 18 (enc length) + 8 (nonce) + len(header) + 16 (tag)
	outCap := 16 + 18 + 8 + len(header) + 16
	out := make([]byte, outCap)
	var outLen C.size_t

	var headerPtr *C.uint8_t
	if len(header) > 0 {
		headerPtr = (*C.uint8_t)(unsafe.Pointer(&header[0]))
	}

	rc := C.xray_vmess_seal_header(
		(*C.uint8_t)(unsafe.Pointer(&cmdKey[0])),
		headerPtr, C.size_t(len(header)),
		(*C.uint8_t)(unsafe.Pointer(&out[0])), C.size_t(outCap), &outLen)
	runtime.KeepAlive(cmdKey)
	runtime.KeepAlive(header)
	runtime.KeepAlive(out)
	if rc != 0 {
		return nil, fmt.Errorf("native: VMess seal header failed (rc=%d)", rc)
	}
	return out[:outLen], nil
}

// VMessOpenHeader opens a VMess AEAD header in a single FFI call.
// cmdKey must be exactly 16 bytes, authid must be exactly 16 bytes.
// data is: encrypted_length[18] + nonce[8] + encrypted_header.
// Returns the decrypted header.
func VMessOpenHeader(cmdKey [16]byte, authid [16]byte, data []byte) ([]byte, error) {
	if len(data) < 26 {
		return nil, errors.New("native: VMess data too short")
	}
	// Output is at most the header plaintext length.
	// Max possible: data_len - 26 (enc_length + nonce) - 16 (tag) = data_len - 42
	outCap := len(data)
	out := make([]byte, outCap)
	var outLen C.size_t

	rc := C.xray_vmess_open_header(
		(*C.uint8_t)(unsafe.Pointer(&cmdKey[0])),
		(*C.uint8_t)(unsafe.Pointer(&authid[0])),
		(*C.uint8_t)(unsafe.Pointer(&data[0])), C.size_t(len(data)),
		(*C.uint8_t)(unsafe.Pointer(&out[0])), C.size_t(outCap), &outLen)
	runtime.KeepAlive(cmdKey)
	runtime.KeepAlive(authid)
	runtime.KeepAlive(data)
	runtime.KeepAlive(out)
	if rc != 0 {
		return nil, fmt.Errorf("native: VMess open header failed (rc=%d)", rc)
	}
	return out[:outLen], nil
}

// --- Geodata Batch Loading FFI ---

// GeoSiteEntry represents a single domain pattern from a GeoSite file.
type GeoSiteEntry struct {
	DomainType byte   // 0=Plain, 1=Regex, 2=Domain, 3=Full
	Value      string // Domain pattern
}

// GeoIPLoad loads GeoIP data from a file and builds IpSet handles for all
// requested country codes in a single pass. Returns one handle per code
// (nil for codes not found in the file).
func GeoIPLoad(path string, codes []string) ([]*IpSetHandle, error) {
	if len(codes) == 0 {
		return nil, nil
	}

	pathBytes := []byte(path)
	if len(pathBytes) == 0 {
		return nil, errors.New("native: empty file path")
	}

	// Build arrays of code pointers and lengths.
	// Pin inner byte slices so cgo allows the Go-pointer-to-Go-pointer pass.
	var pinner runtime.Pinner
	defer pinner.Unpin()

	codePtrs := make([]*C.uint8_t, len(codes))
	codeLens := make([]C.size_t, len(codes))
	codeBytes := make([][]byte, len(codes))
	for i, code := range codes {
		codeBytes[i] = []byte(code)
		if len(codeBytes[i]) == 0 {
			pinner.Pin(&emptyCodeSentinel)
			codePtrs[i] = (*C.uint8_t)(unsafe.Pointer(&emptyCodeSentinel))
			continue
		}
		pinner.Pin(&codeBytes[i][0])
		codePtrs[i] = (*C.uint8_t)(unsafe.Pointer(&codeBytes[i][0]))
		codeLens[i] = C.size_t(len(codeBytes[i]))
	}

	var result C.struct_xray_geoip_result

	rc := C.xray_geoip_load(
		(*C.uint8_t)(unsafe.Pointer(&pathBytes[0])), C.size_t(len(pathBytes)),
		(**C.uint8_t)(unsafe.Pointer(&codePtrs[0])),
		(*C.size_t)(unsafe.Pointer(&codeLens[0])),
		C.size_t(len(codes)),
		&result)
	runtime.KeepAlive(pathBytes)
	runtime.KeepAlive(codePtrs)
	runtime.KeepAlive(codeLens)
	runtime.KeepAlive(codeBytes)

	if rc != 0 {
		C.xray_geoip_result_free(&result)
		return nil, fmt.Errorf("native: GeoIP load failed (rc=%d)", rc)
	}

	// Extract handles
	handles := make([]*IpSetHandle, len(codes))
	if result.handles != nil {
		handleSlice := unsafe.Slice(result.handles, result.count)
		for i := 0; i < int(result.count); i++ {
			ptr := handleSlice[i]
			if ptr != nil {
				h := &IpSetHandle{ptr: ptr}
				runtime.SetFinalizer(h, (*IpSetHandle).release)
				handles[i] = h
			}
		}
	}

	C.xray_geoip_result_free(&result)
	return handles, nil
}

// GeoSiteLoad loads GeoSite data from a file and returns domain patterns
// for all requested country codes in a single pass.
func GeoSiteLoad(path string, codes []string) ([][]GeoSiteEntry, error) {
	if len(codes) == 0 {
		return nil, nil
	}

	pathBytes := []byte(path)
	if len(pathBytes) == 0 {
		return nil, errors.New("native: empty file path")
	}

	var pinner runtime.Pinner
	defer pinner.Unpin()

	codePtrs := make([]*C.uint8_t, len(codes))
	codeLens := make([]C.size_t, len(codes))
	codeBytes := make([][]byte, len(codes))
	for i, code := range codes {
		codeBytes[i] = []byte(code)
		if len(codeBytes[i]) == 0 {
			pinner.Pin(&emptyCodeSentinel)
			codePtrs[i] = (*C.uint8_t)(unsafe.Pointer(&emptyCodeSentinel))
			continue
		}
		pinner.Pin(&codeBytes[i][0])
		codePtrs[i] = (*C.uint8_t)(unsafe.Pointer(&codeBytes[i][0]))
		codeLens[i] = C.size_t(len(codeBytes[i]))
	}

	var result C.struct_xray_geosite_result

	rc := C.xray_geosite_load(
		(*C.uint8_t)(unsafe.Pointer(&pathBytes[0])), C.size_t(len(pathBytes)),
		(**C.uint8_t)(unsafe.Pointer(&codePtrs[0])),
		(*C.size_t)(unsafe.Pointer(&codeLens[0])),
		C.size_t(len(codes)),
		&result)
	runtime.KeepAlive(pathBytes)
	runtime.KeepAlive(codePtrs)
	runtime.KeepAlive(codeLens)
	runtime.KeepAlive(codeBytes)

	if rc != 0 {
		C.xray_geosite_result_free(&result)
		return nil, fmt.Errorf("native: GeoSite load failed (rc=%d)", rc)
	}

	// Extract domain lists
	entries := make([][]GeoSiteEntry, len(codes))
	if result.entries != nil {
		entrySlice := unsafe.Slice(result.entries, result.count)
		for i := 0; i < int(result.count); i++ {
			codeResult := entrySlice[i]
			if codeResult.domains != nil && codeResult.domain_count > 0 {
				domainSlice := unsafe.Slice(codeResult.domains, codeResult.domain_count)
				domainEntries := make([]GeoSiteEntry, codeResult.domain_count)
				for j := 0; j < int(codeResult.domain_count); j++ {
					d := domainSlice[j]
					valBytes := unsafe.Slice(d.value, d.value_len)
					domainEntries[j] = GeoSiteEntry{
						DomainType: byte(d.domain_type),
						Value:      string(valBytes), // copies bytes, safe after free
					}
				}
				entries[i] = domainEntries
			}
		}
	}

	C.xray_geosite_result_free(&result)
	return entries, nil
}

// --- eBPF FFI ---

// SkMsgCapability indicates which SK_MSG tier the Rust/Aya loader achieved.
type SkMsgCapability int

const (
	SkMsgFull     SkMsgCapability = 0 // cork + cookie lookup + redirect
	SkMsgCorkOnly SkMsgCapability = 1 // cork batching only, no redirect
	SkMsgNone     SkMsgCapability = 2 // no SK_MSG loaded
)

// ebpfSkMsgCapability records the SK_MSG tier from the last successful setup.
var ebpfSkMsgCapability SkMsgCapability = SkMsgNone

// EbpfSkMsgCapability returns the SK_MSG capability level from the Rust loader.
func EbpfSkMsgCapability() SkMsgCapability { return ebpfSkMsgCapability }

// EbpfMaxEntries reports the effective SOCKHASH capacity compiled into the native loader.
func EbpfMaxEntries() uint32 { return uint32(C.xray_ebpf_max_entries()) }

// EbpfSetup initializes eBPF sockmap with pinned maps for zero-downtime recovery.
func EbpfSetup(pinPath string, maxEntries, corkThreshold uint32) error {
	if pinPath == "" {
		return errors.New("native: ebpf setup: empty pin path")
	}
	if maxEntries == 0 {
		maxEntries = 65536
	}
	const maxAllowedEntries = 1 << 20 // 1M
	if maxEntries > maxAllowedEntries {
		return fmt.Errorf("native: ebpf setup: maxEntries %d exceeds limit %d", maxEntries, maxAllowedEntries)
	}
	cPath := C.CString(pinPath)
	defer C.free(unsafe.Pointer(cPath))
	rc := C.xray_ebpf_setup(cPath, C.uint32_t(maxEntries), C.uint32_t(corkThreshold))
	if rc < 0 {
		return fmt.Errorf("native: ebpf setup failed: %s (rc=%d)", ebpfSetupErrorDetail(rc), rc)
	}
	ebpfSkMsgCapability = SkMsgCapability(rc)
	return nil
}

// ebpfSetupErrorDetail maps Rust eBPF setup error codes to human-readable descriptions.
func ebpfSetupErrorDetail(rc C.int32_t) string {
	switch rc {
	case -2:
		return "permission denied (need CAP_BPF / CAP_NET_ADMIN)"
	case -3:
		return "missing kernel feature or eBPF bytecode not compiled"
	case -4:
		return "BPF program/map load or attach failure"
	default:
		return "unknown error"
	}
}

// EbpfTeardown tears down eBPF programs and unpins maps.
func EbpfTeardown() error {
	rc := C.xray_ebpf_teardown()
	if rc != 0 {
		return errors.New("native: ebpf teardown failed")
	}
	return nil
}

// EbpfRegisterPair registers a socket pair for bidirectional forwarding.
func EbpfRegisterPair(inboundFD, outboundFD int, inboundCookie, outboundCookie uint64, policyFlags uint32) error {
	rc := C.xray_ebpf_register_pair(
		C.int32_t(inboundFD), C.int32_t(outboundFD),
		C.uint64_t(inboundCookie), C.uint64_t(outboundCookie),
		C.uint32_t(policyFlags),
	)
	if rc != 0 {
		return ebpfErrno("ebpf register pair", rc)
	}
	return nil
}

// EbpfUnregisterPair unregisters a socket pair.
func EbpfUnregisterPair(inboundCookie, outboundCookie uint64) error {
	rc := C.xray_ebpf_unregister_pair(C.uint64_t(inboundCookie), C.uint64_t(outboundCookie))
	if rc != 0 {
		return ebpfErrno("ebpf unregister pair", rc)
	}
	return nil
}

func ebpfErrno(op string, rc C.int32_t) error {
	if rc == 0 {
		return nil
	}
	code := int32(rc)
	if code < 0 {
		errno := syscall.Errno(-code)
		return fmt.Errorf("native: %s failed: %w", op, errno)
	}
	return fmt.Errorf("native: %s failed with code %d", op, code)
}
