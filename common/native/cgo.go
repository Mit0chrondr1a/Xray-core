//go:build cgo && linux

package native

/*
#cgo LDFLAGS: -L${SRCDIR}/../../rust/xray-rust/target/release -lxray_rust
#cgo linux LDFLAGS: -lm -ldl -lpthread

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
    char     error_msg[256];
    uint8_t  tx_secret[48];
    uint8_t  rx_secret[48];
    uint8_t  secret_len;
    uint8_t* drained_ptr;
    uint32_t drained_len;
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
extern int32_t xray_tls_handshake(int fd, const void* cfg, bool is_client, struct xray_tls_result* out);
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
extern int32_t xray_reality_server_handshake(int fd, const void* reality_config, struct xray_tls_result* out);

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

// eBPF sockmap management
extern int32_t xray_ebpf_available();
extern int32_t xray_ebpf_setup(const char* pin_path, uint32_t max_entries, uint32_t cork_threshold);
extern int32_t xray_ebpf_teardown();
extern int32_t xray_ebpf_register_pair(int32_t inbound_fd, int32_t outbound_fd, uint64_t inbound_cookie, uint64_t outbound_cookie, uint32_t policy_flags);
extern int32_t xray_ebpf_unregister_pair(uint64_t inbound_cookie, uint64_t outbound_cookie);
*/
import "C"

import (
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"unicode/utf8"
	"unsafe"

	"lukechampine.com/blake3"
)

// Available reports whether the native Rust implementations are linked.
func Available() bool {
	return true
}

// EbpfAvailable reports whether Rust eBPF bytecode support is compiled in.
func EbpfAvailable() bool {
	return C.xray_ebpf_available() != 0
}

// ErrRealityAuthFailed indicates REALITY auth failed and Go should handle fallback.
var ErrRealityAuthFailed = errors.New("REALITY auth failed: needs fallback")

// --- TLS Types ---

// TlsConfigHandle is an opaque handle to a Rust TLS config.
type TlsConfigHandle struct {
	ptr unsafe.Pointer
}

// TlsStateHandle is an opaque handle to a Rust TLS state (for KeyUpdate).
type TlsStateHandle struct {
	ptr unsafe.Pointer
}

// TlsResult contains the result of a TLS handshake.
type TlsResult struct {
	KtlsTx      bool
	KtlsRx      bool
	Version     uint16
	CipherSuite uint16
	ALPN        string
	StateHandle *TlsStateHandle
	TxSecret    []byte // base traffic secret for KeyUpdate (TLS 1.3 only)
	RxSecret    []byte // base traffic secret for KeyUpdate (TLS 1.3 only)
	DrainedData []byte // plaintext drained from rustls after handshake
}

// ZeroSecrets zeroes the traffic secret fields after they have been copied.
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
	if h == nil {
		return
	}
	nameBytes := []byte(name)
	C.xray_tls_config_set_server_name(h.ptr, (*C.uint8_t)(unsafe.Pointer(&nameBytes[0])), C.size_t(len(nameBytes)))
}

func TlsConfigAddCertPEM(h *TlsConfigHandle, certPEM, keyPEM []byte) error {
	if h == nil || len(certPEM) == 0 || len(keyPEM) == 0 {
		return errors.New("native: nil handle or empty cert/key")
	}
	rc := C.xray_tls_config_add_cert_pem(h.ptr,
		(*C.uint8_t)(unsafe.Pointer(&certPEM[0])), C.size_t(len(certPEM)),
		(*C.uint8_t)(unsafe.Pointer(&keyPEM[0])), C.size_t(len(keyPEM)))
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
}

func TlsConfigSetALPN(h *TlsConfigHandle, protos []byte) {
	if h == nil || len(protos) == 0 {
		return
	}
	C.xray_tls_config_set_alpn(h.ptr, (*C.uint8_t)(unsafe.Pointer(&protos[0])), C.size_t(len(protos)))
}

func TlsConfigSetVersions(h *TlsConfigHandle, minVer, maxVer uint16) {
	if h == nil {
		return
	}
	C.xray_tls_config_set_versions(h.ptr, C.uint16_t(minVer), C.uint16_t(maxVer))
}

func TlsConfigSetInsecureSkipVerify(h *TlsConfigHandle, skip bool) {
	if h == nil {
		return
	}
	C.xray_tls_config_set_insecure_skip_verify(h.ptr, C.bool(skip))
}

func TlsConfigPinCertSHA256(h *TlsConfigHandle, hash []byte) {
	if h == nil || len(hash) == 0 {
		return
	}
	C.xray_tls_config_pin_cert_sha256(h.ptr, (*C.uint8_t)(unsafe.Pointer(&hash[0])), C.size_t(len(hash)))
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
}

func TlsConfigFree(h *TlsConfigHandle) {
	if h == nil || h.ptr == nil {
		return
	}
	runtime.SetFinalizer(h, nil)
	C.xray_tls_config_free(h.ptr)
	h.ptr = nil
}

// --- TLS Handshake ---

func TlsHandshake(fd int, cfg *TlsConfigHandle, isClient bool) (*TlsResult, error) {
	if cfg == nil {
		return nil, errors.New("native: nil config handle")
	}
	var cResult C.struct_xray_tls_result
	rc := C.xray_tls_handshake(C.int(fd), cfg.ptr, C.bool(isClient), &cResult)
	if rc != 0 {
		errMsg := C.GoString(&cResult.error_msg[0])
		return nil, errors.New("native TLS handshake: " + errMsg)
	}
	result := &TlsResult{
		KtlsTx:      bool(cResult.ktls_tx),
		KtlsRx:      bool(cResult.ktls_rx),
		Version:     uint16(cResult.version),
		CipherSuite: uint16(cResult.cipher_suite),
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
	extractSecrets(result, &cResult)
	extractDrained(result, &cResult)
	return result, nil
}

func TlsKeyUpdate(h *TlsStateHandle) error {
	if h == nil {
		return errors.New("native: nil state handle")
	}
	rc := C.xray_tls_key_update(h.ptr)
	if rc != 0 {
		return errors.New("native: key update failed")
	}
	return nil
}

func TlsStateFree(h *TlsStateHandle) {
	if h == nil || h.ptr == nil {
		return
	}
	runtime.SetFinalizer(h, nil)
	C.xray_tls_state_free(h.ptr)
	h.ptr = nil
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
}

func RealityConfigSetShortId(h *RealityConfigHandle, id []byte) {
	if h == nil || len(id) == 0 {
		return
	}
	C.xray_reality_config_set_short_id(h.ptr, (*C.uint8_t)(unsafe.Pointer(&id[0])), C.size_t(len(id)))
}

func RealityConfigSetMldsa65Verify(h *RealityConfigHandle, key []byte) {
	if h == nil || len(key) == 0 {
		return
	}
	C.xray_reality_config_set_mldsa65_verify(h.ptr, (*C.uint8_t)(unsafe.Pointer(&key[0])), C.size_t(len(key)))
}

func RealityConfigSetVersion(h *RealityConfigHandle, x, y, z uint8) {
	if h == nil {
		return
	}
	C.xray_reality_config_set_version(h.ptr, C.uint8_t(x), C.uint8_t(y), C.uint8_t(z))
}

func RealityConfigFree(h *RealityConfigHandle) {
	if h == nil || h.ptr == nil {
		return
	}
	runtime.SetFinalizer(h, nil)
	C.xray_reality_config_free(h.ptr)
	h.ptr = nil
}

func RealityConfigSetPrivateKey(h *RealityConfigHandle, key []byte) {
	if h == nil || len(key) == 0 {
		return
	}
	C.xray_reality_config_set_private_key(h.ptr, (*C.uint8_t)(unsafe.Pointer(&key[0])), C.size_t(len(key)))
}

func RealityConfigSetServerNames(h *RealityConfigHandle, data []byte) {
	if h == nil || len(data) == 0 {
		return
	}
	C.xray_reality_config_set_server_names(h.ptr, (*C.uint8_t)(unsafe.Pointer(&data[0])), C.size_t(len(data)))
}

func RealityConfigSetShortIds(h *RealityConfigHandle, data []byte) {
	if h == nil || len(data) == 0 {
		return
	}
	C.xray_reality_config_set_short_ids(h.ptr, (*C.uint8_t)(unsafe.Pointer(&data[0])), C.size_t(len(data)))
}

func RealityConfigSetMldsa65Key(h *RealityConfigHandle, key []byte) {
	if h == nil || len(key) == 0 {
		return
	}
	C.xray_reality_config_set_mldsa65_key(h.ptr, (*C.uint8_t)(unsafe.Pointer(&key[0])), C.size_t(len(key)))
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
}

func RealityConfigSetMaxTimeDiff(h *RealityConfigHandle, ms uint64) {
	if h == nil {
		return
	}
	C.xray_reality_config_set_max_time_diff(h.ptr, C.uint64_t(ms))
}

func RealityConfigSetVersionRange(h *RealityConfigHandle, minX, minY, minZ, maxX, maxY, maxZ uint8) {
	if h == nil {
		return
	}
	C.xray_reality_config_set_version_range(h.ptr, C.uint8_t(minX), C.uint8_t(minY), C.uint8_t(minZ), C.uint8_t(maxX), C.uint8_t(maxY), C.uint8_t(maxZ))
}

func RealityConfigSetTLSCert(h *RealityConfigHandle, certPEM, keyPEM []byte) {
	if h == nil || len(certPEM) == 0 || len(keyPEM) == 0 {
		return
	}
	C.xray_reality_config_set_tls_cert(h.ptr,
		(*C.uint8_t)(unsafe.Pointer(&certPEM[0])), C.size_t(len(certPEM)),
		(*C.uint8_t)(unsafe.Pointer(&keyPEM[0])), C.size_t(len(keyPEM)))
}

func RealityConfigAddShortId(h *RealityConfigHandle, id []byte) {
	if h == nil || len(id) == 0 {
		return
	}
	C.xray_reality_config_add_short_id(h.ptr, (*C.uint8_t)(unsafe.Pointer(&id[0])), C.size_t(len(id)))
}

// --- REALITY Handshake ---

func RealityClientConnect(fd int, clientHelloRaw []byte, ecdhPrivkey []byte, cfg *RealityConfigHandle) (*TlsResult, error) {
	if cfg == nil {
		return nil, errors.New("native: nil reality config handle")
	}
	if len(clientHelloRaw) == 0 || len(ecdhPrivkey) == 0 {
		return nil, errors.New("native: empty client hello or privkey")
	}
	var cResult C.struct_xray_tls_result
	rc := C.xray_reality_client_connect(
		C.int(fd),
		(*C.uint8_t)(unsafe.Pointer(&clientHelloRaw[0])), C.size_t(len(clientHelloRaw)),
		(*C.uint8_t)(unsafe.Pointer(&ecdhPrivkey[0])), C.size_t(len(ecdhPrivkey)),
		cfg.ptr,
		&cResult,
	)
	if rc != 0 {
		errMsg := C.GoString(&cResult.error_msg[0])
		code := int32(cResult.error_code)
		if code == 1 {
			return nil, ErrRealityAuthFailed
		}
		return nil, errors.New("native REALITY: " + errMsg)
	}
	result := &TlsResult{
		KtlsTx:      bool(cResult.ktls_tx),
		KtlsRx:      bool(cResult.ktls_rx),
		Version:     uint16(cResult.version),
		CipherSuite: uint16(cResult.cipher_suite),
	}
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
	extractSecrets(result, &cResult)
	extractDrained(result, &cResult)
	return result, nil
}

func RealityServerAccept(fd int, cfg *RealityConfigHandle) (*TlsResult, error) {
	if cfg == nil {
		return nil, errors.New("native: nil reality config handle")
	}
	var cResult C.struct_xray_tls_result
	rc := C.xray_reality_server_accept(C.int(fd), cfg.ptr, &cResult)
	if rc != 0 {
		errMsg := C.GoString(&cResult.error_msg[0])
		code := int32(cResult.error_code)
		if code == 1 {
			return nil, ErrRealityAuthFailed
		}
		return nil, errors.New("native REALITY server: " + errMsg)
	}
	result := &TlsResult{
		KtlsTx:      bool(cResult.ktls_tx),
		KtlsRx:      bool(cResult.ktls_rx),
		Version:     uint16(cResult.version),
		CipherSuite: uint16(cResult.cipher_suite),
	}
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
	return result, nil
}

func RealityServerHandshake(fd int, cfg *RealityConfigHandle) (*TlsResult, error) {
	if cfg == nil {
		return nil, errors.New("native: nil reality config handle")
	}
	var cResult C.struct_xray_tls_result
	rc := C.xray_reality_server_handshake(C.int(fd), cfg.ptr, &cResult)
	if rc != 0 {
		errMsg := C.GoString(&cResult.error_msg[0])
		code := int32(cResult.error_code)
		if code == 1 {
			return nil, ErrRealityAuthFailed
		}
		return nil, errors.New("native REALITY server handshake: " + errMsg)
	}
	result := &TlsResult{
		KtlsTx:      bool(cResult.ktls_tx),
		KtlsRx:      bool(cResult.ktls_rx),
		Version:     uint16(cResult.version),
		CipherSuite: uint16(cResult.cipher_suite),
	}
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
	extractSecrets(result, &cResult)
	extractDrained(result, &cResult)
	return result, nil
}

// extractSecrets copies base traffic secrets from the C result to the Go TlsResult.
func extractSecrets(result *TlsResult, cResult *C.struct_xray_tls_result) {
	if secretLen := int(cResult.secret_len); secretLen > 0 {
		result.TxSecret = C.GoBytes(unsafe.Pointer(&cResult.tx_secret[0]), C.int(secretLen))
		result.RxSecret = C.GoBytes(unsafe.Pointer(&cResult.rx_secret[0]), C.int(secretLen))
	}
}

// extractDrained copies drained plaintext from the C result and frees the Rust buffer.
func extractDrained(result *TlsResult, cResult *C.struct_xray_tls_result) {
	if cResult.drained_ptr != nil && cResult.drained_len > 0 {
		result.DrainedData = C.GoBytes(unsafe.Pointer(cResult.drained_ptr), C.int(cResult.drained_len))
		C.xray_tls_drained_free(cResult.drained_ptr, C.size_t(cResult.drained_len))
	}
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
}

// Blake3Sum256 computes a 32-byte BLAKE3 hash.
func Blake3Sum256(data []byte) [32]byte {
	var out [32]byte
	var dataPtr *C.uint8_t
	if len(data) > 0 {
		dataPtr = (*C.uint8_t)(unsafe.Pointer(&data[0]))
	}
	C.xray_blake3_sum256((*C.uint8_t)(unsafe.Pointer(&out[0])), dataPtr, C.size_t(len(data)))
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
	return out
}

// --- MPH ---

// MphHandle is an opaque handle to a Rust MPH table.
type MphHandle struct {
	ptr unsafe.Pointer
}

// MphNew creates a new MPH table.
func MphNew() *MphHandle {
	return &MphHandle{ptr: C.xray_mph_new()}
}

// MphAddPattern adds a pattern. patternType: 0=Full, 1=Substr, 2=Domain.
func MphAddPattern(h *MphHandle, pattern string, patternType byte) {
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
}

// MphBuild builds the MPH table. Must be called after all patterns are added.
func MphBuild(h *MphHandle) {
	C.xray_mph_build(h.ptr)
}

// MphMatch tests if input matches any pattern in the table.
func MphMatch(h *MphHandle, input string) bool {
	var p *byte
	if len(input) > 0 {
		p = unsafe.StringData(input)
	} else {
		var z byte
		p = &z
	}
	return bool(C.xray_mph_match(h.ptr,
		(*C.uint8_t)(unsafe.Pointer(p)), C.size_t(len(input))))
}

// MphFree releases the MPH table.
func MphFree(h *MphHandle) {
	if h != nil && h.ptr != nil {
		C.xray_mph_free(h.ptr)
		h.ptr = nil
	}
}

// --- GeoIP ---

// IpSetHandle is an opaque handle to a Rust IP prefix set.
type IpSetHandle struct {
	ptr unsafe.Pointer
}

// IpSetNew creates a new IP set.
func IpSetNew() *IpSetHandle {
	return &IpSetHandle{ptr: C.xray_ipset_new()}
}

// IpSetAddPrefix adds a CIDR prefix. ipBytes must be 4 (IPv4) or 16 (IPv6) bytes.
func IpSetAddPrefix(h *IpSetHandle, ipBytes []byte, prefixBits int) {
	if len(ipBytes) == 0 {
		return
	}
	C.xray_ipset_add_prefix(h.ptr,
		(*C.uint8_t)(unsafe.Pointer(&ipBytes[0])), C.size_t(len(ipBytes)),
		C.uint8_t(prefixBits))
}

// IpSetBuild finalizes the IP set after all prefixes are added.
func IpSetBuild(h *IpSetHandle) {
	C.xray_ipset_build(h.ptr)
}

// IpSetContains checks whether an IP is in the set.
func IpSetContains(h *IpSetHandle, ipBytes []byte) bool {
	if len(ipBytes) == 0 {
		return false
	}
	return bool(C.xray_ipset_contains(h.ptr,
		(*C.uint8_t)(unsafe.Pointer(&ipBytes[0])), C.size_t(len(ipBytes))))
}

// IpSetMax4 returns the maximum IPv4 prefix length, or 0xff if empty.
func IpSetMax4(h *IpSetHandle) uint8 {
	return uint8(C.xray_ipset_max4(h.ptr))
}

// IpSetMax6 returns the maximum IPv6 prefix length, or 0xff if empty.
func IpSetMax6(h *IpSetHandle) uint8 {
	return uint8(C.xray_ipset_max6(h.ptr))
}

// IpSetFree releases the IP set.
func IpSetFree(h *IpSetHandle) {
	if h != nil && h.ptr != nil {
		C.xray_ipset_free(h.ptr)
		h.ptr = nil
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
	if n < 0 {
		return 0, errors.New("native: vision pad failed")
	}
	return int(n), nil
}

// VisionUnpad removes Vision padding and extracts content.
// Returns the number of content bytes written to out, or an error.
// The state is updated in-place for streaming across multiple calls.
func VisionUnpad(data []byte, state *VisionUnpadState, uuid []byte, out []byte) (int, error) {
	if state == nil || len(data) == 0 {
		return 0, errors.New("native: nil state or empty data")
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
	if n < 0 {
		return 0, errors.New("native: vision unpad failed")
	}
	return int(n), nil
}

// --- eBPF FFI ---

// EbpfSetup initializes eBPF sockmap with pinned maps for zero-downtime recovery.
func EbpfSetup(pinPath string, maxEntries, corkThreshold uint32) error {
	cPath := C.CString(pinPath)
	defer C.free(unsafe.Pointer(cPath))
	rc := C.xray_ebpf_setup(cPath, C.uint32_t(maxEntries), C.uint32_t(corkThreshold))
	if rc != 0 {
		return errors.New("native: ebpf setup failed")
	}
	return nil
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
