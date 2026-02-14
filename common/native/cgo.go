//go:build cgo && linux

package native

/*
#cgo LDFLAGS: -L${SRCDIR}/../../rust/xray-rust/target/release -lxray_rust

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
*/
import "C"

import (
	"errors"
	"runtime"
	"unsafe"
)

// Available returns true when the native Rust library is linked.
func Available() bool {
	return true
}

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

// ErrRealityAuthFailed indicates REALITY auth failed and Go should handle fallback.
var ErrRealityAuthFailed = errors.New("REALITY auth failed: needs fallback")
