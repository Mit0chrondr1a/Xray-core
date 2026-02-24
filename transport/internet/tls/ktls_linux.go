//go:build linux

package tls

import (
	"context"
	"crypto"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	xerrors "github.com/xtls/xray-core/common/errors"
	"golang.org/x/sys/unix"
)

var extractKeysVersionWarnOnce sync.Once

const (
	SOL_TLS = 282
	TLS_TX  = 1
	TLS_RX  = 2

	TLS_1_2_VERSION = 0x0303
	TLS_1_3_VERSION = 0x0304

	TLS_CIPHER_AES_GCM_128       = 51
	TLS_CIPHER_AES_GCM_256       = 52
	TLS_CIPHER_CHACHA20_POLY1305 = 54
)

// cryptoInfoAESGCM128 corresponds to struct tls_crypto_info + tls12_crypto_info_aes_gcm_128.
type cryptoInfoAESGCM128 struct {
	Version    uint16
	CipherType uint16
	IV         [8]byte
	Key        [16]byte
	Salt       [4]byte
	RecSeq     [8]byte
}

// cryptoInfoAESGCM256 corresponds to struct tls12_crypto_info_aes_gcm_256.
type cryptoInfoAESGCM256 struct {
	Version    uint16
	CipherType uint16
	IV         [8]byte
	Key        [32]byte
	Salt       [4]byte
	RecSeq     [8]byte
}

// cryptoInfoChaCha20Poly1305 corresponds to struct tls12_crypto_info_chacha20_poly1305.
type cryptoInfoChaCha20Poly1305 struct {
	Version    uint16
	CipherType uint16
	IV         [12]byte
	Key        [32]byte
	Salt       [0]byte
	RecSeq     [8]byte
}

// Compile-time assertions: verify struct sizes match kernel ABI.
var (
	_ [40]byte = [unsafe.Sizeof(cryptoInfoAESGCM128{})]byte{}
	_ [56]byte = [unsafe.Sizeof(cryptoInfoAESGCM256{})]byte{}
	_ [56]byte = [unsafe.Sizeof(cryptoInfoChaCha20Poly1305{})]byte{}
)

// keyCapture implements io.Writer to capture TLS 1.3 traffic secrets
// from the KeyLogWriter API (SSLKEYLOGFILE format).
type keyCapture struct {
	mu             sync.Mutex
	clientSecret   []byte
	serverSecret   []byte
	originalWriter io.Writer // chain to original KeyLogWriter if set
}

func (kc *keyCapture) Write(p []byte) (n int, err error) {
	kc.mu.Lock()
	line := string(p)
	if strings.HasPrefix(line, "CLIENT_TRAFFIC_SECRET_0 ") {
		parts := strings.Fields(line)
		if len(parts) >= 3 {
			kc.clientSecret, _ = hex.DecodeString(parts[2])
		}
	} else if strings.HasPrefix(line, "SERVER_TRAFFIC_SECRET_0 ") {
		parts := strings.Fields(line)
		if len(parts) >= 3 {
			kc.serverSecret, _ = hex.DecodeString(parts[2])
		}
	}
	kc.mu.Unlock()
	if kc.originalWriter != nil {
		return kc.originalWriter.Write(p)
	}
	return len(p), nil
}

func (kc *keyCapture) secrets() (clientSecret, serverSecret []byte) {
	kc.mu.Lock()
	defer kc.mu.Unlock()
	return kc.clientSecret, kc.serverSecret
}

// clear zeroes captured secrets.
func (kc *keyCapture) clear() {
	kc.mu.Lock()
	defer kc.mu.Unlock()
	zeroBytes(kc.clientSecret)
	zeroBytes(kc.serverSecret)
}

// setupKeyCapture clones the TLS config and installs a KeyLogWriter on the
// clone to capture traffic secrets for TLS 1.3 kTLS key derivation.
// Cloning avoids mutating shared listener/client configs across connections.
func setupKeyCapture(config *tls.Config) (*tls.Config, *keyCapture) {
	if config == nil {
		return nil, nil
	}
	cloned := config.Clone()
	capture := &keyCapture{
		originalWriter: cloned.KeyLogWriter,
	}
	cloned.KeyLogWriter = capture
	return cloned, capture
}

// deriveKeysFromCapture derives kTLS keys from TLS 1.3 traffic secrets
// captured via KeyLogWriter. This avoids the deep reflection needed by
// extractTLSKeys for TLS 1.3 connections.
func deriveKeysFromCapture(capture *keyCapture, cipherSuite uint16, isClient bool) (*tlsKeys, error) {
	clientSecret, serverSecret := capture.secrets()
	if len(clientSecret) == 0 || len(serverSecret) == 0 {
		return nil, fmt.Errorf("traffic secrets not captured")
	}

	var hashFunc crypto.Hash
	var keyLen int
	switch cipherSuite {
	case tls.TLS_AES_128_GCM_SHA256:
		hashFunc = crypto.SHA256
		keyLen = 16
	case tls.TLS_AES_256_GCM_SHA384:
		hashFunc = crypto.SHA384
		keyLen = 32
	case tls.TLS_CHACHA20_POLY1305_SHA256:
		hashFunc = crypto.SHA256
		keyLen = 32
	default:
		return nil, fmt.Errorf("unsupported TLS 1.3 cipher suite: 0x%04x", cipherSuite)
	}

	var txSecret, rxSecret []byte
	if isClient {
		txSecret = clientSecret
		rxSecret = serverSecret
	} else {
		txSecret = serverSecret
		rxSecret = clientSecret
	}

	txKey := expandLabel(hashFunc, txSecret, "key", nil, keyLen)
	txIV := expandLabel(hashFunc, txSecret, "iv", nil, 12)
	rxKey := expandLabel(hashFunc, rxSecret, "key", nil, keyLen)
	rxIV := expandLabel(hashFunc, rxSecret, "iv", nil, 12)

	return &tlsKeys{
		txKey:    txKey,
		txIV:     txIV,
		txSeq:    make([]byte, 8),
		rxKey:    rxKey,
		rxIV:     rxIV,
		rxSeq:    make([]byte, 8),
		txSecret: txSecret,
		rxSecret: rxSecret,
	}, nil
}

// extractSeqOnly extracts only the sequence numbers from a tls.Conn using
// minimal reflection. This is much more stable than full key extraction
// because it only accesses the seq field (a simple [8]byte array) from
// the out and in halfConn structures.
func extractSeqOnly(conn *tls.Conn) (txSeq, rxSeq []byte, err error) {
	connVal := reflect.ValueOf(conn).Elem()

	outVal := connVal.FieldByName("out")
	inVal := connVal.FieldByName("in")
	if !outVal.IsValid() || !inVal.IsValid() {
		return nil, nil, fmt.Errorf("cannot access tls.Conn out/in fields")
	}

	txSeqField := outVal.FieldByName("seq")
	rxSeqField := inVal.FieldByName("seq")
	if !txSeqField.IsValid() || !rxSeqField.IsValid() {
		return nil, nil, fmt.Errorf("cannot access halfConn.seq fields")
	}

	txSeq = make([]byte, txSeqField.Len())
	rxSeq = make([]byte, rxSeqField.Len())
	for i := 0; i < txSeqField.Len(); i++ {
		txSeq[i] = byte(txSeqField.Index(i).Uint())
	}
	for i := 0; i < rxSeqField.Len(); i++ {
		rxSeq[i] = byte(rxSeqField.Index(i).Uint())
	}

	return txSeq, rxSeq, nil
}

// KTLSState tracks the kTLS state for a connection.
type KTLSState struct {
	Enabled          bool
	TxReady          bool
	RxReady          bool
	keyUpdateHandler *KTLSKeyUpdateHandler
}

// TryEnableKTLS attempts to enable kernel TLS on the given connection.
// It extracts the TLS keys after handshake and configures the kernel.
// Returns the kTLS state (which may be partially enabled if only TX or RX succeeded).
//
// Requirements:
// - Linux 4.13+ for TLS_TX
// - Linux 4.17+ for TLS_RX
// - Standard crypto/tls connection (not uTLS or REALITY)
// - TLS 1.2 or 1.3
// - AES-128-GCM, AES-256-GCM, or ChaCha20-Poly1305
func TryEnableKTLS(conn *Conn) KTLSState {
	state := KTLSState{}

	// Ensure captured traffic secrets are always zeroed, regardless of
	// which return path is taken (early error, partial setup, success).
	if conn.capture != nil {
		defer conn.capture.clear()
	}

	// Get the underlying TCP connection
	tcpConn, ok := conn.NetConn().(*net.TCPConn)
	if !ok {
		return state
	}

	// Get the TLS connection state
	cs := conn.ConnectionState()

	// Only support TLS 1.2 and 1.3
	var tlsVersion uint16
	switch cs.Version {
	case tls.VersionTLS12:
		tlsVersion = TLS_1_2_VERSION
	case tls.VersionTLS13:
		tlsVersion = TLS_1_3_VERSION
	default:
		return state
	}
	if !isKTLSCipherSuiteSupported(cs.CipherSuite) {
		return state
	}
	if !kernelKTLSSupportedCached() {
		return state
	}

	var keys *tlsKeys
	var err error

	// For TLS 1.3: try KeyLogWriter capture path first (more stable)
	if cs.Version == tls.VersionTLS13 && conn.capture != nil {
		keys, err = deriveKeysFromCapture(conn.capture, cs.CipherSuite, conn.isClient)
		if err == nil {
			// Get actual sequence numbers via minimal reflection
			txSeq, rxSeq, seqErr := extractSeqOnly(conn.Conn)
			if seqErr == nil {
				keys.txSeq = txSeq
				keys.rxSeq = rxSeq
			}
			// If seq extraction fails, keys still have zero sequences
			// which may work if called immediately after handshake
		}
	}

	// Fallback: full reflection (always works for TLS 1.2, fallback for TLS 1.3)
	if keys == nil {
		keys, err = extractTLSKeys(conn.Conn)
		if err != nil {
			return state
		}
	}

	// Get the file descriptor
	rawConn, err := tcpConn.SyscallConn()
	if err != nil {
		return state
	}

	// Perform all kTLS setup in a single Control call to minimize
	// runtime fd-lock acquisitions (3 → 1).
	var setupErr error
	var txErr error
	var rxErr error
	if err := rawConn.Control(func(fd uintptr) {
		intFD := int(fd)

		// Set TCP_ULP to "tls"
		if err := syscall.SetsockoptString(intFD, syscall.SOL_TCP, unix.TCP_ULP, "tls"); err != nil {
			setupErr = fmt.Errorf("setsockopt TCP_ULP=tls: %w", err)
			return
		}

		state.Enabled = true

		// Configure TX (send direction)
		if err := setKTLSCryptoInfo(intFD, TLS_TX, tlsVersion, cs.CipherSuite, keys.txKey, keys.txIV, keys.txSeq); err == nil {
			state.TxReady = true
		} else {
			txErr = err
		}

		// Configure RX (receive direction)
		if err := setKTLSCryptoInfo(intFD, TLS_RX, tlsVersion, cs.CipherSuite, keys.rxKey, keys.rxIV, keys.rxSeq); err == nil {
			state.RxReady = true
		} else {
			rxErr = err
		}

		// Only report as enabled if at least one direction succeeded.
		// ULP installation alone is a no-op without crypto info.
		if !state.TxReady && !state.RxReady {
			state.Enabled = false
			if setupErr == nil && txErr != nil && rxErr != nil {
				setupErr = fmt.Errorf("kTLS TX+RX setup failed (tx=%v, rx=%v)", txErr, rxErr)
			}
		}

		// For TLS 1.3 with RX offload, create a KeyUpdate handler so we can
		// process EKEYEXPIRED errors when the peer rotates traffic keys.
		if state.RxReady && cs.Version == tls.VersionTLS13 && keys.rxSecret != nil {
			state.keyUpdateHandler = newKTLSKeyUpdateHandler(
				intFD, cs.CipherSuite, keys.rxSecret, keys.txSecret,
			)
		}
	}); err != nil {
		keys.zero()
		return state
	}

	if setupErr != nil {
		xerrors.LogWarning(
			context.Background(),
			"ktls: setup failed version=", cs.Version,
			" cipherSuite=0x", fmt.Sprintf("%04x", cs.CipherSuite),
			": ", setupErr,
		)
	} else if txErr != nil || rxErr != nil {
		xerrors.LogWarning(
			context.Background(),
			"ktls: partial setup version=", cs.Version,
			" cipherSuite=0x", fmt.Sprintf("%04x", cs.CipherSuite),
			" txReady=", state.TxReady,
			" rxReady=", state.RxReady,
			" txErr=", txErr,
			" rxErr=", rxErr,
		)
	}

	// Zero key material now that it's been handed to the kernel / KeyUpdate handler.
	keys.zero()

	return state
}

var (
	ktlsSupportOnce sync.Once
	ktlsSupportOK   bool
	fullKTLSOnce    sync.Once
	fullKTLSOK      bool
	ktlsProbeCache  sync.Map
)

func kernelKTLSSupportedCached() bool {
	ktlsSupportOnce.Do(func() {
		ktlsSupportOK = KTLSSupported()
	})
	return ktlsSupportOK
}

// NativeFullKTLSSupported reports whether this host supports full bidirectional
// kTLS for the TLS 1.3 cipher suites used by native REALITY/TLS paths.
func NativeFullKTLSSupported() bool {
	fullKTLSOnce.Do(func() {
		if !kernelKTLSSupportedCached() {
			xerrors.LogDebug(context.Background(), "kTLS full probe: kernel kTLS unavailable")
			return
		}
		for _, suite := range []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		} {
			if !probeFullKTLSForSuiteCached(TLS_1_3_VERSION, suite) {
				xerrors.LogDebug(context.Background(), "kTLS full probe failed for TLS1.3 suite ", tls.CipherSuiteName(suite), " (", suite, ")")
				return
			}
		}
		fullKTLSOK = true
		xerrors.LogDebug(context.Background(), "kTLS full probe passed for required TLS1.3 suites")
	})
	return fullKTLSOK
}

// NativeFullKTLSSupportedForTLSConfig reports whether native Rust TLS can be
// safely used for this server TLS config without risking handshake-time hard
// failures due to missing full bidirectional kTLS support.
func NativeFullKTLSSupportedForTLSConfig(config *Config) bool {
	if !kernelKTLSSupportedCached() {
		return false
	}
	tls12Enabled, tls13Enabled := nativeTLSConfigVersions(config)

	if tls12Enabled {
		for _, suite := range []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		} {
			if !probeFullKTLSForSuiteCached(TLS_1_2_VERSION, suite) {
				return false
			}
		}
	}
	if tls13Enabled {
		for _, suite := range []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		} {
			if !probeFullKTLSForSuiteCached(TLS_1_3_VERSION, suite) {
				return false
			}
		}
	}
	return true
}

type ktlsProbeResult struct {
	once sync.Once
	ok   bool
}

func probeFullKTLSForSuiteCached(version uint16, cipherSuite uint16) bool {
	key := uint32(version)<<16 | uint32(cipherSuite)
	v, _ := ktlsProbeCache.LoadOrStore(key, &ktlsProbeResult{})
	entry := v.(*ktlsProbeResult)
	entry.once.Do(func() {
		entry.ok = probeFullKTLSForSuite(version, cipherSuite)
	})
	return entry.ok
}

func nativeTLSConfigVersions(config *Config) (tls12Enabled bool, tls13Enabled bool) {
	lo := uint16(tls.VersionTLS12)
	hi := uint16(tls.VersionTLS13)
	if config != nil {
		if v, ok := parseNativeTLSVersion(config.MinVersion); ok {
			lo = v
		}
		if v, ok := parseNativeTLSVersion(config.MaxVersion); ok {
			hi = v
		}
	}
	tls12Enabled = lo <= tls.VersionTLS12 && hi >= tls.VersionTLS12
	tls13Enabled = lo <= tls.VersionTLS13 && hi >= tls.VersionTLS13
	// Keep consistent with Rust build_protocol_versions(): if the configured
	// range maps to no supported versions, native TLS falls back to TLS 1.3.
	if !tls12Enabled && !tls13Enabled {
		tls13Enabled = true
	}
	return
}

func parseNativeTLSVersion(v string) (uint16, bool) {
	switch v {
	case "1.0":
		return tls.VersionTLS10, true
	case "1.1":
		return tls.VersionTLS11, true
	case "1.2":
		return tls.VersionTLS12, true
	case "1.3":
		return tls.VersionTLS13, true
	default:
		return 0, false
	}
}

func probeFullKTLSForSuite(version uint16, cipherSuite uint16) bool {
	keyLen, ok := ktlsKeyLen(cipherSuite)
	if !ok {
		return false
	}

	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: 0,
	})
	if err != nil {
		return false
	}
	defer ln.Close()

	serverConnCh := make(chan *net.TCPConn, 1)
	serverErrCh := make(chan error, 1)
	go func() {
		c, err := ln.AcceptTCP()
		if err != nil {
			serverErrCh <- err
			return
		}
		serverConnCh <- c
	}()

	client, err := net.DialTCP("tcp4", nil, ln.Addr().(*net.TCPAddr))
	if err != nil {
		return false
	}
	defer client.Close()

	var server *net.TCPConn
	select {
	case server = <-serverConnCh:
	case <-serverErrCh:
		return false
	case <-time.After(500 * time.Millisecond):
		return false
	}
	defer server.Close()

	rawConn, err := client.SyscallConn()
	if err != nil {
		return false
	}

	var txErr error
	var rxErr error
	if err := rawConn.Control(func(fd uintptr) {
		intFD := int(fd)
		if ulpErr := syscall.SetsockoptString(intFD, syscall.SOL_TCP, unix.TCP_ULP, "tls"); ulpErr != nil {
			txErr = ulpErr
			return
		}
		key := make([]byte, keyLen)
		iv := make([]byte, 12)
		seq := make([]byte, 8)
		txErr = setKTLSCryptoInfo(intFD, TLS_TX, version, cipherSuite, key, iv, seq)
		rxErr = setKTLSCryptoInfo(intFD, TLS_RX, version, cipherSuite, key, iv, seq)
	}); err != nil {
		return false
	}

	return txErr == nil && rxErr == nil
}

func ktlsKeyLen(cipherSuite uint16) (int, bool) {
	switch cipherSuite {
	case tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
		return 16, true
	case tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
		return 32, true
	default:
		return 0, false
	}
}

// tlsKeys contains the extracted TLS session keys.
type tlsKeys struct {
	txKey, txIV, txSeq []byte
	rxKey, rxIV, rxSeq []byte
	txSecret, rxSecret []byte // TLS 1.3 traffic secrets for KeyUpdate derivation
}

// zero overwrites all key material.
func (k *tlsKeys) zero() {
	zeroBytes(k.txKey)
	zeroBytes(k.txIV)
	zeroBytes(k.rxKey)
	zeroBytes(k.rxIV)
	zeroBytes(k.txSecret)
	zeroBytes(k.rxSecret)
}

// maxTestedGoVersion is the newest Go version against which reflective key
// extraction has been verified. Bump after confirming crypto/tls internals
// are unchanged in a new Go release.
const maxTestedGoVersion = "go1.25"

// extractTLSKeys extracts TLS keys from a tls.Conn using reflection.
// This is necessarily fragile and depends on Go's internal tls.Conn structure.
func extractTLSKeys(conn *tls.Conn) (*tlsKeys, error) {
	if !strings.HasPrefix(runtime.Version(), maxTestedGoVersion) {
		// Log once per new Go version so operators know reflection may break.
		extractKeysVersionWarnOnce.Do(func() {
			fmt.Fprintf(os.Stderr, "ktls: extractTLSKeys tested up to %s, running %s — monitor for failures\n",
				maxTestedGoVersion, runtime.Version())
		})
	}
	// Access the unexported fields via reflection
	connVal := reflect.ValueOf(conn).Elem()

	// Get the "out" (tx) and "in" (rx) half-connections
	outVal := connVal.FieldByName("out")
	inVal := connVal.FieldByName("in")

	if !outVal.IsValid() || !inVal.IsValid() {
		return nil, fmt.Errorf("cannot access tls.Conn internal fields")
	}

	keys := &tlsKeys{}

	// Extract keys from halfConn structures
	var err error
	keys.txKey, keys.txIV, keys.txSeq, keys.txSecret, err = extractHalfConnKeys(outVal)
	if err != nil {
		return nil, fmt.Errorf("extract TX keys: %w", err)
	}

	keys.rxKey, keys.rxIV, keys.rxSeq, keys.rxSecret, err = extractHalfConnKeys(inVal)
	if err != nil {
		return nil, fmt.Errorf("extract RX keys: %w", err)
	}

	return keys, nil
}

// extractHalfConnKeys extracts key, IV, sequence number, and traffic secret from a halfConn.
func extractHalfConnKeys(halfConn reflect.Value) (key, iv, seq, secret []byte, err error) {
	// Get the sequence number
	seqField := halfConn.FieldByName("seq")
	if seqField.IsValid() && seqField.Kind() == reflect.Array {
		seqBytes := make([]byte, seqField.Len())
		for i := 0; i < seqField.Len(); i++ {
			seqBytes[i] = byte(seqField.Index(i).Uint())
		}
		seq = seqBytes
	}

	// Extract traffic secret (TLS 1.3 only; nil for TLS 1.2)
	secretField := halfConn.FieldByName("trafficSecret")
	if secretField.IsValid() && secretField.Kind() == reflect.Slice {
		secret = fieldToBytes(secretField)
	}

	// Get the cipher (which is an AEAD interface)
	cipherField := halfConn.FieldByName("cipher")
	if !cipherField.IsValid() || cipherField.IsNil() {
		return nil, nil, nil, nil, fmt.Errorf("cipher field not found or nil")
	}

	// The cipher is wrapped in a struct that contains the key and nonce.
	// For TLS 1.3, it's a *tls.cipherSuiteTLS13 with an AEAD.
	// For TLS 1.2, it's a crypto/cipher.AEAD directly.
	// We need to dig into the implementation to find the key.
	cipherVal := cipherField
	if cipherVal.Kind() == reflect.Interface || cipherVal.Kind() == reflect.Ptr {
		cipherVal = cipherVal.Elem()
	}
	if !cipherVal.IsValid() {
		return nil, nil, nil, nil, fmt.Errorf("cipher value not valid")
	}

	// Try to find key and nonce fields
	if keyField := findField(cipherVal, "key"); keyField.IsValid() {
		key = fieldToBytes(keyField)
	}
	if key == nil {
		// AES-GCM implementations often expose only expanded round keys.
		key = extractExpandedAESKey(cipherVal)
	}
	if ivField := findField(cipherVal, "nonceMask"); ivField.IsValid() {
		iv = fieldToBytes(ivField)
	} else if ivField := findField(cipherVal, "fixedNonce"); ivField.IsValid() {
		iv = fieldToBytes(ivField)
	} else if ivField := findField(cipherVal, "nonce"); ivField.IsValid() {
		iv = fieldToBytes(ivField)
	}

	if key == nil || iv == nil {
		return nil, nil, nil, nil, fmt.Errorf("could not extract key or IV from cipher")
	}

	return key, iv, seq, secret, nil
}

// findField recursively searches for a named field in a reflect.Value.
func findField(v reflect.Value, name string) reflect.Value {
	return findFieldRecursive(v, name, 0)
}

func findFieldRecursive(v reflect.Value, name string, depth int) reflect.Value {
	if depth > 16 || !v.IsValid() {
		return reflect.Value{}
	}
	if v.Kind() == reflect.Interface || v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return reflect.Value{}
		}
		return findFieldRecursive(v.Elem(), name, depth+1)
	}
	if v.Kind() != reflect.Struct {
		return reflect.Value{}
	}

	// Direct field
	if f := v.FieldByName(name); f.IsValid() {
		return f
	}

	// Search nested fields
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		if result := findFieldRecursive(field, name, depth+1); result.IsValid() {
			return result
		}
	}

	return reflect.Value{}
}

// fieldToBytes converts a reflect.Value to a byte slice.
func fieldToBytes(v reflect.Value) []byte {
	switch v.Kind() {
	case reflect.Slice:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			return append([]byte(nil), v.Bytes()...)
		}
	case reflect.Array:
		bytes := make([]byte, v.Len())
		for i := 0; i < v.Len(); i++ {
			bytes[i] = byte(v.Index(i).Uint())
		}
		return bytes
	}
	return nil
}

// extractExpandedAESKey extracts the original AES key from expanded round keys.
func extractExpandedAESKey(v reflect.Value) []byte {
	return extractExpandedAESKeyRecursive(v, 0)
}

func extractExpandedAESKeyRecursive(v reflect.Value, depth int) []byte {
	if depth > 16 || !v.IsValid() {
		return nil
	}
	if v.Kind() == reflect.Interface || v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return nil
		}
		return extractExpandedAESKeyRecursive(v.Elem(), depth+1)
	}
	if v.Kind() != reflect.Struct {
		return nil
	}

	roundsField := v.FieldByName("rounds")
	encField := v.FieldByName("enc")
	if roundsField.IsValid() && encField.IsValid() {
		rounds := -1
		switch roundsField.Kind() {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			rounds = int(roundsField.Int())
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
			rounds = int(roundsField.Uint())
		}
		keyWords := 0
		switch rounds {
		case 10:
			keyWords = 4 // AES-128
		case 12:
			keyWords = 6 // AES-192
		case 14:
			keyWords = 8 // AES-256
		}
		if keyWords > 0 && (encField.Kind() == reflect.Array || encField.Kind() == reflect.Slice) {
			if encField.Type().Elem().Kind() == reflect.Uint32 && encField.Len() >= keyWords {
				key := make([]byte, keyWords*4)
				for i := 0; i < keyWords; i++ {
					binary.BigEndian.PutUint32(key[i*4:], uint32(encField.Index(i).Uint()))
				}
				return key
			}
		}
	}

	for i := 0; i < v.NumField(); i++ {
		if key := extractExpandedAESKeyRecursive(v.Field(i), depth+1); key != nil {
			return key
		}
	}

	return nil
}

// setKTLSSockopt performs the setsockopt syscall for kTLS crypto info.
func setKTLSSockopt(fd int, direction int, info unsafe.Pointer, size uintptr) error {
	_, _, errno := syscall.Syscall6(
		syscall.SYS_SETSOCKOPT,
		uintptr(fd),
		uintptr(SOL_TLS),
		uintptr(direction),
		uintptr(info),
		size,
		0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}

// setKTLSCryptoInfo configures kTLS for one direction (TX or RX).
func setKTLSCryptoInfo(fd int, direction int, version uint16, cipherSuite uint16, key, iv, seq []byte) error {
	switch cipherSuite {
	case tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
		if len(key) != 16 {
			return fmt.Errorf("invalid key length for AES-128-GCM: %d", len(key))
		}
		info := cryptoInfoAESGCM128{
			Version:    version,
			CipherType: TLS_CIPHER_AES_GCM_128,
		}
		copy(info.Key[:], key)
		if len(iv) >= 12 {
			copy(info.Salt[:], iv[:4])
			copy(info.IV[:], iv[4:12])
		} else if len(iv) >= 4 {
			copy(info.Salt[:], iv[:4])
		}
		if seq != nil {
			copy(info.RecSeq[:], seq)
		}
		err := setKTLSSockopt(fd, direction, unsafe.Pointer(&info), unsafe.Sizeof(info))
		zeroCryptoInfo(unsafe.Pointer(&info), unsafe.Sizeof(info))
		return err

	case tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
		if len(key) != 32 {
			return fmt.Errorf("invalid key length for AES-256-GCM: %d", len(key))
		}
		info := cryptoInfoAESGCM256{
			Version:    version,
			CipherType: TLS_CIPHER_AES_GCM_256,
		}
		copy(info.Key[:], key)
		if len(iv) >= 12 {
			copy(info.Salt[:], iv[:4])
			copy(info.IV[:], iv[4:12])
		} else if len(iv) >= 4 {
			copy(info.Salt[:], iv[:4])
		}
		if seq != nil {
			copy(info.RecSeq[:], seq)
		}
		err := setKTLSSockopt(fd, direction, unsafe.Pointer(&info), unsafe.Sizeof(info))
		zeroCryptoInfo(unsafe.Pointer(&info), unsafe.Sizeof(info))
		return err

	case tls.TLS_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
		if len(key) != 32 {
			return fmt.Errorf("invalid key length for ChaCha20-Poly1305: %d", len(key))
		}
		info := cryptoInfoChaCha20Poly1305{
			Version:    version,
			CipherType: TLS_CIPHER_CHACHA20_POLY1305,
		}
		copy(info.Key[:], key)
		if len(iv) >= 12 {
			copy(info.IV[:], iv[:12])
		}
		if seq != nil {
			copy(info.RecSeq[:], seq)
		}
		err := setKTLSSockopt(fd, direction, unsafe.Pointer(&info), unsafe.Sizeof(info))
		zeroCryptoInfo(unsafe.Pointer(&info), unsafe.Sizeof(info))
		return err

	default:
		return fmt.Errorf("unsupported cipher suite for kTLS: 0x%04x", cipherSuite)
	}
}

// getRecordSeq reads the current TLS record sequence number from the kernel
// via getsockopt(SOL_TLS, direction). The rec_seq field is an 8-byte big-endian
// counter at a cipher-dependent offset within the tls_crypto_info struct.
func getRecordSeq(fd int, direction int, cipherSuiteID uint16) (uint64, error) {
	var size uint32
	var recSeqOffset int
	switch cipherSuiteID {
	case tls.TLS_AES_128_GCM_SHA256:
		size = uint32(unsafe.Sizeof(cryptoInfoAESGCM128{}))
		recSeqOffset = 32
	case tls.TLS_AES_256_GCM_SHA384:
		size = uint32(unsafe.Sizeof(cryptoInfoAESGCM256{}))
		recSeqOffset = 48
	case tls.TLS_CHACHA20_POLY1305_SHA256:
		size = uint32(unsafe.Sizeof(cryptoInfoChaCha20Poly1305{}))
		recSeqOffset = 48
	default:
		return 0, fmt.Errorf("unsupported cipher suite for getRecordSeq: 0x%04x", cipherSuiteID)
	}

	buf := make([]byte, int(size))
	_, _, errno := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		uintptr(fd),
		uintptr(SOL_TLS),
		uintptr(direction),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		0,
	)
	if errno != 0 {
		return 0, errno
	}
	if int(size) < recSeqOffset+8 {
		return 0, fmt.Errorf("short SOL_TLS getsockopt payload: got %d bytes", size)
	}

	seq := binary.BigEndian.Uint64(buf[recSeqOffset : recSeqOffset+8])
	zeroBytes(buf) // zero full crypto_info (contains key material from kernel)
	return seq, nil
}

// zeroBytes overwrites b with zeroes.
//
//go:noinline
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// zeroCryptoInfo zeroes a stack-allocated crypto info struct after setsockopt
// copies it to kernel space, preventing key material from lingering on the stack.
//
//go:noinline
func zeroCryptoInfo(ptr unsafe.Pointer, size uintptr) {
	zeroBytes(unsafe.Slice((*byte)(ptr), size))
}

// KTLSSupported checks if kernel TLS is available.
func KTLSSupported() bool {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		return false
	}
	defer syscall.Close(fd)

	err = syscall.SetsockoptString(fd, syscall.SOL_TCP, unix.TCP_ULP, "tls")
	return err == nil
}
