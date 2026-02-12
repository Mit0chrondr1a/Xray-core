//go:build linux

package tls

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"reflect"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

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

// KTLSState tracks the kTLS state for a connection.
type KTLSState struct {
	Enabled bool
	TxReady bool
	RxReady bool
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

	// Extract keys using reflection
	keys, err := extractTLSKeys(conn.Conn)
	if err != nil {
		return state
	}

	// Get the file descriptor
	rawConn, err := tcpConn.SyscallConn()
	if err != nil {
		return state
	}

	// Perform all kTLS setup in a single Control call to minimize
	// runtime fd-lock acquisitions (3 → 1).
	if err := rawConn.Control(func(fd uintptr) {
		intFD := int(fd)

		// Set TCP_ULP to "tls"
		if err := syscall.SetsockoptString(intFD, syscall.SOL_TCP, unix.TCP_ULP, "tls"); err != nil {
			return
		}

		state.Enabled = true

		// Configure TX (send direction)
		if err := setKTLSCryptoInfo(intFD, TLS_TX, tlsVersion, cs.CipherSuite, keys.txKey, keys.txIV, keys.txSeq); err == nil {
			state.TxReady = true
		}

		// Configure RX (receive direction)
		if err := setKTLSCryptoInfo(intFD, TLS_RX, tlsVersion, cs.CipherSuite, keys.rxKey, keys.rxIV, keys.rxSeq); err == nil {
			state.RxReady = true
		}

		// Only report as enabled if at least one direction succeeded.
		// ULP installation alone is a no-op without crypto info.
		if !state.TxReady && !state.RxReady {
			state.Enabled = false
		}
	}); err != nil {
		return state
	}

	return state
}

var (
	ktlsSupportOnce sync.Once
	ktlsSupportOK   bool
)

func kernelKTLSSupportedCached() bool {
	ktlsSupportOnce.Do(func() {
		ktlsSupportOK = KTLSSupported()
	})
	return ktlsSupportOK
}

// tlsKeys contains the extracted TLS session keys.
type tlsKeys struct {
	txKey []byte
	txIV  []byte
	txSeq []byte
	rxKey []byte
	rxIV  []byte
	rxSeq []byte
}

// extractTLSKeys extracts TLS keys from a tls.Conn using reflection.
// This is necessarily fragile and depends on Go's internal tls.Conn structure.
func extractTLSKeys(conn *tls.Conn) (*tlsKeys, error) {
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
	keys.txKey, keys.txIV, keys.txSeq, err = extractHalfConnKeys(outVal)
	if err != nil {
		return nil, fmt.Errorf("extract TX keys: %w", err)
	}

	keys.rxKey, keys.rxIV, keys.rxSeq, err = extractHalfConnKeys(inVal)
	if err != nil {
		return nil, fmt.Errorf("extract RX keys: %w", err)
	}

	return keys, nil
}

// extractHalfConnKeys extracts key, IV, and sequence number from a halfConn.
func extractHalfConnKeys(halfConn reflect.Value) (key, iv, seq []byte, err error) {
	// Get the sequence number
	seqField := halfConn.FieldByName("seq")
	if seqField.IsValid() && seqField.Kind() == reflect.Array {
		seqBytes := make([]byte, seqField.Len())
		for i := 0; i < seqField.Len(); i++ {
			seqBytes[i] = byte(seqField.Index(i).Uint())
		}
		seq = seqBytes
	}

	// Get the cipher (which is an AEAD interface)
	cipherField := halfConn.FieldByName("cipher")
	if !cipherField.IsValid() || cipherField.IsNil() {
		return nil, nil, nil, fmt.Errorf("cipher field not found or nil")
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
		return nil, nil, nil, fmt.Errorf("cipher value not valid")
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
		return nil, nil, nil, fmt.Errorf("could not extract key or IV from cipher")
	}

	return key, iv, seq, nil
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
		return setKTLSSockopt(fd, direction, unsafe.Pointer(&info), unsafe.Sizeof(info))

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
		return setKTLSSockopt(fd, direction, unsafe.Pointer(&info), unsafe.Sizeof(info))

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
		return setKTLSSockopt(fd, direction, unsafe.Pointer(&info), unsafe.Sizeof(info))

	default:
		return fmt.Errorf("unsupported cipher suite for kTLS: 0x%04x", cipherSuite)
	}
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
