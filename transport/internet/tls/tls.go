package tls

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"math/big"
	gonet "net"
	"syscall"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/native"
	"github.com/xtls/xray-core/common/net"
)

type Interface interface {
	net.Conn
	HandshakeContext(ctx context.Context) error
	VerifyHostname(host string) error
	HandshakeContextServerName(ctx context.Context) string
	NegotiatedProtocol() string
}

var _ buf.Writer = (*Conn)(nil)
var _ Interface = (*Conn)(nil)

type Conn struct {
	*tls.Conn
	ktls         KTLSState
	isClient     bool
	capture      *keyCapture
	writeRecords uint64
}

const (
	tlsCloseTimeout    = 250 * time.Millisecond
	maxRecordPayload   = 16384    // TLS max record payload size
	keyUpdateThreshold = 1 << 24  // ~16.7M records, conservative limit below AES-GCM 2^24.5
)

// Read overrides tls.Conn.Read. When kTLS RX is active, reads bypass the
// Go TLS record layer (the kernel already decrypted) and handle EKEYEXPIRED
// from TLS 1.3 KeyUpdate messages.
func (c *Conn) Read(b []byte) (int, error) {
	if c.ktls.RxReady {
		n, err := c.Conn.NetConn().Read(b)
		if err != nil && isKeyExpired(err) && c.ktls.keyUpdateHandler != nil {
			if herr := c.ktls.keyUpdateHandler.Handle(); herr != nil {
				return 0, herr
			}
			return c.Conn.NetConn().Read(b)
		}
		return n, err
	}
	return c.Conn.Read(b)
}

// Write overrides tls.Conn.Write. When kTLS TX is active, writes bypass the
// Go TLS record layer (the kernel handles encryption) and proactively rotate
// TX keys after keyUpdateThreshold records to stay within AES-GCM limits.
func (c *Conn) Write(b []byte) (int, error) {
	if c.ktls.TxReady {
		n, err := c.Conn.NetConn().Write(b)
		if err == nil && c.ktls.keyUpdateHandler != nil {
			records := uint64((n + maxRecordPayload - 1) / maxRecordPayload)
			c.writeRecords += records
			if c.writeRecords >= keyUpdateThreshold {
				c.ktls.keyUpdateHandler.InitiateUpdate()
				c.writeRecords = 0
			}
		}
		return n, err
	}
	return c.Conn.Write(b)
}

// Close overrides tls.Conn.Close. When kTLS TX is active, closing via
// tls.Conn.Close() would double-encrypt the close_notify alert. Instead
// we close the raw socket directly.
func (c *Conn) Close() error {
	if c.ktls.TxReady {
		return c.Conn.NetConn().Close()
	}
	timer := time.AfterFunc(tlsCloseTimeout, func() {
		c.Conn.NetConn().Close()
	})
	defer timer.Stop()
	return c.Conn.Close()
}

// KTLSKeyUpdateHandler returns the KeyUpdate handler for this connection,
// or nil if kTLS RX is not active or the connection uses TLS 1.2.
func (c *Conn) KTLSKeyUpdateHandler() *KTLSKeyUpdateHandler {
	return c.ktls.keyUpdateHandler
}

func (c *Conn) WriteMultiBuffer(mb buf.MultiBuffer) error {
	mb = buf.Compact(mb)
	mb, err := buf.WriteMultiBuffer(c, mb)
	buf.ReleaseMulti(mb)
	return err
}

func (c *Conn) HandshakeContextServerName(ctx context.Context) string {
	if err := c.HandshakeContext(ctx); err != nil {
		return ""
	}
	return c.ConnectionState().ServerName
}

func (c *Conn) NegotiatedProtocol() string {
	state := c.ConnectionState()
	return state.NegotiatedProtocol
}

// HandshakeAndEnableKTLS performs the TLS handshake and attempts to enable
// kernel TLS offload. kTLS failure is not an error — it degrades gracefully.
func (c *Conn) HandshakeAndEnableKTLS(ctx context.Context) error {
	if err := c.HandshakeContext(ctx); err != nil {
		return err
	}
	c.ktls = TryEnableKTLS(c)
	logCtx := ctx
	if logCtx == nil {
		logCtx = context.Background()
	}
	if c.ktls.Enabled {
		if !c.ktls.TxReady || !c.ktls.RxReady {
			errors.LogDebug(logCtx, "kTLS partially enabled: tx=", c.ktls.TxReady, " rx=", c.ktls.RxReady)
		}
		return nil
	}

	cs := c.ConnectionState()
	switch {
	case !isKTLSCipherSuiteSupported(cs.CipherSuite):
		errors.LogDebug(logCtx, "kTLS not enabled: unsupported cipher suite ", cs.CipherSuite)
	case cs.Version != tls.VersionTLS12 && cs.Version != tls.VersionTLS13:
		errors.LogDebug(logCtx, "kTLS not enabled: unsupported TLS version ", cs.Version)
	case !isUnderlyingTCPConn(c.Conn.NetConn()):
		errors.LogDebug(logCtx, "kTLS not enabled: underlying transport is not TCP")
	default:
		errors.LogDebug(logCtx, "kTLS not enabled: kernel/permission/key extraction constraints")
	}
	return nil
}

func isUnderlyingTCPConn(conn gonet.Conn) bool {
	_, ok := conn.(*gonet.TCPConn)
	return ok
}

func isKTLSCipherSuiteSupported(cipherSuite uint16) bool {
	switch cipherSuite {
	case tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
		return true
	default:
		return false
	}
}

// KTLSEnabled returns the kTLS state for this connection.
func (c *Conn) KTLSEnabled() KTLSState {
	return c.ktls
}

// Client initiates a TLS client handshake on the given connection.
func Client(c net.Conn, config *tls.Config) net.Conn {
	tlsConfig, capture := setupKeyCapture(config)
	tlsConn := tls.Client(c, tlsConfig)
	return &Conn{Conn: tlsConn, isClient: true, capture: capture}
}

// Server initiates a TLS server handshake on the given connection.
func Server(c net.Conn, config *tls.Config) net.Conn {
	tlsConfig, capture := setupKeyCapture(config)
	tlsConn := tls.Server(c, tlsConfig)
	return &Conn{Conn: tlsConn, isClient: false, capture: capture}
}

type UConn struct {
	*utls.UConn
}

var _ Interface = (*UConn)(nil)

func (c *UConn) Close() error {
	timer := time.AfterFunc(tlsCloseTimeout, func() {
		c.Conn.NetConn().Close()
	})
	defer timer.Stop()
	return c.Conn.Close()
}

func (c *UConn) HandshakeContextServerName(ctx context.Context) string {
	if err := c.HandshakeContext(ctx); err != nil {
		return ""
	}
	return c.ConnectionState().ServerName
}

// WebsocketHandshake basically calls UConn.Handshake inside it but it will only send
// http/1.1 in its ALPN.
func (c *UConn) WebsocketHandshakeContext(ctx context.Context) error {
	// Build the handshake state. This will apply every variable of the TLS of the
	// fingerprint in the UConn
	if err := c.BuildHandshakeState(); err != nil {
		return err
	}
	// Iterate over extensions and check for utls.ALPNExtension
	hasALPNExtension := false
	for _, extension := range c.Extensions {
		if alpn, ok := extension.(*utls.ALPNExtension); ok {
			hasALPNExtension = true
			alpn.AlpnProtocols = []string{"http/1.1"}
			break
		}
	}
	if !hasALPNExtension { // Append extension if doesn't exists
		c.Extensions = append(c.Extensions, &utls.ALPNExtension{AlpnProtocols: []string{"http/1.1"}})
	}
	// Rebuild the client hello and do the handshake
	if err := c.BuildHandshakeState(); err != nil {
		return err
	}
	return c.HandshakeContext(ctx)
}

func (c *UConn) NegotiatedProtocol() string {
	state := c.ConnectionState()
	return state.NegotiatedProtocol
}

func UClient(c net.Conn, config *tls.Config, fingerprint *utls.ClientHelloID) net.Conn {
	utlsConn := utls.UClient(c, copyConfig(config), *fingerprint)
	return &UConn{UConn: utlsConn}
}

func GeneraticUClient(c net.Conn, config *tls.Config) *utls.UConn {
	return utls.UClient(c, copyConfig(config), utls.HelloChrome_Auto)
}

// RustConn wraps a raw TCP connection after Rust-side rustls handshake + kTLS setup.
// The kernel handles TLS encryption/decryption via kTLS, so Read/Write go directly
// to the underlying connection.
type RustConn struct {
	rawConn      net.Conn
	state        *native.TlsStateHandle
	ktls         KTLSState
	alpn         string
	version      uint16
	cipher       uint16
	serverName   string
	writeRecords uint64
}

var _ Interface = (*RustConn)(nil)

func (c *RustConn) Read(b []byte) (int, error) {
	if c.ktls.RxReady {
		n, err := c.rawConn.Read(b)
		if err != nil && isKeyExpired(err) && c.ktls.keyUpdateHandler != nil {
			if herr := c.ktls.keyUpdateHandler.Handle(); herr != nil {
				return 0, herr
			}
			return c.rawConn.Read(b)
		}
		return n, err
	}
	return c.rawConn.Read(b)
}

func (c *RustConn) Write(b []byte) (int, error) {
	n, err := c.rawConn.Write(b)
	if err == nil && c.ktls.keyUpdateHandler != nil {
		records := uint64((n + maxRecordPayload - 1) / maxRecordPayload)
		c.writeRecords += records
		if c.writeRecords >= keyUpdateThreshold {
			c.ktls.keyUpdateHandler.InitiateUpdate()
			c.writeRecords = 0
		}
	}
	return n, err
}

func (c *RustConn) Close() error {
	if c.state != nil {
		native.TlsStateFree(c.state)
		c.state = nil
	}
	return c.rawConn.Close()
}

func (c *RustConn) NetConn() gonet.Conn                        { return c.rawConn }
func (c *RustConn) LocalAddr() gonet.Addr                      { return c.rawConn.LocalAddr() }
func (c *RustConn) RemoteAddr() gonet.Addr                     { return c.rawConn.RemoteAddr() }
func (c *RustConn) SetDeadline(t time.Time) error              { return c.rawConn.SetDeadline(t) }
func (c *RustConn) SetReadDeadline(t time.Time) error          { return c.rawConn.SetReadDeadline(t) }
func (c *RustConn) SetWriteDeadline(t time.Time) error         { return c.rawConn.SetWriteDeadline(t) }
func (c *RustConn) HandshakeContext(ctx context.Context) error { return nil }
func (c *RustConn) VerifyHostname(host string) error           { return nil }

func (c *RustConn) HandshakeContextServerName(ctx context.Context) string {
	return c.serverName
}

func (c *RustConn) NegotiatedProtocol() string {
	return c.alpn
}

func (c *RustConn) WriteMultiBuffer(mb buf.MultiBuffer) error {
	mb = buf.Compact(mb)
	mb, err := buf.WriteMultiBuffer(c, mb)
	buf.ReleaseMulti(mb)
	return err
}

func (c *RustConn) KTLSEnabled() KTLSState {
	return c.ktls
}

// KTLSKeyUpdateHandler returns the KeyUpdate handler for this connection,
// or nil if kTLS RX is not active or the connection uses TLS 1.2.
func (c *RustConn) KTLSKeyUpdateHandler() *KTLSKeyUpdateHandler {
	return c.ktls.keyUpdateHandler
}

// NewRustConn creates a RustConn from native handshake results.
// Used by the REALITY package to construct a RustConn from Rust handshake output.
func NewRustConn(rawConn net.Conn, result *native.TlsResult, serverName string) *RustConn {
	rc := &RustConn{
		rawConn:    rawConn,
		state:      result.StateHandle,
		alpn:       result.ALPN,
		version:    result.Version,
		cipher:     result.CipherSuite,
		serverName: serverName,
		ktls: KTLSState{
			Enabled: result.KtlsTx || result.KtlsRx,
			TxReady: result.KtlsTx,
			RxReady: result.KtlsRx,
		},
	}
	// Create KeyUpdate handler if base traffic secrets are available (TLS 1.3)
	if len(result.TxSecret) > 0 && result.Version == 0x0304 {
		if fd, err := ExtractFd(rawConn); err == nil {
			rc.ktls.keyUpdateHandler = newKTLSKeyUpdateHandler(
				fd, result.CipherSuite, result.RxSecret, result.TxSecret,
			)
		}
	}
	return rc
}

// configToNative translates an Xray TLS Config to a native Rust TLS config handle.
func configToNative(config *Config, dest net.Destination, isServer bool) *native.TlsConfigHandle {
	h := native.TlsConfigNew(isServer)
	if h == nil {
		return nil
	}

	// Server name (SNI)
	serverName := config.ServerName
	if serverName == "" && dest.Address.Family().IsDomain() {
		serverName = dest.Address.Domain()
	}
	if serverName != "" {
		native.TlsConfigSetServerName(h, serverName)
	}

	// Certificates
	for _, entry := range config.Certificate {
		if entry.Usage == Certificate_ENCIPHERMENT {
			native.TlsConfigAddCertPEM(h, entry.Certificate, entry.Key)
		} else if entry.Usage == Certificate_AUTHORITY_VERIFY {
			native.TlsConfigAddRootCAPEM(h, entry.Certificate)
		}
	}

	// Root CAs: use system roots unless custom CAs are provided
	hasCustomCA := false
	for _, entry := range config.Certificate {
		if entry.Usage == Certificate_AUTHORITY_VERIFY {
			hasCustomCA = true
			break
		}
	}
	if !hasCustomCA && !config.DisableSystemRoot {
		native.TlsConfigUseSystemRoots(h)
	}

	// ALPN
	if len(config.NextProtocol) > 0 {
		var alpnBuf []byte
		for _, proto := range config.NextProtocol {
			alpnBuf = append(alpnBuf, byte(len(proto)))
			alpnBuf = append(alpnBuf, proto...)
		}
		native.TlsConfigSetALPN(h, alpnBuf)
	}

	// TLS version constraints
	minVer := uint16(tls.VersionTLS12)
	maxVer := uint16(tls.VersionTLS13)
	versionMap := map[string]uint16{
		"1.0": tls.VersionTLS10,
		"1.1": tls.VersionTLS11,
		"1.2": tls.VersionTLS12,
		"1.3": tls.VersionTLS13,
	}
	if v, ok := versionMap[config.MinVersion]; ok {
		minVer = v
	}
	if v, ok := versionMap[config.MaxVersion]; ok {
		maxVer = v
	}
	if config.MinVersion != "" || config.MaxVersion != "" {
		native.TlsConfigSetVersions(h, minVer, maxVer)
	}

	// InsecureSkipVerify
	if config.AllowInsecure {
		native.TlsConfigSetInsecureSkipVerify(h, true)
	}

	// Pinned cert SHA256
	for _, pin := range config.PinnedPeerCertSha256 {
		native.TlsConfigPinCertSHA256(h, pin)
	}

	// Verify peer cert by name
	for _, name := range config.VerifyPeerCertByName {
		native.TlsConfigAddVerifyName(h, name)
	}

	// Key log file
	if config.MasterKeyLog != "" && config.MasterKeyLog != "none" {
		native.TlsConfigSetKeyLogPath(h, config.MasterKeyLog)
	}

	return h
}

// ExtractFd extracts the file descriptor from a net.Conn.
// Returns -1 if the connection doesn't support SyscallConn.
func ExtractFd(conn gonet.Conn) (int, error) {
	type syscallConner interface {
		SyscallConn() (syscall.RawConn, error)
	}
	sc, ok := conn.(syscallConner)
	if !ok {
		return -1, errors.New("connection does not support SyscallConn")
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return -1, err
	}
	var fd int
	if err := raw.Control(func(f uintptr) {
		fd = int(f)
	}); err != nil {
		return -1, err
	}
	return fd, nil
}

func ensureNativeFullKTLS(result *native.TlsResult) error {
	if result == nil {
		return errors.New("native TLS handshake returned nil result")
	}
	if result.KtlsTx && result.KtlsRx {
		return nil
	}
	if result.StateHandle != nil {
		native.TlsStateFree(result.StateHandle)
		result.StateHandle = nil
	}
	return errors.New("native TLS requires full kTLS offload (tx=", result.KtlsTx, ", rx=", result.KtlsRx, ")")
}

// RustClient performs a TLS client handshake using the Rust rustls library
// and enables kTLS for kernel-accelerated encryption.
func RustClient(c net.Conn, config *Config, dest net.Destination) (net.Conn, error) {
	h := configToNative(config, dest, false)
	if h == nil {
		return nil, errors.New("failed to create native TLS config")
	}
	defer native.TlsConfigFree(h)

	fd, err := ExtractFd(c)
	if err != nil {
		return nil, errors.New("failed to extract fd: ").Base(err)
	}

	result, err := native.TlsHandshake(fd, h, true)
	if err != nil {
		return nil, errors.New("native TLS client handshake failed: ").Base(err)
	}
	if err := ensureNativeFullKTLS(result); err != nil {
		return nil, errors.New("native TLS client handshake failed: ").Base(err)
	}

	serverName := config.ServerName
	if serverName == "" && dest.Address.Family().IsDomain() {
		serverName = dest.Address.Domain()
	}

	return NewRustConn(c, result, serverName), nil
}

// RustServer performs a TLS server handshake using the Rust rustls library
// and enables kTLS for kernel-accelerated encryption.
func RustServer(c net.Conn, config *Config) (net.Conn, error) {
	h := configToNative(config, net.Destination{}, true)
	if h == nil {
		return nil, errors.New("failed to create native TLS config")
	}
	defer native.TlsConfigFree(h)

	fd, err := ExtractFd(c)
	if err != nil {
		return nil, errors.New("failed to extract fd: ").Base(err)
	}

	result, err := native.TlsHandshake(fd, h, false)
	if err != nil {
		return nil, errors.New("native TLS server handshake failed: ").Base(err)
	}
	if err := ensureNativeFullKTLS(result); err != nil {
		return nil, errors.New("native TLS server handshake failed: ").Base(err)
	}

	return NewRustConn(c, result, ""), nil
}

func copyConfig(c *tls.Config) *utls.Config {
	return &utls.Config{
		Rand:                           c.Rand,
		RootCAs:                        c.RootCAs,
		ServerName:                     c.ServerName,
		InsecureSkipVerify:             c.InsecureSkipVerify,
		VerifyPeerCertificate:          c.VerifyPeerCertificate,
		KeyLogWriter:                   c.KeyLogWriter,
		EncryptedClientHelloConfigList: c.EncryptedClientHelloConfigList,
	}
}

func init() {
	bigInt, _ := rand.Int(rand.Reader, big.NewInt(int64(len(ModernFingerprints))))
	stopAt := int(bigInt.Int64())
	i := 0
	for _, v := range ModernFingerprints {
		if i == stopAt {
			PresetFingerprints["random"] = v
			break
		}
		i++
	}
	weights := utls.DefaultWeights
	weights.TLSVersMax_Set_VersionTLS13 = 1
	weights.FirstKeyShare_Set_CurveP256 = 0
	randomized := utls.HelloRandomizedALPN
	randomized.Seed, _ = utls.NewPRNGSeed()
	randomized.Weights = &weights
	randomizednoalpn := utls.HelloRandomizedNoALPN
	randomizednoalpn.Seed, _ = utls.NewPRNGSeed()
	randomizednoalpn.Weights = &weights
	PresetFingerprints["randomized"] = &randomized
	PresetFingerprints["randomizednoalpn"] = &randomizednoalpn
}

func GetFingerprint(name string) (fingerprint *utls.ClientHelloID) {
	if name == "" {
		return &utls.HelloChrome_Auto
	}
	if fingerprint = PresetFingerprints[name]; fingerprint != nil {
		return
	}
	if fingerprint = ModernFingerprints[name]; fingerprint != nil {
		return
	}
	if fingerprint = OtherFingerprints[name]; fingerprint != nil {
		return
	}
	return
}

var PresetFingerprints = map[string]*utls.ClientHelloID{
	// Recommended preset options in GUI clients
	"chrome":           &utls.HelloChrome_Auto,
	"firefox":          &utls.HelloFirefox_Auto,
	"safari":           &utls.HelloSafari_Auto,
	"ios":              &utls.HelloIOS_Auto,
	"android":          &utls.HelloAndroid_11_OkHttp,
	"edge":             &utls.HelloEdge_Auto,
	"360":              &utls.Hello360_Auto,
	"qq":               &utls.HelloQQ_Auto,
	"random":           nil,
	"randomized":       nil,
	"randomizednoalpn": nil,
	"unsafe":           nil,
}

var ModernFingerprints = map[string]*utls.ClientHelloID{
	// One of these will be chosen as `random` at startup
	"hellofirefox_99":         &utls.HelloFirefox_99,
	"hellofirefox_102":        &utls.HelloFirefox_102,
	"hellofirefox_105":        &utls.HelloFirefox_105,
	"hellofirefox_120":        &utls.HelloFirefox_120,
	"hellochrome_83":          &utls.HelloChrome_83,
	"hellochrome_87":          &utls.HelloChrome_87,
	"hellochrome_96":          &utls.HelloChrome_96,
	"hellochrome_100":         &utls.HelloChrome_100,
	"hellochrome_102":         &utls.HelloChrome_102,
	"hellochrome_106_shuffle": &utls.HelloChrome_106_Shuffle,
	"hellochrome_120":         &utls.HelloChrome_120,
	"hellochrome_131":         &utls.HelloChrome_131,
	"helloios_13":             &utls.HelloIOS_13,
	"helloios_14":             &utls.HelloIOS_14,
	"helloedge_85":            &utls.HelloEdge_85,
	"helloedge_106":           &utls.HelloEdge_106,
	"hellosafari_16_0":        &utls.HelloSafari_16_0,
	"hello360_11_0":           &utls.Hello360_11_0,
	"helloqq_11_1":            &utls.HelloQQ_11_1,
}

var OtherFingerprints = map[string]*utls.ClientHelloID{
	// Golang, randomized, auto, and fingerprints that are too old
	"hellogolang":            &utls.HelloGolang,
	"hellorandomized":        &utls.HelloRandomized,
	"hellorandomizedalpn":    &utls.HelloRandomizedALPN,
	"hellorandomizednoalpn":  &utls.HelloRandomizedNoALPN,
	"hellofirefox_auto":      &utls.HelloFirefox_Auto,
	"hellofirefox_55":        &utls.HelloFirefox_55,
	"hellofirefox_56":        &utls.HelloFirefox_56,
	"hellofirefox_63":        &utls.HelloFirefox_63,
	"hellofirefox_65":        &utls.HelloFirefox_65,
	"hellochrome_auto":       &utls.HelloChrome_Auto,
	"hellochrome_58":         &utls.HelloChrome_58,
	"hellochrome_62":         &utls.HelloChrome_62,
	"hellochrome_70":         &utls.HelloChrome_70,
	"hellochrome_72":         &utls.HelloChrome_72,
	"helloios_auto":          &utls.HelloIOS_Auto,
	"helloios_11_1":          &utls.HelloIOS_11_1,
	"helloios_12_1":          &utls.HelloIOS_12_1,
	"helloandroid_11_okhttp": &utls.HelloAndroid_11_OkHttp,
	"helloedge_auto":         &utls.HelloEdge_Auto,
	"hellosafari_auto":       &utls.HelloSafari_Auto,
	"hello360_auto":          &utls.Hello360_Auto,
	"hello360_7_5":           &utls.Hello360_7_5,
	"helloqq_auto":           &utls.HelloQQ_Auto,

	// Chrome betas'
	"hellochrome_100_psk":              &utls.HelloChrome_100_PSK,
	"hellochrome_112_psk_shuf":         &utls.HelloChrome_112_PSK_Shuf,
	"hellochrome_114_padding_psk_shuf": &utls.HelloChrome_114_Padding_PSK_Shuf,
	"hellochrome_115_pq":               &utls.HelloChrome_115_PQ,
	"hellochrome_115_pq_psk":           &utls.HelloChrome_115_PQ_PSK,
	"hellochrome_120_pq":               &utls.HelloChrome_120_PQ,
}
