package tls

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"math/big"
	gonet "net"
	"sync/atomic"
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
	ktls             KTLSState
	isClient         bool
	capture          *keyCapture
	writeRecords     atomic.Uint64
	rotationFailures atomic.Uint32
}

const (
	tlsCloseTimeout               = 250 * time.Millisecond
	defaultNativeHandshakeTimeout = 30 * time.Second
	maxRecordPayload              = 16384   // TLS max record payload size
	keyUpdateThreshold            = 1 << 24 // ~16.7M records, conservative limit below AES-GCM 2^24.5
	maxRotationFailures           = 3       // close connection after this many consecutive kTLS key rotation failures
	deferredKTLSPromotionCooldown = 10 * time.Minute
)

// deferredKTLSPromotionDisabledUntilUnixNano stores a cooldown deadline.
// During this window, deferred kTLS promotion is skipped to avoid repeated
// per-connection failures while preserving automatic recovery later.
var deferredKTLSPromotionDisabledUntilUnixNano atomic.Int64

func deferredKTLSPromotionDisabledAt(now time.Time) bool {
	return now.UnixNano() < deferredKTLSPromotionDisabledUntilUnixNano.Load()
}

// DeferredKTLSPromotionDisabled reports whether deferred kTLS promotion is
// currently in cooldown due to recent promotion failures.
func DeferredKTLSPromotionDisabled() bool {
	return deferredKTLSPromotionDisabledAt(time.Now())
}

func deferKTLSPromotionForCooldown() {
	until := time.Now().Add(deferredKTLSPromotionCooldown).UnixNano()
	for {
		current := deferredKTLSPromotionDisabledUntilUnixNano.Load()
		if current >= until {
			return
		}
		if deferredKTLSPromotionDisabledUntilUnixNano.CompareAndSwap(current, until) {
			return
		}
	}
}

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
		if err == nil {
			ktlsAfterWrite(n, c.ktls.keyUpdateHandler, &c.writeRecords, &c.rotationFailures, func() error {
				return c.Conn.NetConn().Close()
			})
		}
		return n, err
	}
	return c.Conn.Write(b)
}

// Close overrides tls.Conn.Close. When kTLS TX is active, closing via
// tls.Conn.Close() would double-encrypt the close_notify alert. Instead
// we close the raw socket directly.
func (c *Conn) Close() error {
	if c.ktls.keyUpdateHandler != nil {
		c.ktls.keyUpdateHandler.Close()
	}
	if c.ktls.TxReady {
		return c.Conn.NetConn().Close()
	}
	// Set a write deadline to bound the close_notify write.
	// If SetWriteDeadline fails (conn already closed by another goroutine),
	// skip the TLS close_notify and close the raw socket directly.
	if err := c.Conn.NetConn().SetWriteDeadline(time.Now().Add(tlsCloseTimeout)); err != nil {
		return c.Conn.NetConn().Close()
	}
	return c.Conn.Close()
}

// KTLSActive reports whether kernel TLS is active on this connection
// (either TX or RX direction). Used by VLESS to reject Vision flow on
// kTLS connections — see docs/ktls-vision-incompatibility.md.
func (c *Conn) KTLSActive() bool {
	return c.ktls.TxReady || c.ktls.RxReady
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
	_ = c.Conn.NetConn().SetWriteDeadline(time.Now().Add(tlsCloseTimeout))
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

// ktlsAfterWrite handles key rotation bookkeeping after a successful kTLS write.
// Both Conn and RustConn delegate to this to avoid duplicating the rotation logic.
func ktlsAfterWrite(n int, handler *KTLSKeyUpdateHandler, writeRecords *atomic.Uint64, rotationFailures *atomic.Uint32, closeConn func() error) {
	if handler == nil {
		return
	}
	records := uint64((n + maxRecordPayload - 1) / maxRecordPayload)
	total := writeRecords.Add(records)
	if total >= keyUpdateThreshold {
		if writeRecords.CompareAndSwap(total, 0) {
			if err := handler.InitiateUpdate(); err != nil {
				writeRecords.Add(total) // restore so next writer retries
				if rotationFailures.Add(1) >= maxRotationFailures {
					errors.LogError(context.Background(), "ktls: TX key rotation failed ", maxRotationFailures, " times, closing connection: ", err)
					if cerr := closeConn(); cerr != nil {
						errors.LogWarning(context.Background(), "ktls: failed to close connection after key exhaustion: ", cerr)
					}
				} else {
					errors.LogWarning(context.Background(), "ktls: TX key rotation failed: ", err)
				}
			} else {
				rotationFailures.Store(0)
			}
		}
	}
}

// RustConn wraps a raw TCP connection after Rust-side rustls handshake + kTLS setup.
// The kernel handles TLS encryption/decryption via kTLS, so Read/Write go directly
// to the underlying connection.
type RustConn struct {
	rawConn          net.Conn
	state            *native.TlsStateHandle
	ktls             KTLSState
	closed           atomic.Bool // atomic: Close() may race with concurrent Read()/Write()
	initErr          error
	alpn             string
	version          uint16
	cipher           uint16
	serverName       string
	writeRecords     atomic.Uint64
	rotationFailures atomic.Uint32
	drainedData      []byte
	drainedOff       int
	readRecords      atomic.Uint64 // kTLS RX record counter for EBADMSG diagnostics
	readBytes        atomic.Int64  // total kTLS RX bytes for EBADMSG diagnostics
}

var _ Interface = (*RustConn)(nil)

func (c *RustConn) Read(b []byte) (int, error) {
	if c.initErr != nil {
		return 0, c.initErr
	}
	if c.closed.Load() || c.rawConn == nil {
		return 0, gonet.ErrClosed
	}
	// Serve any drained plaintext from the handshake first
	if c.drainedOff < len(c.drainedData) {
		n := copy(b, c.drainedData[c.drainedOff:])
		c.drainedOff += n
		if c.drainedOff >= len(c.drainedData) {
			c.drainedData = nil // release buffer
		}
		return n, nil
	}
	if c.ktls.RxReady {
		// Full kTLS RX path — kernel decrypts.
		n, err := c.rawConn.Read(b)
		if n > 0 {
			c.readRecords.Add(1)
			c.readBytes.Add(int64(n))
		}
		if err != nil && isKeyExpired(err) && c.ktls.keyUpdateHandler != nil {
			if herr := c.ktls.keyUpdateHandler.Handle(); herr != nil {
				return 0, herr
			}
			n2, err2 := c.rawConn.Read(b)
			if n2 > 0 {
				c.readRecords.Add(1)
				c.readBytes.Add(int64(n2))
			}
			return n2, err2
		}
		if err != nil && isBadMessage(err) {
			c.logKTLSBadMessage()
		}
		if err != nil && isEIO(err) {
			c.logKTLSEIO()
		}
		return n, err
	}
	return c.rawConn.Read(b)
}

func (c *RustConn) Write(b []byte) (int, error) {
	if c.initErr != nil {
		return 0, c.initErr
	}
	if c.closed.Load() || c.rawConn == nil {
		return 0, gonet.ErrClosed
	}
	n, err := c.rawConn.Write(b)
	if err == nil {
		ktlsAfterWrite(n, c.ktls.keyUpdateHandler, &c.writeRecords, &c.rotationFailures, c.rawConn.Close)
	}
	return n, err
}

func (c *RustConn) Close() error {
	if !c.closed.CompareAndSwap(false, true) {
		return nil // already closed by another goroutine
	}
	// Close keyUpdateHandler before rawConn — a concurrent Read() may call
	// handler.Handle() (sendmsg on fd) between rawConn.Close() and handler.Close(),
	// operating on a closed or reused fd. This matches Conn.Close() ordering.
	if c.ktls.keyUpdateHandler != nil {
		c.ktls.keyUpdateHandler.Close()
		c.ktls.keyUpdateHandler = nil
	}
	var err error
	if c.rawConn != nil {
		err = c.rawConn.Close()
		c.rawConn = nil
	}
	if c.state != nil {
		native.TlsStateFree(c.state)
		c.state = nil
	}
	// Zero drainedData (may contain handshake plaintext).
	for i := range c.drainedData {
		c.drainedData[i] = 0
	}
	c.drainedData = nil
	return err
}

func (c *RustConn) NetConn() gonet.Conn { return c.rawConn }
func (c *RustConn) LocalAddr() gonet.Addr {
	if c.rawConn == nil {
		return nil
	}
	return c.rawConn.LocalAddr()
}
func (c *RustConn) RemoteAddr() gonet.Addr {
	if c.rawConn == nil {
		return nil
	}
	return c.rawConn.RemoteAddr()
}
func (c *RustConn) SetDeadline(t time.Time) error {
	if c.rawConn == nil {
		return errors.New("tls: RustConn is closed")
	}
	return c.rawConn.SetDeadline(t)
}
func (c *RustConn) SetReadDeadline(t time.Time) error {
	if c.rawConn == nil {
		return errors.New("tls: RustConn is closed")
	}
	return c.rawConn.SetReadDeadline(t)
}
func (c *RustConn) SetWriteDeadline(t time.Time) error {
	if c.rawConn == nil {
		return errors.New("tls: RustConn is closed")
	}
	return c.rawConn.SetWriteDeadline(t)
}
func (c *RustConn) HandshakeContext(ctx context.Context) error { return c.initErr }
func (c *RustConn) VerifyHostname(host string) error {
	if c.initErr != nil {
		return c.initErr
	}
	if c.serverName == "" {
		return errors.New("tls: RustConn: no server name was set during handshake")
	}
	if host != c.serverName {
		return errors.New("tls: RustConn: requested hostname ", host, " does not match verified server name ", c.serverName)
	}
	return nil
}

func (c *RustConn) HandshakeContextServerName(ctx context.Context) string {
	return c.serverName
}

func (c *RustConn) NegotiatedProtocol() string {
	return c.alpn
}

// ConnectionState returns a crypto/tls.ConnectionState with the negotiated
// TLS session parameters. This allows http2.Transport to populate request.TLS
// and verify ALPN. For server-side XHTTP, kTLSPlaintextConn hides this method
// so http.Server takes the h2c path instead.
func (c *RustConn) ConnectionState() tls.ConnectionState {
	return tls.ConnectionState{
		Version:            c.version,
		NegotiatedProtocol: c.alpn,
		CipherSuite:        c.cipher,
		ServerName:         c.serverName,
	}
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

// logKTLSBadMessage logs diagnostic information when kTLS RX returns EBADMSG
// (AEAD authentication tag verification failure). This captures the connection
// state at the point of failure to help determine whether the cause is a kernel
// bug, reverse proxy corruption, or sequence number desynchronization.
func (c *RustConn) logKTLSBadMessage() {
	readRecs := c.readRecords.Load()
	readB := c.readBytes.Load()
	writeRecs := c.writeRecords.Load()
	local := "<nil>"
	remote := "<nil>"
	if c.rawConn != nil {
		if a := c.rawConn.LocalAddr(); a != nil {
			local = a.String()
		}
		if a := c.rawConn.RemoteAddr(); a != nil {
			remote = a.String()
		}
	}

	// Try to read kernel-side RX sequence number for desync detection
	var seqInfo string
	if c.rawConn != nil {
		if fd, err := ExtractFd(c.rawConn); err == nil {
			if seq, serr := ktlsRxDiagnostics(fd, c.cipher); serr == nil {
				seqInfo = fmt.Sprintf(" kernelRxSeq=%d", seq)
			} else {
				seqInfo = " kernelRxSeq=err:" + serr.Error()
			}
		} else {
			seqInfo = " fd=err:" + err.Error()
		}
	}

	errors.LogWarning(context.Background(),
		fmt.Sprintf("kTLS EBADMSG on RustConn: cipher=0x%04x version=0x%04x readRecords=%d readBytes=%d writeRecords=%d%s local=%s remote=%s",
			c.cipher, c.version, readRecs, readB, writeRecs, seqInfo, local, remote),
	)
}

func (c *RustConn) logKTLSEIO() {
	readRecs := c.readRecords.Load()
	readB := c.readBytes.Load()
	writeRecs := c.writeRecords.Load()
	local := "<nil>"
	remote := "<nil>"
	if c.rawConn != nil {
		if a := c.rawConn.LocalAddr(); a != nil {
			local = a.String()
		}
		if a := c.rawConn.RemoteAddr(); a != nil {
			remote = a.String()
		}
	}

	var seqInfo string
	if c.rawConn != nil {
		if fd, err := ExtractFd(c.rawConn); err == nil {
			if seq, serr := ktlsRxDiagnostics(fd, c.cipher); serr == nil {
				seqInfo = fmt.Sprintf(" kernelRxSeq=%d", seq)
			} else {
				seqInfo = " kernelRxSeq=err:" + serr.Error()
			}
		}
	}

	errors.LogWarning(context.Background(),
		fmt.Sprintf("kTLS EIO on RustConn: cipher=0x%04x version=0x%04x readRecords=%d readBytes=%d writeRecords=%d%s local=%s remote=%s",
			c.cipher, c.version, readRecs, readB, writeRecs, seqInfo, local, remote),
	)
}

// NewRustConn creates a RustConn from native handshake results.
// Used by the REALITY package to construct a RustConn from Rust handshake output.
func NewRustConn(rawConn net.Conn, result *native.TlsResult, serverName string) *RustConn {
	rc, err := NewRustConnChecked(rawConn, result, serverName)
	if err != nil {
		return &RustConn{
			rawConn: rawConn,
			initErr: err,
		}
	}
	return rc
}

func cleanupFailedRustConn(rc *RustConn) {
	if rc == nil {
		return
	}
	if rc.ktls.keyUpdateHandler != nil {
		rc.ktls.keyUpdateHandler.Close()
		rc.ktls.keyUpdateHandler = nil
	}
	if rc.state != nil {
		native.TlsStateFree(rc.state)
		rc.state = nil
	}
	for i := range rc.drainedData {
		rc.drainedData[i] = 0
	}
	rc.drainedData = nil
}

// NewRustConnChecked creates a RustConn and returns an error when native
// handshake/kTLS invariants are not met.
func NewRustConnChecked(rawConn net.Conn, result *native.TlsResult, serverName string) (*RustConn, error) {
	if result == nil {
		if rawConn != nil {
			_ = rawConn.Close()
		}
		return nil, errors.New("tls: native RustConn init: nil handshake result")
	}
	defer result.ZeroSecrets()

	if rawConn == nil {
		if result.StateHandle != nil {
			native.TlsStateFree(result.StateHandle)
			result.StateHandle = nil
		}
		return nil, errors.New("tls: native RustConn init: nil raw connection")
	}

	stateHandle := result.StateHandle
	result.StateHandle = nil

	rc := &RustConn{
		rawConn:     rawConn,
		state:       stateHandle,
		alpn:        result.ALPN,
		version:     result.Version,
		cipher:      result.CipherSuite,
		serverName:  serverName,
		drainedData: result.DrainedData,
		ktls: KTLSState{
			Enabled: result.KtlsTx && result.KtlsRx,
			TxReady: result.KtlsTx,
			RxReady: result.KtlsRx,
		},
	}

	fail := func(err error) (*RustConn, error) {
		cleanupFailedRustConn(rc)
		_ = rawConn.Close()
		return nil, err
	}

	if !result.KtlsTx || !result.KtlsRx {
		return fail(errors.New("tls: native RustConn init: full kTLS offload required (tx=", result.KtlsTx, " rx=", result.KtlsRx, ")"))
	}

	// Create KeyUpdate handler if base traffic secrets are available (TLS 1.3)
	if len(result.TxSecret) > 0 && result.Version == 0x0304 {
		if fd, err := ExtractFd(rawConn); err == nil {
			rc.ktls.keyUpdateHandler = newKTLSKeyUpdateHandler(fd, result.CipherSuite, result.RxSecret, result.TxSecret)
		}
	}

	return rc, nil
}

// ---------------------------------------------------------------------------
// DeferredRustConn — deferred kTLS promotion for REALITY
// ---------------------------------------------------------------------------

// DeferredRustConn wraps a deferred REALITY session. During the deferred phase,
// reads/writes go through rustls (Rust FFI). After EnableKTLS(), the connection
// transparently switches to kernel-level kTLS I/O on the raw socket.
type DeferredRustConn struct {
	rawConn          gonet.Conn
	handle           *native.DeferredSessionHandle
	alpn             string
	version          uint16
	cipher           uint16
	sni              string
	closed           atomic.Bool           // atomic: Close() may race with concurrent Read()/Write()
	ktlsActive       bool                  // true after EnableKTLS()
	ktlsState        KTLSState             // populated after EnableKTLS()
	ktlsHandler      *KTLSKeyUpdateHandler // populated after EnableKTLS()
	state            *native.TlsStateHandle
	drainedData      []byte // from enable_ktls drain
	drainedOff       int
	writeRecords     atomic.Uint64
	rotationFailures atomic.Uint32
}

// NewDeferredRustConn creates a DeferredRustConn from native deferred handshake results.
func NewDeferredRustConn(rawConn gonet.Conn, result *native.DeferredResult) (*DeferredRustConn, error) {
	if result == nil || result.Handle == nil {
		if rawConn != nil {
			_ = rawConn.Close()
		}
		return nil, errors.New("tls: DeferredRustConn init: nil handshake result")
	}
	if rawConn == nil {
		native.DeferredFree(result.Handle)
		return nil, errors.New("tls: DeferredRustConn init: nil raw connection")
	}
	return &DeferredRustConn{
		rawConn: rawConn,
		handle:  result.Handle,
		alpn:    result.ALPN,
		version: result.Version,
		cipher:  result.CipherSuite,
		sni:     result.SNI,
	}, nil
}

func (c *DeferredRustConn) Read(b []byte) (int, error) {
	if c.closed.Load() {
		return 0, gonet.ErrClosed
	}
	// 1. Serve drainedData first (from EnableKTLS)
	if c.drainedOff < len(c.drainedData) {
		n := copy(b, c.drainedData[c.drainedOff:])
		c.drainedOff += n
		if c.drainedOff >= len(c.drainedData) {
			// Zero and release drained data
			for i := range c.drainedData {
				c.drainedData[i] = 0
			}
			c.drainedData = nil
			c.drainedOff = 0
		}
		return n, nil
	}
	// 2. If kTLS active: read from rawConn (kernel decrypts)
	if c.ktlsActive {
		n, err := c.rawConn.Read(b)
		if err != nil && isKeyExpired(err) && c.ktlsHandler != nil {
			if herr := c.ktlsHandler.Handle(); herr != nil {
				return 0, herr
			}
			return c.rawConn.Read(b)
		}
		return n, err
	}
	// 3. Else: read through rustls via FFI.
	// Nil-guard: EnableKTLS() consumes handle; if a rare race occurs
	// where EnableKTLS() transitions state mid-Read, fail safely.
	h := c.handle
	if h == nil {
		return 0, gonet.ErrClosed
	}
	return native.DeferredRead(h, b)
}

func (c *DeferredRustConn) Write(b []byte) (int, error) {
	if c.closed.Load() {
		return 0, gonet.ErrClosed
	}
	// 1. If kTLS active: write to rawConn (kernel encrypts)
	if c.ktlsActive {
		n, err := c.rawConn.Write(b)
		if err == nil {
			ktlsAfterWrite(n, c.ktlsHandler, &c.writeRecords, &c.rotationFailures, c.rawConn.Close)
		}
		return n, err
	}
	// 2. Else: write through rustls via FFI.
	h := c.handle
	if h == nil {
		return 0, gonet.ErrClosed
	}
	return native.DeferredWrite(h, b)
}

// EnableKTLS installs kTLS on the socket in-place. After this call, Read/Write
// transparently use kernel TLS instead of rustls. Existing references to this
// DeferredRustConn continue to work — no variable replacement needed.
func (c *DeferredRustConn) EnableKTLS() error {
	if c.handle == nil {
		return errors.New("tls: DeferredRustConn: already consumed or freed")
	}
	if DeferredKTLSPromotionDisabled() {
		return nil
	}
	result, err := native.DeferredEnableKTLS(c.handle)
	// The native deferred handle is consumed by FFI regardless of promotion
	// success, so this DeferredRustConn cannot continue rustls I/O after error.
	c.handle = nil
	if err != nil {
		deferKTLSPromotionForCooldown()
		return err
	}

	// Extract secrets and create KeyUpdateHandler first, then zero secrets
	// immediately to minimize the window where key material lives on the Go heap.
	if len(result.TxSecret) > 0 && result.Version == 0x0304 {
		if fd, err := ExtractFd(c.rawConn); err == nil {
			c.ktlsHandler = newKTLSKeyUpdateHandler(fd, result.CipherSuite, result.RxSecret, result.TxSecret)
		}
	}
	result.ZeroSecrets()

	c.ktlsActive = true
	c.ktlsState = KTLSState{Enabled: true, TxReady: result.KtlsTx, RxReady: result.KtlsRx}
	c.cipher = result.CipherSuite
	c.drainedData = result.DrainedData
	c.drainedOff = 0

	// Store state handle for cleanup
	c.state = result.StateHandle
	result.StateHandle = nil

	return nil
}

func (c *DeferredRustConn) Close() error {
	if !c.closed.CompareAndSwap(false, true) {
		return nil // already closed by another goroutine
	}
	if c.handle != nil {
		native.DeferredFree(c.handle)
		c.handle = nil
	}
	if c.ktlsHandler != nil {
		c.ktlsHandler.Close()
		c.ktlsHandler = nil
	}
	if c.state != nil {
		native.TlsStateFree(c.state)
		c.state = nil
	}
	// Zero and release drained data
	for i := range c.drainedData {
		c.drainedData[i] = 0
	}
	c.drainedData = nil
	return c.rawConn.Close()
}

// NetConn returns the underlying raw connection.
// Used by UnwrapRawConn to access the raw TCP socket.
func (c *DeferredRustConn) NetConn() gonet.Conn {
	return c.rawConn
}

// KTLSEnabled returns the kTLS state (empty before EnableKTLS, populated after).
func (c *DeferredRustConn) KTLSEnabled() KTLSState {
	return c.ktlsState
}

// KTLSKeyUpdateHandler returns the key update handler (nil before EnableKTLS).
func (c *DeferredRustConn) KTLSKeyUpdateHandler() *KTLSKeyUpdateHandler {
	return c.ktlsHandler
}

// ConnectionState returns a tls.ConnectionState with REALITY session metadata.
func (c *DeferredRustConn) ConnectionState() tls.ConnectionState {
	return tls.ConnectionState{
		Version:            c.version,
		NegotiatedProtocol: c.alpn,
		ServerName:         c.sni,
		CipherSuite:        c.cipher,
	}
}

// HandshakeContext is a no-op — handshake already completed in Rust.
func (c *DeferredRustConn) HandshakeContext(ctx context.Context) error {
	return nil
}

// VerifyHostname is a no-op — REALITY has its own auth mechanism.
func (c *DeferredRustConn) VerifyHostname(host string) error {
	return nil
}

// HandshakeContextServerName returns the SNI from the REALITY handshake.
func (c *DeferredRustConn) HandshakeContextServerName(ctx context.Context) string {
	return c.sni
}

// NegotiatedProtocol returns the ALPN protocol from the REALITY handshake.
func (c *DeferredRustConn) NegotiatedProtocol() string {
	return c.alpn
}

// LocalAddr delegates to the underlying connection.
func (c *DeferredRustConn) LocalAddr() gonet.Addr {
	return c.rawConn.LocalAddr()
}

// RemoteAddr delegates to the underlying connection.
func (c *DeferredRustConn) RemoteAddr() gonet.Addr {
	return c.rawConn.RemoteAddr()
}

// SetDeadline delegates to the underlying connection.
func (c *DeferredRustConn) SetDeadline(t time.Time) error {
	return c.rawConn.SetDeadline(t)
}

// SetReadDeadline delegates to the underlying connection.
func (c *DeferredRustConn) SetReadDeadline(t time.Time) error {
	return c.rawConn.SetReadDeadline(t)
}

// SetWriteDeadline delegates to the underlying connection.
func (c *DeferredRustConn) SetWriteDeadline(t time.Time) error {
	return c.rawConn.SetWriteDeadline(t)
}

// Verify DeferredRustConn implements the required interfaces.
var _ gonet.Conn = (*DeferredRustConn)(nil)
var _ Interface = (*DeferredRustConn)(nil)

// ---------------------------------------------------------------------------
// KTLSPlaintextConn — hides ConnectionState() from http.Server
// ---------------------------------------------------------------------------

// KTLSPlaintextConn wraps a kTLS-enabled connection, hiding ConnectionState()
// so http.Server treats it as plaintext and uses h2c detection. On the wire,
// kTLS still handles encryption transparently in the kernel.
type KTLSPlaintextConn struct {
	inner gonet.Conn
}

// NewKTLSPlaintextConn wraps a kTLS-enabled connection for server-side h2c use.
func NewKTLSPlaintextConn(conn gonet.Conn) *KTLSPlaintextConn {
	return &KTLSPlaintextConn{inner: conn}
}

func (c *KTLSPlaintextConn) Read(b []byte) (int, error)  { return c.inner.Read(b) }
func (c *KTLSPlaintextConn) Write(b []byte) (int, error) { return c.inner.Write(b) }
func (c *KTLSPlaintextConn) Close() error                { return c.inner.Close() }
func (c *KTLSPlaintextConn) LocalAddr() gonet.Addr       { return c.inner.LocalAddr() }
func (c *KTLSPlaintextConn) RemoteAddr() gonet.Addr      { return c.inner.RemoteAddr() }
func (c *KTLSPlaintextConn) SetDeadline(t time.Time) error {
	return c.inner.SetDeadline(t)
}
func (c *KTLSPlaintextConn) SetReadDeadline(t time.Time) error {
	return c.inner.SetReadDeadline(t)
}
func (c *KTLSPlaintextConn) SetWriteDeadline(t time.Time) error {
	return c.inner.SetWriteDeadline(t)
}

// Verify KTLSPlaintextConn implements net.Conn but NOT connectionStater.
var _ gonet.Conn = (*KTLSPlaintextConn)(nil)

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
			if err := native.TlsConfigAddCertPEM(h, entry.Certificate, entry.Key); err != nil {
				errors.LogWarning(context.Background(), "native TLS: failed to add cert: ", err)
			}
		} else if entry.Usage == Certificate_AUTHORITY_VERIFY {
			if err := native.TlsConfigAddRootCAPEM(h, entry.Certificate); err != nil {
				errors.LogWarning(context.Background(), "native TLS: failed to add root CA: ", err)
			}
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
//
// IMPORTANT: The connection must not have an intermediary buffered reader
// (e.g. proxyproto.Conn) between the caller and the kernel socket. Such
// wrappers consume bytes from the socket into a userspace buffer that is
// invisible to raw fd readers. Callers must gate on connection type before
// calling this function.
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

func validateNativeKTLS(result *native.TlsResult) error {
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

func normalizeNativeHandshakeTimeout(timeout time.Duration) time.Duration {
	if timeout <= 0 {
		return defaultNativeHandshakeTimeout
	}
	return timeout
}

// RustClient performs a TLS client handshake using the Rust rustls library
// and enables kTLS for kernel-accelerated encryption.
func RustClient(c net.Conn, config *Config, dest net.Destination) (net.Conn, error) {
	return RustClientWithTimeout(c, config, dest, 0)
}

// RustClientWithTimeout performs Rust TLS handshake with an explicit timeout.
func RustClientWithTimeout(c net.Conn, config *Config, dest net.Destination, handshakeTimeout time.Duration) (net.Conn, error) {
	h := configToNative(config, dest, false)
	if h == nil {
		return nil, errors.New("failed to create native TLS config")
	}
	defer native.TlsConfigFree(h)

	fd, err := ExtractFd(c)
	if err != nil {
		return nil, errors.New("failed to extract fd: ").Base(err)
	}

	result, err := native.TlsHandshakeWithTimeout(fd, h, true, normalizeNativeHandshakeTimeout(handshakeTimeout))
	if err != nil {
		return nil, errors.New("native TLS client handshake failed: ").Base(err)
	}
	if err := validateNativeKTLS(result); err != nil {
		return nil, errors.New("native TLS client handshake failed: ").Base(err)
	}

	serverName := config.ServerName
	if serverName == "" && dest.Address.Family().IsDomain() {
		serverName = dest.Address.Domain()
	}

	rc, err := NewRustConnChecked(c, result, serverName)
	if err != nil {
		return nil, errors.New("native TLS client handshake failed: ").Base(err)
	}
	return rc, nil
}

// RustServer performs a TLS server handshake using the Rust rustls library
// and enables kTLS for kernel-accelerated encryption.
func RustServer(c net.Conn, config *Config) (net.Conn, error) {
	return RustServerWithTimeout(c, config, 0)
}

// RustServerWithTimeout performs Rust TLS server handshake with an explicit timeout.
func RustServerWithTimeout(c net.Conn, config *Config, handshakeTimeout time.Duration) (net.Conn, error) {
	h := configToNative(config, net.Destination{}, true)
	if h == nil {
		return nil, errors.New("failed to create native TLS config")
	}
	defer native.TlsConfigFree(h)

	fd, err := ExtractFd(c)
	if err != nil {
		return nil, errors.New("failed to extract fd: ").Base(err)
	}

	result, err := native.TlsHandshakeWithTimeout(fd, h, false, normalizeNativeHandshakeTimeout(handshakeTimeout))
	if err != nil {
		return nil, errors.New("native TLS server handshake failed: ").Base(err)
	}
	if err := validateNativeKTLS(result); err != nil {
		return nil, errors.New("native TLS server handshake failed: ").Base(err)
	}

	rc, err := NewRustConnChecked(c, result, "")
	if err != nil {
		return nil, errors.New("native TLS server handshake failed: ").Base(err)
	}
	return rc, nil
}

// RustServerDeferred performs a TLS server handshake via Rust rustls but does
// NOT install kTLS. Returns a DeferredRustConn that reads/writes through rustls.
// The protocol handler later calls EnableKTLS() (non-Vision) or keeps rustls (Vision).
func RustServerDeferred(c net.Conn, config *Config, handshakeTimeout time.Duration) (*DeferredRustConn, error) {
	h := configToNative(config, net.Destination{}, true)
	if h == nil {
		return nil, errors.New("failed to create native TLS config")
	}
	defer native.TlsConfigFree(h)

	fd, err := ExtractFd(c)
	if err != nil {
		return nil, errors.New("failed to extract fd").Base(err)
	}

	result, err := native.TlsServerDeferred(fd, h, normalizeNativeHandshakeTimeout(handshakeTimeout))
	if err != nil {
		return nil, errors.New("native TLS server deferred handshake failed").Base(err)
	}

	return NewDeferredRustConn(c, result)
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
