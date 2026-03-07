package tls

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"math/big"
	gonet "net"
	"sync"
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
	deferredKTLSPromotionCooldown = 3 * time.Minute
	deferredReadBatchCap          = 16 * 1024 // 16 KiB read-ahead for deferred rustls reads
	deferredReadBatchThreshold    = 2 * 1024  // batch only for small app reads to amortize cgo crossings
	deferredWriteBatchCap         = 16 * 1024 // 16 KiB write coalescing budget for deferred rustls writes
	deferredWriteBatchThreshold   = 2 * 1024  // coalesce only small app writes; large payloads flush immediately
)

// deferredKTLSPromotionDisabledUntilUnixNano stores a cooldown deadline.
// During this window, deferred kTLS promotion is skipped to avoid repeated
// per-connection failures while preserving automatic recovery later.
// Scoped by a string key to avoid penalizing all listeners on a single blip.
// Key examples: "global" (default), "xhttp:<addr>", "vision".
var deferredKTLSPromotionDisabledUntilUnixNano atomic.Int64

const ktlsScopeDefault = "global"

var deferredKTLSPromotionScopes sync.Map       // key string -> int64 unixNano until
var deferredKTLSPromotionScopeMetrics sync.Map // key string -> int64 unixNano until (last set)

func deferredKTLSPromotionDisabledAt(now time.Time) bool {
	return deferredKTLSPromotionDisabledForScope(now, ktlsScopeDefault)
}

func deferredKTLSPromotionDisabledForScope(now time.Time, scope string) bool {
	if scope == "" {
		scope = ktlsScopeDefault
	}
	if val, ok := deferredKTLSPromotionScopes.Load(scope); ok {
		if until, ok2 := val.(int64); ok2 && now.UnixNano() < until {
			return true
		}
	}
	// Always honor the legacy global gate for backward compatibility.
	if now.UnixNano() < deferredKTLSPromotionDisabledUntilUnixNano.Load() {
		return true
	}
	return false
}

// DeferredKTLSPromotionDisabled reports whether deferred kTLS promotion is
// currently in cooldown due to recent promotion failures (default scope).
func DeferredKTLSPromotionDisabled() bool {
	return deferredKTLSPromotionDisabledAt(time.Now())
}

// DeferredKTLSPromotionDisabledFor reports cooldown state for a specific scope.
func DeferredKTLSPromotionDisabledFor(scope string) bool {
	return deferredKTLSPromotionDisabledForScope(time.Now(), scope)
}

func deferKTLSPromotionForCooldownScope(scope string) {
	if scope == "" {
		scope = ktlsScopeDefault
	}
	until := time.Now().Add(deferredKTLSPromotionCooldown).UnixNano()
	deferredKTLSPromotionScopes.Store(scope, until)
	deferredKTLSPromotionScopeMetrics.Store(scope, until)
	// Maintain legacy global cooldown for callers that still consult the global atomic.
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

// deferKTLSPromotionForCooldown keeps backward compatibility for tests/callers
// that still use the global cooldown helper.
func deferKTLSPromotionForCooldown() {
	deferKTLSPromotionForCooldownScope(ktlsScopeDefault)
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
	if handler == nil || handler.IsClosed() {
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
	mu               sync.RWMutex
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

	c.mu.Lock()
	if c.closed.Load() || c.rawConn == nil {
		c.mu.Unlock()
		return 0, gonet.ErrClosed
	}
	// Serve any drained plaintext from the handshake first.
	if c.drainedOff < len(c.drainedData) {
		n := copy(b, c.drainedData[c.drainedOff:])
		c.drainedOff += n
		if c.drainedOff >= len(c.drainedData) {
			c.drainedData = nil
			c.drainedOff = 0
		}
		c.mu.Unlock()
		return n, nil
	}
	rawConn := c.rawConn
	ktlsRxReady := c.ktls.RxReady
	handler := c.ktls.keyUpdateHandler
	c.mu.Unlock()

	if ktlsRxReady {
		// Full kTLS RX path — kernel decrypts.
		n, err := rawConn.Read(b)
		if n > 0 {
			c.readRecords.Add(1)
			c.readBytes.Add(int64(n))
		}
		if err != nil && isKeyExpired(err) && handler != nil {
			if herr := handler.Handle(); herr != nil {
				return 0, herr
			}
			n2, err2 := rawConn.Read(b)
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

	return rawConn.Read(b)
}

func (c *RustConn) Write(b []byte) (int, error) {
	if c.initErr != nil {
		return 0, c.initErr
	}

	c.mu.RLock()
	if c.closed.Load() || c.rawConn == nil {
		c.mu.RUnlock()
		return 0, gonet.ErrClosed
	}
	rawConn := c.rawConn
	handler := c.ktls.keyUpdateHandler
	c.mu.RUnlock()

	n, err := rawConn.Write(b)
	if err == nil {
		ktlsAfterWrite(n, handler, &c.writeRecords, &c.rotationFailures, rawConn.Close)
	}
	return n, err
}

func (c *RustConn) Close() error {
	if !c.closed.CompareAndSwap(false, true) {
		return nil // already closed by another goroutine
	}

	c.mu.Lock()
	// Close keyUpdateHandler before rawConn — a concurrent Read() may call
	// handler.Handle() (sendmsg on fd) between rawConn.Close() and handler.Close(),
	// operating on a closed or reused fd. This matches Conn.Close() ordering.
	handler := c.ktls.keyUpdateHandler
	c.ktls.keyUpdateHandler = nil
	rawConn := c.rawConn
	c.rawConn = nil
	state := c.state
	c.state = nil
	drained := c.drainedData
	c.drainedData = nil
	c.drainedOff = 0
	c.mu.Unlock()

	if handler != nil {
		handler.Close()
	}
	if state != nil {
		native.TlsStateFree(state)
	}
	// Zero drainedData (may contain handshake plaintext).
	for i := range drained {
		drained[i] = 0
	}
	if rawConn != nil {
		return rawConn.Close()
	}
	return nil
}

func (c *RustConn) NetConn() gonet.Conn {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.rawConn
}
func (c *RustConn) LocalAddr() gonet.Addr {
	c.mu.RLock()
	rawConn := c.rawConn
	c.mu.RUnlock()
	if rawConn == nil {
		return nil
	}
	return rawConn.LocalAddr()
}
func (c *RustConn) RemoteAddr() gonet.Addr {
	c.mu.RLock()
	rawConn := c.rawConn
	c.mu.RUnlock()
	if rawConn == nil {
		return nil
	}
	return rawConn.RemoteAddr()
}
func (c *RustConn) SetDeadline(t time.Time) error {
	c.mu.RLock()
	rawConn := c.rawConn
	c.mu.RUnlock()
	if rawConn == nil {
		return errors.New("tls: RustConn is closed")
	}
	return rawConn.SetDeadline(t)
}
func (c *RustConn) SetReadDeadline(t time.Time) error {
	c.mu.RLock()
	rawConn := c.rawConn
	c.mu.RUnlock()
	if rawConn == nil {
		return errors.New("tls: RustConn is closed")
	}
	return rawConn.SetReadDeadline(t)
}
func (c *RustConn) SetWriteDeadline(t time.Time) error {
	c.mu.RLock()
	rawConn := c.rawConn
	c.mu.RUnlock()
	if rawConn == nil {
		return errors.New("tls: RustConn is closed")
	}
	return rawConn.SetWriteDeadline(t)
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
		HandshakeComplete:  true,
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
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.ktls
}

// KTLSKeyUpdateHandler returns the KeyUpdate handler for this connection,
// or nil if kTLS RX is not active or the connection uses TLS 1.2.
func (c *RustConn) KTLSKeyUpdateHandler() *KTLSKeyUpdateHandler {
	c.mu.RLock()
	defer c.mu.RUnlock()
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
	c.mu.RLock()
	rawConn := c.rawConn
	cipher := c.cipher
	version := c.version
	c.mu.RUnlock()
	local := "<nil>"
	remote := "<nil>"
	if rawConn != nil {
		if a := rawConn.LocalAddr(); a != nil {
			local = a.String()
		}
		if a := rawConn.RemoteAddr(); a != nil {
			remote = a.String()
		}
	}

	// Try to read kernel-side RX sequence number for desync detection
	var seqInfo string
	if rawConn != nil {
		if fd, err := ExtractFd(rawConn); err == nil {
			if seq, serr := ktlsRxDiagnostics(fd, cipher); serr == nil {
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
			cipher, version, readRecs, readB, writeRecs, seqInfo, local, remote),
	)
}

func (c *RustConn) logKTLSEIO() {
	readRecs := c.readRecords.Load()
	readB := c.readBytes.Load()
	writeRecs := c.writeRecords.Load()
	c.mu.RLock()
	rawConn := c.rawConn
	cipher := c.cipher
	version := c.version
	c.mu.RUnlock()
	local := "<nil>"
	remote := "<nil>"
	if rawConn != nil {
		if a := rawConn.LocalAddr(); a != nil {
			local = a.String()
		}
		if a := rawConn.RemoteAddr(); a != nil {
			remote = a.String()
		}
	}

	var seqInfo string
	if rawConn != nil {
		if fd, err := ExtractFd(rawConn); err == nil {
			if seq, serr := ktlsRxDiagnostics(fd, cipher); serr == nil {
				seqInfo = fmt.Sprintf(" kernelRxSeq=%d", seq)
			} else {
				seqInfo = " kernelRxSeq=err:" + serr.Error()
			}
		}
	}

	errors.LogWarning(context.Background(),
		fmt.Sprintf("kTLS EIO on RustConn: cipher=0x%04x version=0x%04x readRecords=%d readBytes=%d writeRecords=%d%s local=%s remote=%s",
			cipher, version, readRecs, readB, writeRecs, seqInfo, local, remote),
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
	deferredMu       sync.RWMutex
	deferredCond     *sync.Cond
	deferredOps      int
	deferredOpsBlock bool
	handle           *native.DeferredSessionHandle
	alpn             string
	version          uint16
	cipher           uint16
	sni              string
	ktlsScope        string
	closed           atomic.Bool           // atomic: Close() may race with concurrent Read()/Write()
	ktlsActive       bool                  // true after EnableKTLS()
	ktlsState        KTLSState             // populated after EnableKTLS()
	ktlsHandler      *KTLSKeyUpdateHandler // populated after EnableKTLS()
	state            *native.TlsStateHandle
	drainedData      []byte // from enable_ktls drain or detach read-ahead
	drainedOff       int
	writeRecords     atomic.Uint64
	rotationFailures atomic.Uint32
	detached         atomic.Bool // true after DrainAndDetach()
	deferredReadMu   sync.Mutex
	deferredReadBuf  []byte
	deferredReadOff  int
	deferredReadLen  int
	writeBatching    atomic.Bool
	deferredWriteMu  sync.Mutex
	deferredWriteBuf []byte
	deferredWriteLen int
	deadlineMu       sync.RWMutex
	readDeadline     time.Time
	writeDeadline    time.Time
	readRecords      atomic.Uint64 // kTLS RX record counter for EBADMSG diagnostics
	readBytes        atomic.Int64  // total kTLS RX bytes for EBADMSG diagnostics
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
		rawConn:   rawConn,
		handle:    result.Handle,
		alpn:      result.ALPN,
		version:   result.Version,
		cipher:    result.CipherSuite,
		sni:       result.SNI,
		ktlsScope: ktlsScopeDefault,
	}, nil
}

// SetKTLSPromotionScope allows callers to scope cooldowns to a listener / cipher / kernel path.
// Empty scope falls back to a shared default.
func (c *DeferredRustConn) SetKTLSPromotionScope(scope string) {
	if scope == "" {
		c.ktlsScope = ktlsScopeDefault
		return
	}
	c.ktlsScope = scope
}

// SetDeferredWriteBatching enables or disables deferred small-write coalescing.
// The default is disabled so protocol-control writes preserve progress unless a
// caller explicitly opts into batching for a proven-safe data path.
func (c *DeferredRustConn) SetDeferredWriteBatching(enabled bool) {
	if c == nil {
		return
	}
	c.writeBatching.Store(enabled)
}

func (c *DeferredRustConn) ensureDeferredCondLocked() *sync.Cond {
	if c.deferredCond == nil {
		c.deferredCond = sync.NewCond(&c.deferredMu)
	}
	return c.deferredCond
}

// beginDeferredHandleUse pins the deferred handle for a blocking native read or
// write without holding deferredMu across the FFI call. State transitions block
// new entrants and wait for active users to drain before consuming the handle.
func (c *DeferredRustConn) beginDeferredHandleUse() (*native.DeferredSessionHandle, bool, error) {
	c.deferredMu.Lock()
	defer c.deferredMu.Unlock()

	for {
		if c.closed.Load() {
			return nil, false, gonet.ErrClosed
		}
		if c.ktlsActive || c.detached.Load() {
			return nil, false, nil
		}
		if c.handle == nil {
			return nil, false, gonet.ErrClosed
		}
		if !c.deferredOpsBlock {
			c.deferredOps++
			return c.handle, true, nil
		}
		c.ensureDeferredCondLocked().Wait()
	}
}

func (c *DeferredRustConn) endDeferredHandleUse() {
	c.deferredMu.Lock()
	if c.deferredOps > 0 {
		c.deferredOps--
		if c.deferredOps == 0 {
			c.ensureDeferredCondLocked().Broadcast()
		}
	}
	c.deferredMu.Unlock()
}

func (c *DeferredRustConn) beginExclusiveDeferredTransitionLocked() {
	c.ensureDeferredCondLocked()
	c.deferredOpsBlock = true
	for c.deferredOps > 0 {
		c.deferredCond.Wait()
	}
}

func (c *DeferredRustConn) endExclusiveDeferredTransitionLocked() {
	if !c.deferredOpsBlock {
		return
	}
	c.deferredOpsBlock = false
	c.ensureDeferredCondLocked().Broadcast()
}

func (c *DeferredRustConn) appendDeferredWritePendingLocked(b []byte) {
	if len(b) == 0 {
		return
	}
	needed := c.deferredWriteLen + len(b)
	if cap(c.deferredWriteBuf) < needed {
		nextCap := cap(c.deferredWriteBuf)
		if nextCap < deferredWriteBatchCap {
			nextCap = deferredWriteBatchCap
		}
		for nextCap < needed {
			nextCap *= 2
		}
		next := make([]byte, needed, nextCap)
		copy(next, c.deferredWriteBuf[:c.deferredWriteLen])
		for i := range c.deferredWriteBuf {
			c.deferredWriteBuf[i] = 0
		}
		c.deferredWriteBuf = next
	}
	if len(c.deferredWriteBuf) < needed {
		c.deferredWriteBuf = c.deferredWriteBuf[:needed]
	}
	copy(c.deferredWriteBuf[c.deferredWriteLen:needed], b)
	c.deferredWriteLen = needed
}

func (c *DeferredRustConn) consumeDeferredWritePendingLocked(n int) {
	if n <= 0 || c.deferredWriteLen == 0 {
		return
	}
	if n >= c.deferredWriteLen {
		for i := 0; i < c.deferredWriteLen; i++ {
			c.deferredWriteBuf[i] = 0
		}
		c.deferredWriteLen = 0
		if len(c.deferredWriteBuf) > 0 {
			c.deferredWriteBuf = c.deferredWriteBuf[:0]
		}
		return
	}
	copy(c.deferredWriteBuf[:c.deferredWriteLen-n], c.deferredWriteBuf[n:c.deferredWriteLen])
	for i := c.deferredWriteLen - n; i < c.deferredWriteLen; i++ {
		c.deferredWriteBuf[i] = 0
	}
	c.deferredWriteLen -= n
}

func (c *DeferredRustConn) flushDeferredWritePendingLocked(h *native.DeferredSessionHandle, deadline time.Time) error {
	c.deferredWriteMu.Lock()
	defer c.deferredWriteMu.Unlock()
	if c.deferredWriteLen == 0 {
		return nil
	}
	n, err := deferredWriteWithDeadlineFn(h, c.deferredWriteBuf[:c.deferredWriteLen], deadline)
	c.logDeferredKTLSError(err)
	if err == nil && n > 0 {
		c.writeRecords.Add(1)
	}
	if err == nil && n < c.deferredWriteLen {
		err = io.ErrShortWrite
	}
	c.consumeDeferredWritePendingLocked(n)
	return err
}

func earlierDeadline(a, b time.Time) time.Time {
	switch {
	case a.IsZero():
		return b
	case b.IsZero():
		return a
	case b.Before(a):
		return b
	default:
		return a
	}
}

func (c *DeferredRustConn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	if n := c.consumeDeferredReadCache(b); n > 0 {
		return n, nil
	}

	for {
		if c.closed.Load() {
			return 0, gonet.ErrClosed
		}

		c.deferredMu.RLock()
		ktlsActive := c.ktlsActive
		detached := c.detached.Load()
		c.deferredMu.RUnlock()

		if ktlsActive {
			// Serve any plaintext drained during deferred->kTLS promotion first.
			var handler *KTLSKeyUpdateHandler
			c.deferredMu.Lock()
			if c.drainedOff < len(c.drainedData) {
				n := copy(b, c.drainedData[c.drainedOff:])
				c.drainedOff += n
				if c.drainedOff >= len(c.drainedData) {
					// Zero and release drained data.
					for i := range c.drainedData {
						c.drainedData[i] = 0
					}
					c.drainedData = nil
					c.drainedOff = 0
				}
				c.deferredMu.Unlock()
				return n, nil
			}
			handler = c.ktlsHandler
			c.deferredMu.Unlock()

			n, err := c.rawConn.Read(b)
			c.logDeferredKTLSError(err)
			if err != nil && isKeyExpired(err) && handler != nil {
				if herr := handler.Handle(); herr != nil {
					return 0, herr
				}
				return c.rawConn.Read(b)
			}
			return n, err
		}

		if detached {
			c.deferredMu.Lock()
			if c.drainedOff < len(c.drainedData) {
				n := copy(b, c.drainedData[c.drainedOff:])
				c.drainedOff += n
				if c.drainedOff >= len(c.drainedData) {
					for i := range c.drainedData {
						c.drainedData[i] = 0
					}
					c.drainedData = nil
					c.drainedOff = 0
				}
				c.deferredMu.Unlock()
				return n, nil
			}
			c.deferredMu.Unlock()
			return c.rawConn.Read(b)
		}

		h, acquired, err := c.beginDeferredHandleUse()
		if err != nil {
			return 0, err
		}
		if !acquired {
			continue
		}
		var n int
		defer c.endDeferredHandleUse()
		readDeadline := c.currentReadDeadline()
		if err := c.flushDeferredWritePendingLocked(h, earlierDeadline(readDeadline, c.currentWriteDeadline())); err != nil {
			return 0, err
		}
		if len(b) < deferredReadBatchThreshold {
			n, err = c.deferredReadBatched(h, b, readDeadline)
		} else {
			n, err = deferredReadWithDeadlineFn(h, b, readDeadline)
			c.logDeferredKTLSError(err)
		}
		if err == nil && n > 0 {
			c.readRecords.Add(1)
			c.readBytes.Add(int64(n))
		}
		return n, err
	}
}

func (c *DeferredRustConn) consumeDeferredReadCache(dst []byte) int {
	c.deferredReadMu.Lock()
	defer c.deferredReadMu.Unlock()
	if c.deferredReadOff >= c.deferredReadLen {
		return 0
	}
	n := copy(dst, c.deferredReadBuf[c.deferredReadOff:c.deferredReadLen])
	c.deferredReadOff += n
	if c.deferredReadOff >= c.deferredReadLen {
		c.deferredReadOff = 0
		c.deferredReadLen = 0
	}
	return n
}

// deferredReadBatched reads into an internal read-ahead buffer and serves `dst`
// from that buffer. This amortizes cgo call overhead for small reads while the
// deferred handle is pinned by beginDeferredHandleUse.
func (c *DeferredRustConn) deferredReadBatched(h *native.DeferredSessionHandle, dst []byte, deadline time.Time) (int, error) {
	c.deferredReadMu.Lock()
	defer c.deferredReadMu.Unlock()

	if c.deferredReadOff < c.deferredReadLen {
		n := copy(dst, c.deferredReadBuf[c.deferredReadOff:c.deferredReadLen])
		c.deferredReadOff += n
		if c.deferredReadOff >= c.deferredReadLen {
			c.deferredReadOff = 0
			c.deferredReadLen = 0
		}
		return n, nil
	}

	if cap(c.deferredReadBuf) < deferredReadBatchCap {
		c.deferredReadBuf = make([]byte, deferredReadBatchCap)
	}
	buf := c.deferredReadBuf[:deferredReadBatchCap]
	n, err := deferredReadWithDeadlineFn(h, buf, deadline)
	c.logDeferredKTLSError(err)
	if n <= 0 {
		return n, err
	}

	outN := copy(dst, buf[:n])
	if outN < n {
		c.deferredReadOff = outN
		c.deferredReadLen = n
		// Surface buffered plaintext first; the next read will drain cache,
		// then observe EOF/close status from native.DeferredRead.
		if err != nil {
			return outN, nil
		}
	}
	return outN, err
}

func (c *DeferredRustConn) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	for {
		if c.closed.Load() {
			return 0, gonet.ErrClosed
		}

		c.deferredMu.RLock()
		ktlsActive := c.ktlsActive
		detached := c.detached.Load()
		handler := c.ktlsHandler
		c.deferredMu.RUnlock()

		// Fast path after promotion: no native deferred handle involved.
		if ktlsActive {
			n, err := c.rawConn.Write(b)
			if err == nil {
				ktlsAfterWrite(n, handler, &c.writeRecords, &c.rotationFailures, c.rawConn.Close)
			}
			return n, err
		}
		// If detached (Vision command=2 completed): write plaintext to raw socket.
		if detached {
			return c.rawConn.Write(b)
		}

		h, acquired, err := c.beginDeferredHandleUse()
		if err != nil {
			return 0, err
		}
		if !acquired {
			continue
		}

		writeDeadline := c.currentWriteDeadline()
		if c.writeBatching.Load() && len(b) < deferredWriteBatchThreshold && writeDeadline.IsZero() {
			defer c.endDeferredHandleUse()
			c.deferredWriteMu.Lock()
			prevPending := c.deferredWriteLen
			c.appendDeferredWritePendingLocked(b)
			if c.deferredWriteLen < deferredWriteBatchThreshold {
				c.deferredWriteMu.Unlock()
				return len(b), nil
			}
			payloadLen := c.deferredWriteLen
			n, err := deferredWriteWithDeadlineFn(h, c.deferredWriteBuf[:payloadLen], writeDeadline)
			c.logDeferredKTLSError(err)
			if err == nil && n > 0 {
				c.writeRecords.Add(1)
			}
			if err == nil && n < payloadLen {
				err = io.ErrShortWrite
			}
			c.consumeDeferredWritePendingLocked(n)
			c.deferredWriteMu.Unlock()

			sentFromCurrent := 0
			if n > prevPending {
				sentFromCurrent = n - prevPending
				if sentFromCurrent > len(b) {
					sentFromCurrent = len(b)
				}
			}
			if err != nil && c.detached.Load() {
				rawN, rawErr := c.rawConn.Write(b[sentFromCurrent:])
				return sentFromCurrent + rawN, rawErr
			}
			return sentFromCurrent, err
		}

		defer c.endDeferredHandleUse()
		if err := c.flushDeferredWritePendingLocked(h, writeDeadline); err != nil {
			if c.detached.Load() {
				return c.rawConn.Write(b)
			}
			return 0, err
		}
		n, err := deferredWriteWithDeadlineFn(h, b, writeDeadline)
		c.logDeferredKTLSError(err)
		if err == nil && n > 0 {
			c.writeRecords.Add(1)
		}
		// Transition race: reader may detach while writer is still on rustls path.
		// Retry on raw socket once detached.
		if err != nil && c.detached.Load() {
			return c.rawConn.Write(b)
		}
		return n, err
	}
}

func (c *DeferredRustConn) logDeferredKTLSError(err error) {
	if err == nil {
		return
	}
	if isBadMessage(err) {
		c.logDeferredKTLSBadMessage()
		return
	}
	if isEIO(err) {
		c.logDeferredKTLSEIO()
	}
}

// DeferredRustConn mirrors RustConn diagnostics for kTLS errors during deferred paths.
func (c *DeferredRustConn) logDeferredKTLSBadMessage() {
	readRecs := c.readRecords.Load()
	readB := c.readBytes.Load()
	writeRecs := c.writeRecords.Load()
	c.deferredMu.RLock()
	rawConn := c.rawConn
	cipher := c.cipher
	version := c.version
	c.deferredMu.RUnlock()
	local := "<nil>"
	remote := "<nil>"
	if rawConn != nil {
		if a := rawConn.LocalAddr(); a != nil {
			local = a.String()
		}
		if a := rawConn.RemoteAddr(); a != nil {
			remote = a.String()
		}
	}
	var seqInfo string
	if rawConn != nil {
		if fd, err := ExtractFd(rawConn); err == nil {
			if seq, serr := ktlsRxDiagnostics(fd, cipher); serr == nil {
				seqInfo = fmt.Sprintf(" kernelRxSeq=%d", seq)
			} else {
				seqInfo = " kernelRxSeq=err:" + serr.Error()
			}
		} else {
			seqInfo = " fd=err:" + err.Error()
		}
	}
	errors.LogWarning(context.Background(),
		fmt.Sprintf("kTLS EBADMSG on DeferredRustConn: cipher=0x%04x version=0x%04x readRecords=%d readBytes=%d writeRecords=%d%s local=%s remote=%s",
			cipher, version, readRecs, readB, writeRecs, seqInfo, local, remote),
	)
}

func (c *DeferredRustConn) logDeferredKTLSEIO() {
	readRecs := c.readRecords.Load()
	readB := c.readBytes.Load()
	writeRecs := c.writeRecords.Load()
	c.deferredMu.RLock()
	rawConn := c.rawConn
	cipher := c.cipher
	version := c.version
	c.deferredMu.RUnlock()
	local := "<nil>"
	remote := "<nil>"
	if rawConn != nil {
		if a := rawConn.LocalAddr(); a != nil {
			local = a.String()
		}
		if a := rawConn.RemoteAddr(); a != nil {
			remote = a.String()
		}
	}
	var seqInfo string
	if rawConn != nil {
		if fd, err := ExtractFd(rawConn); err == nil {
			if seq, serr := ktlsRxDiagnostics(fd, cipher); serr == nil {
				seqInfo = fmt.Sprintf(" kernelRxSeq=%d", seq)
			} else {
				seqInfo = " kernelRxSeq=err:" + serr.Error()
			}
		}
	}
	errors.LogWarning(context.Background(),
		fmt.Sprintf("kTLS EIO on DeferredRustConn: cipher=0x%04x version=0x%04x readRecords=%d readBytes=%d writeRecords=%d%s local=%s remote=%s",
			cipher, version, readRecs, readB, writeRecs, seqInfo, local, remote),
	)
}

// DrainAndDetach drains rustls buffered plaintext and read-ahead bytes, then
// detaches the deferred session. Detached bytes are also staged internally so
// callers that stay on DeferredRustConn after a late detach still observe a
// lossless stream.
func (c *DeferredRustConn) DrainAndDetach() (plaintext []byte, rawAhead []byte, err error) {
	c.deferredMu.Lock()
	defer func() {
		c.endExclusiveDeferredTransitionLocked()
		c.deferredMu.Unlock()
	}()
	if c.closed.Load() {
		return nil, nil, gonet.ErrClosed
	}
	if c.ktlsActive {
		return nil, nil, errors.New("tls: DeferredRustConn: kTLS already active")
	}
	if c.detached.Load() {
		return nil, nil, nil
	}
	c.beginExclusiveDeferredTransitionLocked()
	h := c.handle
	if h == nil {
		return nil, nil, errors.New("tls: DeferredRustConn: already consumed or freed")
	}
	if err := c.flushDeferredWritePendingLocked(h, c.currentWriteDeadline()); err != nil {
		return nil, nil, errors.New("tls: DeferredRustConn: flush pending writes before detach").Base(err)
	}
	plaintext, rawAhead, err = deferredDrainAndDetachFn(h)
	if err != nil {
		// Keep handle for fallback-to-rustls behavior.
		return nil, nil, err
	}
	for i := range c.drainedData {
		c.drainedData[i] = 0
	}
	total := len(plaintext) + len(rawAhead)
	if total > 0 {
		staged := make([]byte, 0, total)
		staged = append(staged, plaintext...)
		staged = append(staged, rawAhead...)
		c.drainedData = staged
		c.drainedOff = 0
	} else {
		c.drainedData = nil
		c.drainedOff = 0
	}
	native.DeferredFree(h) // free Rust DeferredSession — restores fd state, closes dup'd fds
	c.handle = nil
	c.detached.Store(true)
	return plaintext, rawAhead, nil
}

// KTLSPromotionStatus is a typed outcome for deferred promotion.
type KTLSPromotionStatus uint8

const (
	KTLSPromotionEnabled KTLSPromotionStatus = iota
	KTLSPromotionCooldown
	KTLSPromotionUnsupported
	KTLSPromotionFailed
)

func (s KTLSPromotionStatus) String() string {
	switch s {
	case KTLSPromotionEnabled:
		return "enabled"
	case KTLSPromotionCooldown:
		return "cooldown"
	case KTLSPromotionUnsupported:
		return "unsupported"
	case KTLSPromotionFailed:
		return "failed"
	default:
		return "unknown"
	}
}

type KTLSPromotionOutcome struct {
	Status KTLSPromotionStatus
	State  KTLSState
}

// allow tests to override native DeferredEnableKTLS
var deferredReadFn = native.DeferredRead
var deferredReadWithDeadlineFn = func(h *native.DeferredSessionHandle, b []byte, deadline time.Time) (int, error) {
	if deadline.IsZero() {
		return deferredReadFn(h, b)
	}
	return native.DeferredReadWithDeadline(h, b, deadline)
}
var deferredWriteFn = native.DeferredWrite
var deferredWriteWithDeadlineFn = func(h *native.DeferredSessionHandle, b []byte, deadline time.Time) (int, error) {
	if deadline.IsZero() {
		return deferredWriteFn(h, b)
	}
	return native.DeferredWriteWithDeadline(h, b, deadline)
}
var deferredDrainAndDetachFn = native.DeferredDrainAndDetach
var deferredEnableKTLSFn = native.DeferredEnableKTLS
var deferredHandleAliveFn = native.DeferredHandleAlive
var nativeFullKTLSSupportedFn = NativeFullKTLSSupported

func failCloseRawConn(rawConn gonet.Conn) {
	if rawConn == nil {
		return
	}
	if fd, err := ExtractFd(rawConn); err == nil {
		_ = syscall.Shutdown(fd, syscall.SHUT_RDWR)
	}
	_ = rawConn.Close()
}

// EnableKTLS installs kTLS on the socket in-place and returns a typed outcome.
// Existing callers can continue using the legacy error-return contract via EnableKTLS().
func (c *DeferredRustConn) EnableKTLSOutcome() (KTLSPromotionOutcome, error) {
	out := KTLSPromotionOutcome{Status: KTLSPromotionFailed}
	closeAfterUnlock := false
	closeRawConn := false
	var rawConnToClose gonet.Conn
	c.deferredMu.Lock()
	defer func() {
		c.endExclusiveDeferredTransitionLocked()
		c.deferredMu.Unlock()
		if closeAfterUnlock && closeRawConn {
			failCloseRawConn(rawConnToClose)
		}
	}()
	if c.detached.Load() {
		return out, errors.New("tls: DeferredRustConn: already detached")
	}
	if c.handle == nil {
		return out, errors.New("tls: DeferredRustConn: already consumed or freed")
	}
	scope := c.ktlsScope
	if scope == "" {
		scope = ktlsScopeDefault
	}
	if DeferredKTLSPromotionDisabledFor(scope) {
		out.Status = KTLSPromotionCooldown
		return out, nil
	}
	if !nativeFullKTLSSupportedFn() {
		out.Status = KTLSPromotionUnsupported
		return out, nil
	}
	c.beginExclusiveDeferredTransitionLocked()
	if err := c.flushDeferredWritePendingLocked(c.handle, c.currentWriteDeadline()); err != nil {
		return out, errors.New("tls: deferred kTLS promotion flush failed").Base(err)
	}
	result, err := deferredEnableKTLSFn(c.handle)
	handleRetained := c.handle != nil && deferredHandleAliveFn(c.handle)
	if !handleRetained {
		c.handle = nil
	}

	var (
		handler *KTLSKeyUpdateHandler
		state   *native.TlsStateHandle
		drained []byte
	)
	rollbackPromotionFailure := func() {
		if handler != nil {
			handler.Close()
			handler = nil
		}
		if state != nil {
			native.TlsStateFree(state)
			state = nil
		}
		for i := range drained {
			drained[i] = 0
		}
		drained = nil
		if c.ktlsHandler != nil {
			c.ktlsHandler.Close()
			c.ktlsHandler = nil
		}
		if c.state != nil {
			native.TlsStateFree(c.state)
			c.state = nil
		}
		for i := range c.drainedData {
			c.drainedData[i] = 0
		}
		c.drainedData = nil
		c.drainedOff = 0
		c.deferredReadMu.Lock()
		if !handleRetained {
			for i := range c.deferredReadBuf {
				c.deferredReadBuf[i] = 0
			}
			c.deferredReadBuf = nil
			c.deferredReadOff = 0
			c.deferredReadLen = 0
		}
		c.deferredReadMu.Unlock()
		c.ktlsState = KTLSState{}
		c.ktlsActive = false
	}
	failPromotion := func(err error) error {
		rollbackPromotionFailure()
		deferKTLSPromotionForCooldownScope(scope)
		if !handleRetained {
			closeAfterUnlock = true
			if c.closed.CompareAndSwap(false, true) {
				closeRawConn = true
				rawConnToClose = c.rawConn
			}
		}
		return err
	}

	if err != nil {
		if !handleRetained {
			return out, failPromotion(errors.New("tls: deferred kTLS promotion consumed deferred session").Base(err))
		}
		return out, failPromotion(err)
	}
	defer result.ZeroSecrets()
	if result.DeferredHandleOwnership == native.DeferredHandleOwnershipRetained {
		// Success with retained ownership is an invalid contract; fail safe.
		return out, failPromotion(errors.New("tls: deferred kTLS promotion returned retained ownership on success"))
	}
	// Successful native promotion consumed the deferred handle.
	c.handle = nil

	state = result.StateHandle
	result.StateHandle = nil
	drained = result.DrainedData
	result.DrainedData = nil

	// Deferred handover must be full TX/RX kTLS; otherwise rustls state is
	// already consumed and this connection can no longer safely carry TLS I/O.
	if !result.KtlsTx || !result.KtlsRx {
		rollbackPromotionFailure()
		if handleRetained {
			out.Status = KTLSPromotionUnsupported
			return out, nil
		}
		return out, failPromotion(errors.New("tls: deferred kTLS promotion incomplete and consumed deferred session"))
	}

	// Extract secrets and create KeyUpdateHandler first, then zero secrets
	// via defer to minimize the window where key material lives on the Go heap.
	if len(result.TxSecret) > 0 && result.Version == 0x0304 {
		if fd, err := ExtractFd(c.rawConn); err == nil {
			handler = newKTLSKeyUpdateHandler(fd, result.CipherSuite, result.RxSecret, result.TxSecret)
		}
	}

	// Optional post-install sanity check: read a zero-length MSG_PEEK to confirm
	// kTLS stack is responsive. If it returns EAGAIN/OK, proceed; if it returns
	// EBADMSG/errno, mark promotion as failed and terminate the consumed session.
	if fd, err := ExtractFd(c.rawConn); err == nil {
		var buf [0]byte
		_, _, serr := syscall.Recvfrom(fd, buf[:], syscall.MSG_PEEK)
		if serr != nil && serr != syscall.EAGAIN && serr != syscall.EWOULDBLOCK {
			return out, failPromotion(errors.New("tls: kTLS post-install sanity failed").Base(serr))
		}
	}

	// Publish new state only after all promotion checks succeed.
	if c.ktlsHandler != nil {
		c.ktlsHandler.Close()
	}
	c.ktlsHandler = handler
	handler = nil
	if c.state != nil {
		native.TlsStateFree(c.state)
	}
	c.state = state
	state = nil
	for i := range c.drainedData {
		c.drainedData[i] = 0
	}
	c.drainedData = drained
	drained = nil
	c.drainedOff = 0
	c.ktlsState = KTLSState{Enabled: true, TxReady: true, RxReady: true}
	c.ktlsActive = true
	c.cipher = result.CipherSuite

	out.Status = KTLSPromotionEnabled
	out.State = c.ktlsState
	return out, nil
}

// EnableKTLS preserves the legacy signature; on cooldown/unsupported it now returns an error.
func (c *DeferredRustConn) EnableKTLS() error {
	out, err := c.EnableKTLSOutcome()
	if err != nil {
		return err
	}
	if out.Status != KTLSPromotionEnabled {
		return errors.New("tls: deferred kTLS promotion " + out.Status.String())
	}
	return nil
}

func (c *DeferredRustConn) Close() error {
	if !c.closed.CompareAndSwap(false, true) {
		return nil // already closed by another goroutine
	}
	// DeferredSession uses dup'd socket FDs on the Rust side. Shutdown the
	// original fd first so blocked deferred reads/writes wake up promptly.
	if fd, err := ExtractFd(c.rawConn); err == nil {
		_ = syscall.Shutdown(fd, syscall.SHUT_RDWR)
	}

	c.deferredMu.Lock()
	c.beginExclusiveDeferredTransitionLocked()
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
	c.drainedOff = 0
	c.endExclusiveDeferredTransitionLocked()
	c.deferredMu.Unlock()

	// Zero and release deferred read-ahead plaintext.
	c.deferredReadMu.Lock()
	for i := range c.deferredReadBuf {
		c.deferredReadBuf[i] = 0
	}
	c.deferredReadBuf = nil
	c.deferredReadOff = 0
	c.deferredReadLen = 0
	c.deferredReadMu.Unlock()

	c.deferredWriteMu.Lock()
	for i := 0; i < c.deferredWriteLen; i++ {
		c.deferredWriteBuf[i] = 0
	}
	c.deferredWriteBuf = nil
	c.deferredWriteLen = 0
	c.deferredWriteMu.Unlock()

	return c.rawConn.Close()
}

// NetConn returns the underlying raw connection.
// Used by UnwrapRawConn to access the raw TCP socket.
func (c *DeferredRustConn) NetConn() gonet.Conn {
	c.deferredMu.RLock()
	defer c.deferredMu.RUnlock()
	return c.rawConn
}

// KTLSEnabled returns the kTLS state (empty before EnableKTLS, populated after).
func (c *DeferredRustConn) KTLSEnabled() KTLSState {
	c.deferredMu.RLock()
	defer c.deferredMu.RUnlock()
	return c.ktlsState
}

// HasDeferredHandle reports whether the native deferred session handle is still
// available for rustls I/O (i.e., not consumed for kTLS or freed/detached).
func (c *DeferredRustConn) HasDeferredHandle() bool {
	c.deferredMu.RLock()
	defer c.deferredMu.RUnlock()
	return c.handle != nil && deferredHandleAliveFn(c.handle) && !c.ktlsActive && !c.detached.Load()
}

// KTLSKeyUpdateHandler returns the key update handler (nil before EnableKTLS).
func (c *DeferredRustConn) KTLSKeyUpdateHandler() *KTLSKeyUpdateHandler {
	c.deferredMu.RLock()
	defer c.deferredMu.RUnlock()
	return c.ktlsHandler
}

// IsDetached reports whether the deferred rustls session has been detached.
// Callers should prefer NetConn() directly, though DeferredRustConn will keep
// serving any staged detached plaintext for correctness.
func (c *DeferredRustConn) IsDetached() bool {
	return c.detached.Load()
}

// RestoreNonBlock restores O_NONBLOCK on the underlying fd without detaching.
// After this call, Go can safely write to the raw socket (via UnwrapRawConn)
// without blocking the OS thread, while Rust's reader/writer handle EAGAIN
// via poll(2).
func (c *DeferredRustConn) RestoreNonBlock() error {
	if c.detached.Load() {
		return nil // already detached, O_NONBLOCK already restored
	}
	c.deferredMu.RLock()
	defer c.deferredMu.RUnlock()
	if c.handle == nil {
		return nil
	}
	return native.DeferredRestoreNonBlock(c.handle)
}

// ConnectionState returns a tls.ConnectionState with REALITY session metadata.
func (c *DeferredRustConn) ConnectionState() tls.ConnectionState {
	c.deferredMu.RLock()
	defer c.deferredMu.RUnlock()
	return tls.ConnectionState{
		HandshakeComplete:  true,
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
	c.deadlineMu.Lock()
	c.readDeadline = t
	c.writeDeadline = t
	c.deadlineMu.Unlock()
	if c.rawConn == nil {
		return gonet.ErrClosed
	}
	return c.rawConn.SetDeadline(t)
}

func (c *DeferredRustConn) currentReadDeadline() time.Time {
	c.deadlineMu.RLock()
	defer c.deadlineMu.RUnlock()
	return c.readDeadline
}

func (c *DeferredRustConn) currentWriteDeadline() time.Time {
	c.deadlineMu.RLock()
	defer c.deadlineMu.RUnlock()
	return c.writeDeadline
}

// SetReadDeadline updates the deferred rustls read deadline and mirrors it to
// the underlying raw connection for post-detach / kTLS paths.
func (c *DeferredRustConn) SetReadDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.readDeadline = t
	c.deadlineMu.Unlock()
	if c.rawConn == nil {
		return gonet.ErrClosed
	}
	return c.rawConn.SetReadDeadline(t)
}

// SetWriteDeadline updates the deferred rustls write deadline and mirrors it to
// the underlying raw connection for post-detach / kTLS paths.
func (c *DeferredRustConn) SetWriteDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.writeDeadline = t
	c.deadlineMu.Unlock()
	if c.rawConn == nil {
		return gonet.ErrClosed
	}
	return c.rawConn.SetWriteDeadline(t)
}

// Verify DeferredRustConn implements the required interfaces.
var _ gonet.Conn = (*DeferredRustConn)(nil)
var _ Interface = (*DeferredRustConn)(nil)

// ---------------------------------------------------------------------------
// KTLSPlaintextConn — hides ConnectionState() from http.Server
// ---------------------------------------------------------------------------

// KTLSPlaintextConn wraps a kTLS-enabled connection, withholding the
// ConnectionState() method so http.Server treats it as plaintext and uses h2c
// detection. On the wire, kTLS still handles encryption transparently in the
// kernel.
type KTLSPlaintextConn struct {
	inner    gonet.Conn
	tlsState tls.ConnectionState
}

// NewKTLSPlaintextConn wraps a kTLS-enabled connection for server-side h2c use.
// It preserves the TLS ConnectionState for HTTP stacks that need it.
func NewKTLSPlaintextConn(conn gonet.Conn) *KTLSPlaintextConn {
	kc := &KTLSPlaintextConn{inner: conn}
	if st, ok := conn.(interface{ ConnectionState() tls.ConnectionState }); ok {
		kc.tlsState = st.ConnectionState()
	}
	return kc
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

// TLSState exposes the captured TLS state without satisfying net/http's TLS
// detection interface.
func (c *KTLSPlaintextConn) TLSState() tls.ConnectionState {
	return c.tlsState
}

// Verify KTLSPlaintextConn implements net.Conn.
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
