package tcp

import (
	"context"
	gotls "crypto/tls"
	stderrors "errors"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	goreality "github.com/xtls/reality"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/native"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/ebpf"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

// maxConcurrentHandshakes is the maximum number of concurrent TLS/REALITY
// handshakes per TCP listener. Once the handshake completes, the semaphore
// is released so it only gates CPU-intensive handshake work, not session
// lifetime. The worker-level semaphore in app/proxyman/inbound gates total
// concurrent sessions.
const maxConcurrentHandshakes = 32768

// Listener is an internet.Listener that listens for TCP connections.
type Listener struct {
	listener          net.Listener
	tlsConfig         *gotls.Config
	tlsXrayConfig     *tls.Config
	realityConfig     *goreality.Config
	realityXrayConfig *reality.Config
	authConfig        internet.ConnectionAuthenticator
	config            *Config
	addConn           internet.ConnHandler
	connSemaphore     chan struct{}
}

const tlsHandshakeTimeout = 8 * time.Second
const tcpRealityMarkerLogInterval = 30 * time.Second
const rustPeekBypassWindow = 3 * time.Minute
const rustPeekBypassLoopbackWindow = 5 * time.Second

var (
	realityBlacklist     *ebpf.BlacklistManager
	realityBlacklistOnce sync.Once

	tcpRealityMarkerLastLogUnix atomic.Int64

	tcpRealityMarkerRustAttempt                        atomic.Uint64
	tcpRealityMarkerRustSuccess                        atomic.Uint64
	tcpRealityMarkerRustPathIneligible                 atomic.Uint64
	tcpRealityMarkerRustFDExtractFailed                atomic.Uint64
	tcpRealityMarkerRustAuthFallback                   atomic.Uint64
	tcpRealityMarkerRustPeekTimeoutFallback            atomic.Uint64
	tcpRealityMarkerRustPeekBypassActive               atomic.Uint64
	tcpRealityMarkerRustPeekBypassSet                  atomic.Uint64
	tcpRealityMarkerRustPeekBypassLoopback             atomic.Uint64
	tcpRealityMarkerRustPeekBypassLoopbackScopedSet    atomic.Uint64
	tcpRealityMarkerRustPeekBypassLoopbackScopedActive atomic.Uint64
	tcpRealityMarkerRustWrapFailed                     atomic.Uint64
	tcpRealityMarkerRustHandshakeFailed                atomic.Uint64
	tcpRealityMarkerRustDurationNanosTotal             atomic.Uint64
	tcpRealityMarkerRustDurationSamples                atomic.Uint64

	tcpRealityMarkerGoFallbackAttempt    atomic.Uint64
	tcpRealityMarkerGoFallbackSuccess    atomic.Uint64
	tcpRealityMarkerGoFallbackFailed     atomic.Uint64
	tcpRealityMarkerGoFallbackNanosTotal atomic.Uint64
	tcpRealityMarkerGoFallbackSamples    atomic.Uint64

	tcpRealityMarkerLastRustAttempt                        atomic.Uint64
	tcpRealityMarkerLastRustSuccess                        atomic.Uint64
	tcpRealityMarkerLastRustPathIneligible                 atomic.Uint64
	tcpRealityMarkerLastRustFDExtractFailed                atomic.Uint64
	tcpRealityMarkerLastRustAuthFallback                   atomic.Uint64
	tcpRealityMarkerLastRustPeekTimeoutFallback            atomic.Uint64
	tcpRealityMarkerLastRustPeekBypassActive               atomic.Uint64
	tcpRealityMarkerLastRustPeekBypassSet                  atomic.Uint64
	tcpRealityMarkerLastRustPeekBypassLoopback             atomic.Uint64
	tcpRealityMarkerLastRustPeekBypassLoopbackScopedSet    atomic.Uint64
	tcpRealityMarkerLastRustPeekBypassLoopbackScopedActive atomic.Uint64
	tcpRealityMarkerLastRustWrapFailed                     atomic.Uint64
	tcpRealityMarkerLastRustHandshakeFailed                atomic.Uint64
	tcpRealityMarkerLastRustDurationNanosTotal             atomic.Uint64
	tcpRealityMarkerLastRustDurationSamples                atomic.Uint64
	tcpRealityMarkerLastGoFallbackAttempt                  atomic.Uint64
	tcpRealityMarkerLastGoFallbackSuccess                  atomic.Uint64
	tcpRealityMarkerLastGoFallbackFailed                   atomic.Uint64
	tcpRealityMarkerLastGoFallbackNanosTotal               atomic.Uint64
	tcpRealityMarkerLastGoFallbackSamples                  atomic.Uint64

	getRealityBlacklistFn   = getRealityBlacklist
	realityServerFn         = reality.Server
	doRustRealityDeferredFn = func(v *Listener, fd int) (*native.DeferredResult, error) {
		return v.doRustRealityDeferred(fd)
	}
	// Rust REALITY server path re-enabled with deferred kTLS:
	// TLS handshake completes via rustls but kTLS is NOT installed yet.
	// The VLESS handler decides: Vision flows keep rustls (no kTLS),
	// non-Vision flows call EnableKTLS() to install kTLS in-place.
	// Camouflage is preserved: auth uses MSG_PEEK so unauthenticated
	// probers always fall through to Go goreality which mirrors the
	// real Dest's ServerHello. Only authenticated clients (our own
	// Xray clients) see the Rust ServerHello.
	// See docs/ktls-vision-incompatibility.md.
	useNativeRealityServerFn = func(v *Listener) bool {
		return nativeRealityServerEligible(v, native.Available(), tls.NativeFullKTLSSupported(), tls.DeferredKTLSPromotionDisabled())
	}

	rustPeekBypassByRemote sync.Map // key: remote scope key (IP for non-loopback, endpoint for loopback), value: int64(unix nano until)
)

func isLoopbackAddr(addr net.Addr) bool {
	ip := extractIP(addr)
	return ip != nil && ip.IsLoopback()
}

func rustPeekBypassKey(addr net.Addr) string {
	ip := extractIP(addr)
	if ip == nil {
		return ""
	}
	if ip.IsLoopback() {
		// Keep loopback bypass flow-scoped so one localhost timeout does not
		// suppress Rust deferred handshakes for unrelated localhost flows.
		return addr.String()
	}
	return ip.String()
}

func shouldBypassRustDeferredForRemote(addr net.Addr, nowUnix int64) bool {
	key := rustPeekBypassKey(addr)
	if key == "" {
		return false
	}
	untilAny, ok := rustPeekBypassByRemote.Load(key)
	if !ok {
		return false
	}
	untilUnix, ok := untilAny.(int64)
	if !ok {
		rustPeekBypassByRemote.Delete(key)
		return false
	}
	if untilUnix <= nowUnix {
		rustPeekBypassByRemote.Delete(key)
		return false
	}
	return true
}

func bypassWindowForRemote(addr net.Addr) time.Duration {
	if isLoopbackAddr(addr) {
		return rustPeekBypassLoopbackWindow
	}
	return rustPeekBypassWindow
}

func setRustPeekBypassForRemote(addr net.Addr, nowUnix int64) (time.Duration, bool) {
	key := rustPeekBypassKey(addr)
	if key == "" {
		return 0, false
	}
	window := bypassWindowForRemote(addr)
	rustPeekBypassByRemote.Store(key, nowUnix+int64(window))
	return window, true
}

func pruneAndCountRustPeekBypass(nowUnix int64) int {
	tracked := 0
	rustPeekBypassByRemote.Range(func(key, value any) bool {
		untilUnix, ok := value.(int64)
		if !ok || untilUnix <= nowUnix {
			rustPeekBypassByRemote.Delete(key)
			return true
		}
		tracked++
		return true
	})
	return tracked
}

func nativeRealityServerEligible(v *Listener, nativeAvailable, fullKTLS, deferredPromotionDisabled bool) bool {
	if !nativeAvailable || !fullKTLS || deferredPromotionDisabled || v == nil || v.realityXrayConfig == nil {
		return false
	}
	if v.config != nil && v.config.AcceptProxyProtocol {
		return false
	}
	// Go REALITY derives ML-DSA signing key from mldsa65_seed. Keep Go path
	// until native deferred server config wires equivalent signing material.
	if len(v.realityXrayConfig.Mldsa65Seed) > 0 {
		return false
	}
	return true
}

func tcpMarkerSnapshot(total *atomic.Uint64, last *atomic.Uint64) (current uint64, delta uint64) {
	current = total.Load()
	previous := last.Swap(current)
	return current, current - previous
}

func maybeLogTCPRealityHandoverMarkers(ctx context.Context) {
	now := time.Now().UnixNano()
	last := tcpRealityMarkerLastLogUnix.Load()
	if last != 0 && now-last < int64(tcpRealityMarkerLogInterval) {
		return
	}
	if !tcpRealityMarkerLastLogUnix.CompareAndSwap(last, now) {
		return
	}

	rustPeekBypassTracked := pruneAndCountRustPeekBypass(now)

	rustAttempt, rustAttemptDelta := tcpMarkerSnapshot(&tcpRealityMarkerRustAttempt, &tcpRealityMarkerLastRustAttempt)
	rustSuccess, rustSuccessDelta := tcpMarkerSnapshot(&tcpRealityMarkerRustSuccess, &tcpRealityMarkerLastRustSuccess)
	rustPathIneligible, rustPathIneligibleDelta := tcpMarkerSnapshot(&tcpRealityMarkerRustPathIneligible, &tcpRealityMarkerLastRustPathIneligible)
	rustFDExtractFailed, rustFDExtractFailedDelta := tcpMarkerSnapshot(&tcpRealityMarkerRustFDExtractFailed, &tcpRealityMarkerLastRustFDExtractFailed)
	rustAuthFallback, rustAuthFallbackDelta := tcpMarkerSnapshot(&tcpRealityMarkerRustAuthFallback, &tcpRealityMarkerLastRustAuthFallback)
	rustPeekFallback, rustPeekFallbackDelta := tcpMarkerSnapshot(&tcpRealityMarkerRustPeekTimeoutFallback, &tcpRealityMarkerLastRustPeekTimeoutFallback)
	rustPeekBypassActive, rustPeekBypassActiveDelta := tcpMarkerSnapshot(&tcpRealityMarkerRustPeekBypassActive, &tcpRealityMarkerLastRustPeekBypassActive)
	rustPeekBypassSet, rustPeekBypassSetDelta := tcpMarkerSnapshot(&tcpRealityMarkerRustPeekBypassSet, &tcpRealityMarkerLastRustPeekBypassSet)
	rustPeekBypassLoopback, rustPeekBypassLoopbackDelta := tcpMarkerSnapshot(&tcpRealityMarkerRustPeekBypassLoopback, &tcpRealityMarkerLastRustPeekBypassLoopback)
	rustPeekBypassLoopbackScopedSet, rustPeekBypassLoopbackScopedSetDelta := tcpMarkerSnapshot(&tcpRealityMarkerRustPeekBypassLoopbackScopedSet, &tcpRealityMarkerLastRustPeekBypassLoopbackScopedSet)
	rustPeekBypassLoopbackScopedActive, rustPeekBypassLoopbackScopedActiveDelta := tcpMarkerSnapshot(&tcpRealityMarkerRustPeekBypassLoopbackScopedActive, &tcpRealityMarkerLastRustPeekBypassLoopbackScopedActive)
	rustWrapFailed, rustWrapFailedDelta := tcpMarkerSnapshot(&tcpRealityMarkerRustWrapFailed, &tcpRealityMarkerLastRustWrapFailed)
	rustHandshakeFailed, rustHandshakeFailedDelta := tcpMarkerSnapshot(&tcpRealityMarkerRustHandshakeFailed, &tcpRealityMarkerLastRustHandshakeFailed)
	rustNanos, rustNanosDelta := tcpMarkerSnapshot(&tcpRealityMarkerRustDurationNanosTotal, &tcpRealityMarkerLastRustDurationNanosTotal)
	rustSamples, rustSamplesDelta := tcpMarkerSnapshot(&tcpRealityMarkerRustDurationSamples, &tcpRealityMarkerLastRustDurationSamples)

	goFallbackAttempt, goFallbackAttemptDelta := tcpMarkerSnapshot(&tcpRealityMarkerGoFallbackAttempt, &tcpRealityMarkerLastGoFallbackAttempt)
	goFallbackSuccess, goFallbackSuccessDelta := tcpMarkerSnapshot(&tcpRealityMarkerGoFallbackSuccess, &tcpRealityMarkerLastGoFallbackSuccess)
	goFallbackFailed, goFallbackFailedDelta := tcpMarkerSnapshot(&tcpRealityMarkerGoFallbackFailed, &tcpRealityMarkerLastGoFallbackFailed)
	goFallbackNanos, goFallbackNanosDelta := tcpMarkerSnapshot(&tcpRealityMarkerGoFallbackNanosTotal, &tcpRealityMarkerLastGoFallbackNanosTotal)
	goFallbackSamples, goFallbackSamplesDelta := tcpMarkerSnapshot(&tcpRealityMarkerGoFallbackSamples, &tcpRealityMarkerLastGoFallbackSamples)

	var rustAvgNs uint64
	if rustSamples > 0 {
		rustAvgNs = rustNanos / rustSamples
	}
	var rustAvgNsDelta uint64
	if rustSamplesDelta > 0 {
		rustAvgNsDelta = rustNanosDelta / rustSamplesDelta
	}
	var goFallbackAvgNs uint64
	if goFallbackSamples > 0 {
		goFallbackAvgNs = goFallbackNanos / goFallbackSamples
	}
	var goFallbackAvgNsDelta uint64
	if goFallbackSamplesDelta > 0 {
		goFallbackAvgNsDelta = goFallbackNanosDelta / goFallbackSamplesDelta
	}

	errors.LogInfo(ctx, "reality markers[kind=tcp-handover]: ",
		"rust_attempt=", rustAttempt, "(+", rustAttemptDelta, ") ",
		"rust_success=", rustSuccess, "(+", rustSuccessDelta, ") ",
		"rust_path_ineligible=", rustPathIneligible, "(+", rustPathIneligibleDelta, ") ",
		"rust_fd_extract_failed=", rustFDExtractFailed, "(+", rustFDExtractFailedDelta, ") ",
		"rust_auth_fallback=", rustAuthFallback, "(+", rustAuthFallbackDelta, ") ",
		"rust_peek_timeout_fallback=", rustPeekFallback, "(+", rustPeekFallbackDelta, ") ",
		"rust_peek_bypass_active=", rustPeekBypassActive, "(+", rustPeekBypassActiveDelta, ") ",
		"rust_peek_bypass_set=", rustPeekBypassSet, "(+", rustPeekBypassSetDelta, ") ",
		"rust_peek_bypass_loopback=", rustPeekBypassLoopback, "(+", rustPeekBypassLoopbackDelta, ") ",
		"rust_peek_bypass_loopback_scoped_set=", rustPeekBypassLoopbackScopedSet, "(+", rustPeekBypassLoopbackScopedSetDelta, ") ",
		"rust_peek_bypass_loopback_scoped_active=", rustPeekBypassLoopbackScopedActive, "(+", rustPeekBypassLoopbackScopedActiveDelta, ") ",
		"rust_peek_bypass_tracked=", rustPeekBypassTracked, " ",
		"rust_wrap_failed=", rustWrapFailed, "(+", rustWrapFailedDelta, ") ",
		"rust_handshake_failed=", rustHandshakeFailed, "(+", rustHandshakeFailedDelta, ") ",
		"rust_duration_ns=", rustNanos, "(+", rustNanosDelta, ") ",
		"rust_samples=", rustSamples, "(+", rustSamplesDelta, ") ",
		"rust_avg_ns=", rustAvgNs, "(+", rustAvgNsDelta, ") ",
		"go_fallback_attempt=", goFallbackAttempt, "(+", goFallbackAttemptDelta, ") ",
		"go_fallback_success=", goFallbackSuccess, "(+", goFallbackSuccessDelta, ") ",
		"go_fallback_failed=", goFallbackFailed, "(+", goFallbackFailedDelta, ") ",
		"go_fallback_duration_ns=", goFallbackNanos, "(+", goFallbackNanosDelta, ") ",
		"go_fallback_samples=", goFallbackSamples, "(+", goFallbackSamplesDelta, ") ",
		"go_fallback_avg_ns=", goFallbackAvgNs, "(+", goFallbackAvgNsDelta, ")",
	)
}

// getRealityBlacklist returns the global REALITY auth blacklist manager,
// lazily initialized on first call.
func getRealityBlacklist() *ebpf.BlacklistManager {
	realityBlacklistOnce.Do(func() {
		realityBlacklist = ebpf.NewBlacklistManager(ebpf.DefaultBlacklistConfig())
	})
	return realityBlacklist
}

// extractIP extracts the IP address from a net.Addr.
func extractIP(addr net.Addr) net.IP {
	switch a := addr.(type) {
	case *net.TCPAddr:
		return a.IP
	case *net.UDPAddr:
		return a.IP
	}
	// Try parsing as "host:port" string.
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return nil
	}
	return net.ParseAddress(host).IP()
}

// ListenTCP creates a new Listener based on configurations.
func ListenTCP(ctx context.Context, address net.Address, port net.Port, streamSettings *internet.MemoryStreamConfig, handler internet.ConnHandler) (internet.Listener, error) {
	l := &Listener{
		addConn:       handler,
		connSemaphore: make(chan struct{}, maxConcurrentHandshakes),
	}
	tcpSettings := streamSettings.ProtocolSettings.(*Config)
	l.config = tcpSettings
	if l.config != nil {
		if streamSettings.SocketSettings == nil {
			streamSettings.SocketSettings = &internet.SocketConfig{}
		}
		streamSettings.SocketSettings.AcceptProxyProtocol = l.config.AcceptProxyProtocol || streamSettings.SocketSettings.AcceptProxyProtocol
	}
	var listener net.Listener
	var err error
	if port == net.Port(0) { // unix
		if !address.Family().IsDomain() {
			return nil, errors.New("invalid unix listen: ", address).AtError()
		}
		listener, err = internet.ListenSystem(ctx, &net.UnixAddr{
			Name: address.Domain(),
			Net:  "unix",
		}, streamSettings.SocketSettings)
		if err != nil {
			return nil, errors.New("failed to listen Unix Domain Socket on ", address).Base(err)
		}
		errors.LogInfo(ctx, "listening Unix Domain Socket on ", address)
	} else {
		listener, err = internet.ListenSystem(ctx, &net.TCPAddr{
			IP:   address.IP(),
			Port: int(port),
		}, streamSettings.SocketSettings)
		if err != nil {
			return nil, errors.New("failed to listen TCP on ", address, ":", port).Base(err)
		}
		errors.LogInfo(ctx, "listening TCP on ", address, ":", port)
	}

	if streamSettings.SocketSettings != nil && streamSettings.SocketSettings.AcceptProxyProtocol {
		errors.LogWarning(ctx, "accepting PROXY protocol")
	}

	l.listener = listener

	if config := tls.ConfigFromStreamSettings(streamSettings); config != nil {
		l.tlsConfig = config.GetTLSConfig()
		l.tlsXrayConfig = config
	}
	if config := reality.ConfigFromStreamSettings(streamSettings); config != nil {
		l.realityConfig = config.GetREALITYConfig()
		l.realityXrayConfig = config
		go goreality.DetectPostHandshakeRecordsLens(l.realityConfig)
	}

	if tcpSettings.HeaderSettings != nil {
		headerConfig, err := tcpSettings.HeaderSettings.GetInstance()
		if err != nil {
			return nil, errors.New("invalid header settings").Base(err).AtError()
		}
		auth, err := internet.CreateConnectionAuthenticator(headerConfig)
		if err != nil {
			return nil, errors.New("invalid header settings.").Base(err).AtError()
		}
		l.authConfig = auth
	}

	go l.keepAccepting()
	return l, nil
}

func (v *Listener) keepAccepting() {
	for {
		conn, err := v.listener.Accept()
		if err != nil {
			errStr := err.Error()
			if strings.Contains(errStr, "closed") {
				break
			}
			errors.LogWarningInner(context.Background(), err, "failed to accepted raw connections")
			if strings.Contains(errStr, "too many") {
				time.Sleep(time.Millisecond * 500)
			}
			continue
		}
		select {
		case v.connSemaphore <- struct{}{}:
		default:
			errors.LogWarning(context.Background(), "TCP connection limit reached (", maxConcurrentHandshakes, "), rejecting connection from ", conn.RemoteAddr())
			_ = conn.Close()
			continue
		}
		go func(rawConn net.Conn) {
			var handshakeReleased atomic.Bool
			var realityFailureRecorded atomic.Bool
			releaseHandshake := func() {
				if handshakeReleased.CompareAndSwap(false, true) {
					<-v.connSemaphore
				}
			}
			// conn tracks the current connection — starts as rawConn, may be
			// reassigned to a TLS/REALITY wrapper during handshake. Declared
			// before the panic handler so the closure captures the variable
			// (not the initial value), ensuring we close the correct object.
			conn := rawConn
			recordRealityFailureOnce := func() {
				if !realityFailureRecorded.CompareAndSwap(false, true) {
					return
				}
				if bl := getRealityBlacklistFn(); bl != nil {
					bl.RecordFailure(extractIP(conn.RemoteAddr()))
				}
			}
			defer releaseHandshake()
			defer func() {
				if r := recover(); r != nil {
					errors.LogError(context.Background(), "panic in TCP listener handler: ", r)
					_ = conn.Close()
				}
			}()
			if v.tlsConfig != nil {
				// Complete the TLS handshake first and defer any kTLS decision
				// to protocol-layer logic (for example, VLESS flow handling).
				// This avoids eager kTLS state transitions before the protocol
				// decides whether direct-copy stripping is required.
				tlsConn := tls.Server(conn, v.tlsConfig)
				// Reassign conn immediately so the panic handler's defer
				// closes the TLS wrapper (not just rawConn) on panic.
				conn = tlsConn
				if err := conn.SetDeadline(time.Now().Add(tlsHandshakeTimeout)); err != nil {
					errors.LogWarningInner(context.Background(), err, "failed to set TLS handshake deadline on accepted connection")
					_ = conn.Close()
					return
				}
				hsCtx, cancel := context.WithTimeout(context.Background(), tlsHandshakeTimeout)
				hsErr := conn.(*tls.Conn).HandshakeContext(hsCtx)
				cancel()
				if err := conn.SetDeadline(time.Time{}); err != nil {
					errors.LogWarningInner(context.Background(), err, "failed to clear TLS handshake deadline on accepted connection")
				}
				if hsErr != nil {
					errors.LogWarningInner(context.Background(), hsErr, "failed TLS handshake on accepted connection")
					_ = conn.Close()
					return
				}
			} else if v.realityConfig != nil {
				rustDone := false
				defer maybeLogTCPRealityHandoverMarkers(context.Background())
				nowUnix := time.Now().UnixNano()
				nativePathEligible := useNativeRealityServerFn(v)
				if nativePathEligible && shouldBypassRustDeferredForRemote(conn.RemoteAddr(), nowUnix) {
					tcpRealityMarkerRustPeekBypassActive.Add(1)
					if isLoopbackAddr(conn.RemoteAddr()) {
						tcpRealityMarkerRustPeekBypassLoopbackScopedActive.Add(1)
					}
					nativePathEligible = false
					errors.LogDebug(context.Background(), "[kind=tcp-handover.rust_peek_bypass] skip Rust deferred for ", conn.RemoteAddr())
				}
				if !nativePathEligible {
					tcpRealityMarkerRustPathIneligible.Add(1)
					acceptProxyProtocol := v.config != nil && v.config.AcceptProxyProtocol
					hasMldsa65Seed := v.realityXrayConfig != nil && len(v.realityXrayConfig.Mldsa65Seed) > 0
					deferredPromotionDisabled := tls.DeferredKTLSPromotionDisabled()
					errors.LogDebug(context.Background(),
						"[kind=tcp-handover.rust_path_ineligible] Rust REALITY server path disabled: nativeAvailable=", native.Available(),
						" fullKTLS=", tls.NativeFullKTLSSupported(),
						" hasRealityXrayConfig=", v.realityXrayConfig != nil,
						" deferredPromotionDisabled=", deferredPromotionDisabled,
						" acceptProxyProtocol=", acceptProxyProtocol,
						" hasMldsa65Seed=", hasMldsa65Seed,
					)
				}
				if nativePathEligible {
					tcpRealityMarkerRustAttempt.Add(1)
					fd, fdErr := tls.ExtractFd(conn)
					if fdErr == nil {
						if err := conn.SetDeadline(time.Now().Add(tlsHandshakeTimeout)); err != nil {
							errors.LogWarningInner(context.Background(), err, "failed to set REALITY handshake deadline")
							_ = conn.Close()
							return
						}
						rustStart := time.Now()
						deferredResult, deferredErr := doRustRealityDeferredFn(v, fd)
						tcpRealityMarkerRustDurationNanosTotal.Add(uint64(time.Since(rustStart).Nanoseconds()))
						tcpRealityMarkerRustDurationSamples.Add(1)
						if err := conn.SetDeadline(time.Time{}); err != nil {
							errors.LogWarningInner(context.Background(), err, "failed to clear REALITY handshake deadline")
						}
						if deferredErr == nil {
							deferredConn, wrapErr := tls.NewDeferredRustConn(conn, deferredResult)
							if wrapErr != nil {
								tcpRealityMarkerRustWrapFailed.Add(1)
								errors.LogWarningInner(context.Background(), wrapErr, "[kind=tcp-handover.rust_wrap_failed] Rust REALITY deferred handshake succeeded but wrap failed")
								if deferredResult.Handle != nil {
									native.DeferredFree(deferredResult.Handle)
								}
								_ = conn.Close()
								return
							}
							tcpRealityMarkerRustSuccess.Add(1)
							conn = deferredConn
							rustDone = true
							errors.LogDebug(context.Background(), "Rust REALITY deferred path active: wrapped as *tls.DeferredRustConn (kTLS deferred)")
						} else if stderrors.Is(deferredErr, native.ErrRealityAuthFailed) {
							tcpRealityMarkerRustAuthFallback.Add(1)
							recordRealityFailureOnce()
							errors.LogInfo(context.Background(), "[kind=tcp-handover.rust_auth_fallback] Rust REALITY auth failed, falling back to camouflage")
							errors.LogDebug(context.Background(), "REALITY auth detail: ", deferredErr)
							// Fall through — MSG_PEEK left socket data unconsumed,
							// Go reality.Server() will read it and handle spider crawl.
						} else if isDeferredRealityPeekTimeout(deferredErr) {
							tcpRealityMarkerRustPeekTimeoutFallback.Add(1)
							tcpRealityMarkerRustPeekBypassSet.Add(1)
							if bypassWindow, ok := setRustPeekBypassForRemote(conn.RemoteAddr(), time.Now().UnixNano()); ok && bypassWindow <= rustPeekBypassLoopbackWindow {
								tcpRealityMarkerRustPeekBypassLoopback.Add(1)
								tcpRealityMarkerRustPeekBypassLoopbackScopedSet.Add(1)
							}
							// Timeout happened before auth/handshake consumed bytes.
							// Try Go REALITY path for better compatibility on slow paths.
							errors.LogDebugInner(context.Background(), deferredErr, "[kind=tcp-handover.rust_peek_timeout] Rust REALITY deferred peek timed out, falling back to Go REALITY")
						} else {
							tcpRealityMarkerRustHandshakeFailed.Add(1)
							errors.LogWarningInner(context.Background(), deferredErr, "[kind=tcp-handover.rust_deferred_failed] Rust REALITY deferred handshake failed")
							_ = conn.Close()
							return
						}
					} else {
						tcpRealityMarkerRustFDExtractFailed.Add(1)
						errors.LogDebugInner(context.Background(), fdErr, "[kind=tcp-handover.rust_fd_extract_failed] Rust REALITY server path skipped: failed to extract fd")
					}
				}
				if !rustDone {
					tcpRealityMarkerGoFallbackAttempt.Add(1)
					// Keep fallback behavior aligned with upstream Go REALITY
					// listener: do not wrap reality.Server() with an external
					// deadline, so camouflage flow/timing remains unchanged.
					goFallbackStart := time.Now()
					realityConn, serveErr := realityServerFn(conn, v.realityConfig)
					tcpRealityMarkerGoFallbackNanosTotal.Add(uint64(time.Since(goFallbackStart).Nanoseconds()))
					tcpRealityMarkerGoFallbackSamples.Add(1)
					if serveErr != nil {
						tcpRealityMarkerGoFallbackFailed.Add(1)
						recordRealityFailureOnce()
						errors.LogInfo(context.Background(), "[kind=tcp-handover.go_fallback_failed] ", serveErr.Error())
						_ = conn.Close()
						return
					}
					tcpRealityMarkerGoFallbackSuccess.Add(1)
					conn = realityConn
				}
			}

			// Release handshake semaphore BEFORE session begins.
			// The semaphore gates concurrent handshake work (TLS, Rust REALITY
			// deferred path, and Go REALITY fallback), not session lifetime.
			// The worker semaphore gates total sessions.
			releaseHandshake()

			if v.authConfig != nil {
				conn = v.authConfig.Server(conn)
			}
			v.addConn(stat.Connection(conn))
		}(conn)
	}
}

func (v *Listener) doRustRealityDeferred(fd int) (*native.DeferredResult, error) {
	cfg := native.RealityConfigNew(false)
	if cfg == nil {
		return nil, errors.New("failed to create native REALITY server config")
	}
	defer native.RealityConfigFree(cfg)

	rc := v.realityXrayConfig
	native.RealityConfigSetPrivateKey(cfg, rc.PrivateKey)

	// Use the same SNI allowlist policy as Go REALITY.
	if serverNames := encodeRealityServerNames(rc.ServerNames); len(serverNames) > 0 {
		native.RealityConfigSetServerNames(cfg, serverNames)
	}

	// Set short IDs (each may contain null bytes, so add individually)
	for _, sid := range rc.ShortIds {
		if len(sid) > 0 {
			native.RealityConfigAddShortId(cfg, sid)
		}
	}

	// Set max time diff (protobuf field is in milliseconds)
	native.RealityConfigSetMaxTimeDiff(cfg, rc.MaxTimeDiff)

	// Apply min/max bounds even when only one side is configured.
	if hasVersionRange, minVer, maxVer := realityVersionRange(rc.MinClientVer, rc.MaxClientVer); hasVersionRange {
		native.RealityConfigSetVersionRange(cfg,
			minVer[0], minVer[1], minVer[2],
			maxVer[0], maxVer[1], maxVer[2])
	}

	return native.RealityServerDeferred(fd, cfg, tlsHandshakeTimeout)
}

func encodeRealityServerNames(serverNames []string) []byte {
	totalLen := 0
	for _, name := range serverNames {
		if len(name) > 0 {
			totalLen += len(name) + 1 // null separator expected by native parser
		}
	}
	if totalLen == 0 {
		return nil
	}

	encoded := make([]byte, 0, totalLen)
	for _, name := range serverNames {
		if len(name) == 0 {
			continue
		}
		encoded = append(encoded, name...)
		encoded = append(encoded, 0)
	}
	return encoded
}

func realityVersionRange(minClientVer, maxClientVer []byte) (bool, [3]uint8, [3]uint8) {
	minVer := [3]uint8{}
	maxVer := [3]uint8{255, 255, 255}
	hasVersionRange := false

	if len(minClientVer) > 0 {
		hasVersionRange = true
		copy(minVer[:], minClientVer)
	}
	if len(maxClientVer) > 0 {
		hasVersionRange = true
		copy(maxVer[:], maxClientVer)
	}

	return hasVersionRange, minVer, maxVer
}

func isDeferredRealityPeekTimeout(err error) bool {
	return native.IsRealityDeferredPeekTimeout(err)
}

// Addr implements internet.Listener.Addr.
func (v *Listener) Addr() net.Addr {
	return v.listener.Addr()
}

// Close implements internet.Listener.Close.
func (v *Listener) Close() error {
	return v.listener.Close()
}

func init() {
	common.Must(internet.RegisterTransportListener(protocolName, ListenTCP))
}
