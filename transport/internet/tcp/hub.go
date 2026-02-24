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

var (
	realityBlacklist     *ebpf.BlacklistManager
	realityBlacklistOnce sync.Once

	getRealityBlacklistFn = getRealityBlacklist
	realityServerFn       = reality.Server
	doRustRealityServerFn = func(v *Listener, fd int) (*native.TlsResult, error) {
		return v.doRustRealityServer(fd)
	}
	useNativeRealityServerFn = func(v *Listener) bool {
		return native.Available() &&
			tls.NativeFullKTLSSupported() &&
			v.realityXrayConfig != nil &&
			len(v.realityXrayConfig.Mldsa65Seed) == 0
	}
)

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
				if native.Available() && v.tlsXrayConfig != nil && tls.NativeFullKTLSSupportedForTLSConfig(v.tlsXrayConfig) {
					if err := conn.SetDeadline(time.Now().Add(tlsHandshakeTimeout)); err != nil {
						errors.LogWarningInner(context.Background(), err, "failed to set Rust TLS handshake deadline on accepted connection")
						_ = conn.Close()
						return
					}
					rustConn, tlsErr := tls.RustServer(conn, v.tlsXrayConfig)
					if err := conn.SetDeadline(time.Time{}); err != nil {
						errors.LogWarningInner(context.Background(), err, "failed to clear Rust TLS handshake deadline on accepted connection")
					}
					if tlsErr != nil {
						errors.LogWarningInner(context.Background(), tlsErr, "failed Rust TLS handshake on accepted connection")
						_ = conn.Close()
						return
					}
					conn = rustConn
				} else {
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
					hsErr := conn.(*tls.Conn).HandshakeAndEnableKTLS(hsCtx)
					cancel()
					if err := conn.SetDeadline(time.Time{}); err != nil {
						errors.LogWarningInner(context.Background(), err, "failed to clear TLS handshake deadline on accepted connection")
					}
					if hsErr != nil {
						errors.LogWarningInner(context.Background(), hsErr, "failed TLS handshake on accepted connection")
						_ = conn.Close()
						return
					}
				}
			} else if v.realityConfig != nil {
				rustDone := false
				nativePathEligible := useNativeRealityServerFn(v)
				if !nativePathEligible {
					hasMldsa65Seed := v.realityXrayConfig != nil && len(v.realityXrayConfig.Mldsa65Seed) > 0
					errors.LogDebug(context.Background(),
						"Rust REALITY server path disabled: nativeAvailable=", native.Available(),
						" fullKTLS=", tls.NativeFullKTLSSupported(),
						" hasRealityXrayConfig=", v.realityXrayConfig != nil,
						" hasMldsa65Seed=", hasMldsa65Seed,
					)
				}
				if nativePathEligible {
					fd, fdErr := tls.ExtractFd(conn)
					if fdErr == nil {
						if err := conn.SetDeadline(time.Now().Add(tlsHandshakeTimeout)); err != nil {
							errors.LogWarningInner(context.Background(), err, "failed to set REALITY handshake deadline")
							_ = conn.Close()
							return
						}
						rustResult, rustErr := doRustRealityServerFn(v, fd)
						if err := conn.SetDeadline(time.Time{}); err != nil {
							errors.LogWarningInner(context.Background(), err, "failed to clear REALITY handshake deadline")
						}
						if rustErr == nil && rustResult.KtlsTx && rustResult.KtlsRx {
							rustConn, wrapErr := tls.NewRustConnChecked(conn, rustResult, "")
							if wrapErr != nil {
								errors.LogWarningInner(context.Background(), wrapErr, "Rust REALITY handshake succeeded but native kTLS session init failed")
								_ = conn.Close()
								return
							}
							conn = rustConn
							rustDone = true
							errors.LogDebug(context.Background(), "Rust REALITY server path active: wrapped as *tls.RustConn")
						} else {
							if rustResult != nil && rustResult.StateHandle != nil {
								native.TlsStateFree(rustResult.StateHandle)
							}
							if rustErr == nil {
								// Handshake succeeded but kTLS incomplete — socket data
								// already consumed by rustls, Go fallback won't work.
								errors.LogWarning(context.Background(), "REALITY: Rust handshake OK but kTLS incomplete, closing")
								_ = conn.Close()
								return
							}
							if stderrors.Is(rustErr, native.ErrRealityAuthFailed) {
								recordRealityFailureOnce()
								errors.LogInfo(context.Background(), "Rust REALITY auth failed, falling back to camouflage")
								// Fall through — MSG_PEEK left socket data unconsumed,
								// Go reality.Server() will read it and handle spider crawl.
							} else {
								errors.LogWarningInner(context.Background(), rustErr, "Rust REALITY server handshake failed")
								_ = conn.Close()
								return
							}
						}
					} else {
						errors.LogDebugInner(context.Background(), fdErr, "Rust REALITY server path skipped: failed to extract fd")
					}
				}
				if !rustDone {
					if err := conn.SetDeadline(time.Now().Add(tlsHandshakeTimeout)); err != nil {
						errors.LogWarningInner(context.Background(), err, "failed to set REALITY fallback handshake deadline")
						_ = conn.Close()
						return
					}
					realityConn, serveErr := realityServerFn(conn, v.realityConfig)
					if err := conn.SetDeadline(time.Time{}); err != nil {
						errors.LogWarningInner(context.Background(), err, "failed to clear REALITY fallback handshake deadline")
					}
					if serveErr != nil {
						recordRealityFailureOnce()
						errors.LogInfo(context.Background(), serveErr.Error())
						_ = conn.Close()
						return
					}
					conn = realityConn
				}
			}

			// Release handshake semaphore BEFORE session begins.
			// The semaphore now gates concurrent TLS handshakes (CPU-intensive),
			// not session lifetime. The worker semaphore gates total sessions.
			releaseHandshake()

			if v.authConfig != nil {
				conn = v.authConfig.Server(conn)
			}
			v.addConn(stat.Connection(conn))
		}(conn)
	}
}

func (v *Listener) doRustRealityServer(fd int) (*native.TlsResult, error) {
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

	return native.RealityServerHandshake(fd, cfg)
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
