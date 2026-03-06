package splithttp

import (
	"bytes"
	"context"
	gotls "crypto/tls"
	"encoding/base64"
	stderrors "errors"
	"fmt"
	"io"
	stdnet "net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	goreality "github.com/xtls/reality"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/native"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/pipeline"
	"github.com/xtls/xray-core/common/platform"
	http_proto "github.com/xtls/xray-core/common/protocol/http"
	"github.com/xtls/xray-core/common/signal/done"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/ebpf"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

func applyXHTTPCopyGate(decision *pipeline.DecisionSnapshot) {
	_, gate, gateReason, copyPath, _ := pipeline.EvaluateCopyGate(pipeline.CopyGateInput{
		InboundGate:   pipeline.CopyGateNotApplicable,
		InboundReason: pipeline.CopyGateReasonTransportNonRawSplitConn,
	})
	decision.CopyGateState = gate
	decision.CopyGateReason = gateReason
	if copyPath != pipeline.CopyPathUnknown {
		decision.CopyPath = copyPath
	}
}

var (
	xhttpCapsVal       atomic.Value // pipeline.CapabilitySummary
	xhttpCapsEpoch     atomic.Uint64
	xhttpCapsProbeSeen atomic.Uint64

	deferredKTLSPromotionDisabledFn = tls.DeferredKTLSPromotionDisabledFor
)

type requestHandler struct {
	config         *Config
	host           string
	path           string
	ln             *Listener
	sessionMu      *sync.Mutex
	sessions       sync.Map
	sessionCount   atomic.Int64
	maxSessions    int64
	localAddr      net.Addr
	socketSettings *internet.SocketConfig
}

type httpSession struct {
	uploadQueue *uploadQueue
	// for as long as the GET request is not opened by the client, this will be
	// open ("undone"), and the session may be expired within a certain TTL.
	// after the client connects, this becomes "done" and the session lives as
	// long as the GET request.
	isFullyConnected *done.Instance
	reaperTimer      *time.Timer
	released         atomic.Bool
}

func (h *requestHandler) releaseSession(sessionId string, session *httpSession) {
	if !session.released.CompareAndSwap(false, true) {
		return
	}

	h.sessions.CompareAndDelete(sessionId, session)
	h.sessionCount.Add(-1)
	_ = session.uploadQueue.Close()
}

func (h *requestHandler) upsertSession(sessionId string) *httpSession {
	// fast path
	currentSessionAny, ok := h.sessions.Load(sessionId)
	if ok {
		return currentSessionAny.(*httpSession)
	}

	// slow path
	h.sessionMu.Lock()
	defer h.sessionMu.Unlock()

	currentSessionAny, ok = h.sessions.Load(sessionId)
	if ok {
		return currentSessionAny.(*httpSession)
	}

	maxSessions := h.maxSessions
	if maxSessions <= 0 {
		maxSessions = getMaxConcurrentSessions()
	}
	if h.sessionCount.Load() >= maxSessions {
		return nil
	}

	s := &httpSession{
		uploadQueue:      NewUploadQueue(h.ln.config.GetNormalizedScMaxBufferedPosts()),
		isFullyConnected: done.New(),
	}

	h.sessions.Store(sessionId, s)
	h.sessionCount.Add(1)

	s.reaperTimer = time.AfterFunc(30*time.Second, func() {
		if !s.isFullyConnected.Done() {
			h.releaseSession(sessionId, s)
		}
	})

	return s
}

func (h *requestHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if len(h.host) > 0 && !internet.IsValidHTTPHost(request.Host, h.host) {
		errors.LogInfo(context.Background(), "failed to validate host, request:", request.Host, ", config:", h.host)
		writer.WriteHeader(http.StatusNotFound)
		return
	}

	if !strings.HasPrefix(request.URL.Path, h.path) {
		errors.LogInfo(context.Background(), "failed to validate path, request:", request.URL.Path, ", config:", h.path)
		writer.WriteHeader(http.StatusNotFound)
		return
	}

	h.config.WriteResponseHeader(writer)
	length := int(h.config.GetNormalizedXPaddingBytes().rand())
	config := XPaddingConfig{Length: length}

	if h.config.XPaddingObfsMode {
		config.Placement = XPaddingPlacement{
			Placement: h.config.XPaddingPlacement,
			Key:       h.config.XPaddingKey,
			Header:    h.config.XPaddingHeader,
		}
		config.Method = PaddingMethod(h.config.XPaddingMethod)
	} else {
		config.Placement = XPaddingPlacement{
			Placement: PlacementHeader,
			Header:    "X-Padding",
		}
	}

	h.config.ApplyXPaddingToHeader(writer.Header(), config)

	/*
		clientVer := []int{0, 0, 0}
		x_version := strings.Split(request.URL.Query().Get("x_version"), ".")
		for j := 0; j < 3 && len(x_version) > j; j++ {
			clientVer[j], _ = strconv.Atoi(x_version[j])
		}
	*/

	validRange := h.config.GetNormalizedXPaddingBytes()
	paddingValue, paddingPlacement := h.config.ExtractXPaddingFromRequest(request, h.config.XPaddingObfsMode)

	if !h.config.IsPaddingValid(paddingValue, validRange.From, validRange.To, PaddingMethod(h.config.XPaddingMethod)) {
		errors.LogInfo(context.Background(), "invalid padding ("+paddingPlacement+") length:", int32(len(paddingValue)))
		writer.WriteHeader(http.StatusBadRequest)
		return
	}

	sessionId, seqStr := h.config.ExtractMetaFromRequest(request, h.path)

	if sessionId == "" && h.config.Mode != "" && h.config.Mode != "auto" && h.config.Mode != "stream-one" && h.config.Mode != "stream-up" {
		errors.LogInfo(context.Background(), "stream-one mode is not allowed")
		writer.WriteHeader(http.StatusBadRequest)
		return
	}

	var forwardedAddrs []net.Address
	if h.socketSettings != nil && len(h.socketSettings.TrustedXForwardedFor) > 0 {
		for _, key := range h.socketSettings.TrustedXForwardedFor {
			if len(request.Header.Values(key)) > 0 {
				forwardedAddrs = http_proto.ParseXForwardedFor(request.Header)
				break
			}
		}
	} else {
		forwardedAddrs = http_proto.ParseXForwardedFor(request.Header)
	}
	var remoteAddr net.Addr
	var err error
	remoteAddr, err = net.ResolveTCPAddr("tcp", request.RemoteAddr)
	if err != nil {
		remoteAddr = &net.TCPAddr{
			IP:   []byte{0, 0, 0, 0},
			Port: 0,
		}
	}
	if request.ProtoMajor == 3 {
		remoteAddr = &net.UDPAddr{
			IP:   remoteAddr.(*net.TCPAddr).IP,
			Port: remoteAddr.(*net.TCPAddr).Port,
		}
	}
	if len(forwardedAddrs) > 0 && forwardedAddrs[0].Family().IsIP() {
		remoteAddr = &net.TCPAddr{
			IP:   forwardedAddrs[0].IP(),
			Port: 0,
		}
	}

	var currentSession *httpSession
	if sessionId != "" {
		currentSession = h.upsertSession(sessionId)
		if currentSession == nil {
			maxSessions := h.maxSessions
			if maxSessions <= 0 {
				maxSessions = getMaxConcurrentSessions()
			}
			errors.LogWarning(context.Background(), "XHTTP session limit reached (", maxSessions, ")")
			writer.WriteHeader(http.StatusServiceUnavailable)
			return
		}
	}
	scMaxEachPostBytes := int(h.ln.config.GetNormalizedScMaxEachPostBytes().To)
	uplinkHTTPMethod := h.config.GetNormalizedUplinkHTTPMethod()
	isUplinkRequest := false

	if uplinkHTTPMethod != "GET" && request.Method == uplinkHTTPMethod {
		isUplinkRequest = true
	}

	uplinkDataPlacement := h.config.GetNormalizedUplinkDataPlacement()
	uplinkDataKey := h.config.UplinkDataKey

	switch uplinkDataPlacement {
	case PlacementHeader:
		if request.Header.Get(uplinkDataKey+"-Upstream") == "1" {
			isUplinkRequest = true
		}
	case PlacementCookie:
		if c, _ := request.Cookie(uplinkDataKey + "_upstream"); c != nil && c.Value == "1" {
			isUplinkRequest = true
		}
	}

	if isUplinkRequest && sessionId != "" { // stream-up, packet-up
		if seqStr == "" {
			if h.config.Mode != "" && h.config.Mode != "auto" && h.config.Mode != "stream-up" {
				errors.LogInfo(context.Background(), "stream-up mode is not allowed")
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			httpSC := &httpServerConn{
				Instance:       done.New(),
				Reader:         request.Body,
				ResponseWriter: writer,
			}
			err = currentSession.uploadQueue.Push(Packet{
				Reader: httpSC,
			})
			if err != nil {
				errors.LogInfoInner(context.Background(), err, "failed to upload (PushReader)")
				writer.WriteHeader(http.StatusConflict)
			} else {
				writer.Header().Set("X-Accel-Buffering", "no")
				writer.Header().Set("Cache-Control", "no-store")
				writer.WriteHeader(http.StatusOK)
				scStreamUpServerSecs := h.config.GetNormalizedScStreamUpServerSecs()
				referrer := request.Header.Get("Referer")
				if referrer != "" && scStreamUpServerSecs.To > 0 {
					go func() {
						defer func() {
							if r := recover(); r != nil {
								errors.LogError(context.Background(), "panic in XHTTP SSE padding goroutine: ", r)
							}
						}()
						for {
							_, err := httpSC.Write(bytes.Repeat([]byte{'X'}, int(h.config.GetNormalizedXPaddingBytes().rand())))
							if err != nil {
								break
							}
							time.Sleep(time.Duration(scStreamUpServerSecs.rand()) * time.Second)
						}
					}()
				}
				select {
				case <-request.Context().Done():
				case <-httpSC.Wait():
				}
			}
			httpSC.Close()
			return
		}

		if h.config.Mode != "" && h.config.Mode != "auto" && h.config.Mode != "packet-up" {
			errors.LogInfo(context.Background(), "packet-up mode is not allowed")
			writer.WriteHeader(http.StatusBadRequest)
			return
		}

		var payload []byte

		if uplinkDataPlacement != PlacementBody {
			var encodedStr string
			switch uplinkDataPlacement {
			case PlacementHeader:
				dataLenStr := request.Header.Get(uplinkDataKey + "-Length")

				if dataLenStr != "" {
					dataLen, _ := strconv.Atoi(dataLenStr)
					var chunks []string
					i := 0

					for {
						chunk := request.Header.Get(fmt.Sprintf("%s-%d", uplinkDataKey, i))
						if chunk == "" {
							break
						}
						chunks = append(chunks, chunk)
						i++
					}

					encodedStr = strings.Join(chunks, "")
					if len(encodedStr) != dataLen {
						encodedStr = ""
					}
				}
			case PlacementCookie:
				var chunks []string
				i := 0

				for {
					cookieName := fmt.Sprintf("%s_%d", uplinkDataKey, i)
					if c, _ := request.Cookie(cookieName); c != nil {
						chunks = append(chunks, c.Value)
						i++
					} else {
						break
					}
				}

				if len(chunks) > 0 {
					encodedStr = strings.Join(chunks, "")
				}
			}

			if encodedStr != "" {
				payload, err = base64.RawURLEncoding.DecodeString(encodedStr)
			} else {
				errors.LogInfoInner(context.Background(), err, "failed to extract data from key "+uplinkDataKey+" placed in "+uplinkDataPlacement)
				writer.WriteHeader(http.StatusInternalServerError)
				return
			}
		} else {
			payload, err = io.ReadAll(io.LimitReader(request.Body, int64(scMaxEachPostBytes)+1))
		}

		if len(payload) > scMaxEachPostBytes {
			errors.LogInfo(context.Background(), "Too large upload. scMaxEachPostBytes is set to ", scMaxEachPostBytes, "but request size exceed it. Adjust scMaxEachPostBytes on the server to be at least as large as client.")
			writer.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}

		if err != nil {
			errors.LogInfoInner(context.Background(), err, "failed to upload (ReadAll)")
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}

		seq, err := strconv.ParseUint(seqStr, 10, 64)
		if err != nil {
			errors.LogInfoInner(context.Background(), err, "failed to upload (ParseUint)")
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}

		err = currentSession.uploadQueue.Push(Packet{
			Payload: payload,
			Seq:     seq,
		})

		if err != nil {
			errors.LogInfoInner(context.Background(), err, "failed to upload (PushPayload)")
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}

		writer.WriteHeader(http.StatusOK)
	} else if request.Method == "GET" || sessionId == "" { // stream-down, stream-one
		if sessionId != "" {
			// after GET is done, the connection is finished. disable automatic
			// session reaping, and handle it in defer
			currentSession.isFullyConnected.Close()
			h.sessionMu.Lock()
			reaper := currentSession.reaperTimer
			h.sessionMu.Unlock()
			if reaper != nil {
				reaper.Stop()
			}
			defer func() {
				h.releaseSession(sessionId, currentSession)
			}()
		}

		// magic header instructs nginx + apache to not buffer response body
		writer.Header().Set("X-Accel-Buffering", "no")
		// A web-compliant header telling all middleboxes to disable caching.
		// Should be able to prevent overloading the cache, or stop CDNs from
		// teeing the response stream into their cache, causing slowdowns.
		writer.Header().Set("Cache-Control", "no-store")

		if !h.config.NoSSEHeader {
			// magic header to make the HTTP middle box consider this as SSE to disable buffer
			writer.Header().Set("Content-Type", "text/event-stream")
		}

		writer.WriteHeader(http.StatusOK)
		if f, ok := writer.(http.Flusher); ok {
			f.Flush()
		}

		httpSC := &httpServerConn{
			Instance:       done.New(),
			Reader:         request.Body,
			ResponseWriter: writer,
		}
		conn := splitConn{
			writer:     httpSC,
			reader:     httpSC,
			remoteAddr: remoteAddr,
			localAddr:  h.localAddr,
		}
		if sessionId != "" { // if not stream-one
			conn.reader = currentSession.uploadQueue
		}

		h.ln.addConn(stat.Connection(&conn))

		// "A ResponseWriter may not be used after [Handler.ServeHTTP] has returned."
		select {
		case <-request.Context().Done():
		case <-httpSC.Wait():
		}

		conn.Close()
	} else {
		errors.LogInfo(context.Background(), "unsupported method: ", request.Method)
		writer.WriteHeader(http.StatusMethodNotAllowed)
	}
}

type httpServerConn struct {
	sync.Mutex
	*done.Instance
	io.Reader // no need to Close request.Body
	http.ResponseWriter
}

func (c *httpServerConn) Write(b []byte) (int, error) {
	c.Lock()
	defer c.Unlock()
	if c.Done() {
		return 0, io.ErrClosedPipe
	}
	n, err := c.ResponseWriter.Write(b)
	if err == nil {
		if f, ok := c.ResponseWriter.(http.Flusher); ok {
			f.Flush()
		}
	}
	return n, err
}

func (c *httpServerConn) Close() error {
	c.Lock()
	defer c.Unlock()
	return c.Instance.Close()
}

func (c *httpServerConn) SetDeadline(t time.Time) error {
	return stderrors.Join(c.SetReadDeadline(t), c.SetWriteDeadline(t))
}

func (c *httpServerConn) SetReadDeadline(t time.Time) error {
	return setSplitReadDeadline(c.Reader, t)
}

func (c *httpServerConn) SetWriteDeadline(t time.Time) error {
	return http.NewResponseController(c.ResponseWriter).SetWriteDeadline(t)
}

// kTLSListener wraps a net.Listener to perform Rust-based TLS handshakes
// with mandatory kTLS offload on Accept. The returned connections have TLS
// handled transparently by the kernel; http.Server sees them as plaintext
// (via KTLSPlaintextConn) and uses h2c detection for HTTP/2.
type kTLSListener struct {
	inner            net.Listener
	tlsConfig        *tls.Config
	timeout          time.Duration
	consecutiveFails int // backoff counter for systematic handshake failures
}

var xhttpListenerSleepFn = time.Sleep

func xhttpListenerApplyBackoff(consecutiveFails int) {
	// Exponential backoff under systematic failure to prevent CPU saturation
	// from misconfiguration or adversarial handshake bombing.
	if consecutiveFails <= 10 {
		return
	}
	backoff := time.Duration(consecutiveFails-10) * 100 * time.Millisecond
	if backoff > 5*time.Second {
		backoff = 5 * time.Second
	}
	xhttpListenerSleepFn(backoff)
}

func xhttpKTLSListenerEligible(port net.Port, socketSettings *internet.SocketConfig, nativeAvailable, fullKTLSSupported bool) bool {
	if port == 0 || !nativeAvailable || !fullKTLSSupported {
		return false
	}
	if socketSettings != nil && socketSettings.AcceptProxyProtocol {
		return false
	}
	return true
}

func (l *kTLSListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.inner.Accept()
		if err != nil {
			return nil, err // real listener error (closed, shutdown) — propagate
		}
		rc, err := tls.RustServerWithTimeout(conn, l.tlsConfig, l.timeout)
		if err != nil {
			// TLS handshake failure is per-connection (scanner, bot, timeout).
			// Log and accept the next connection — do NOT return the error,
			// because http.Server.Serve exits on non-temporary Accept errors.
			conn.Close()
			l.consecutiveFails++
			errors.LogDebug(context.Background(), "XHTTP kTLS handshake failed (consecutive=", l.consecutiveFails, "): ", err)
			xhttpListenerApplyBackoff(l.consecutiveFails)
			continue
		}
		l.consecutiveFails = 0
		return tls.NewKTLSPlaintextConn(rc), nil
	}
}

func (l *kTLSListener) Close() error   { return l.inner.Close() }
func (l *kTLSListener) Addr() net.Addr { return l.inner.Addr() }

// kREALITYListener wraps a net.Listener to perform Rust REALITY handshakes
// with immediate deferred kTLS promotion for XHTTP. On Rust auth failure
// (or safe peek-timeout cases), it falls back to Go REALITY for camouflage.
type kREALITYListener struct {
	inner             net.Listener
	realityConfig     *goreality.Config
	realityXrayConfig *reality.Config
	timeout           time.Duration
	handshakeSem      chan struct{}
	conns             chan net.Conn
	done              chan struct{}
	closeOnce         sync.Once
	mu                sync.Mutex
	err               error
}

const xhttpMaxConcurrentRealityHandshakes = 4096
const xhttpRealityAcceptRetryDelay = 100 * time.Millisecond
const xhttpRealityMarkerLogInterval = 30 * time.Second

var (
	xhttpRealityMarkerLastLogUnix atomic.Int64

	xhttpRealityMarkerRustAttempt             atomic.Uint64
	xhttpRealityMarkerRustSuccess             atomic.Uint64
	xhttpRealityMarkerRustFDExtractFailed     atomic.Uint64
	xhttpRealityMarkerRustAuthFallback        atomic.Uint64
	xhttpRealityMarkerRustPeekTimeoutFallback atomic.Uint64
	xhttpRealityMarkerRustWrapFailed          atomic.Uint64
	xhttpRealityMarkerRustHandshakeFailed     atomic.Uint64
	xhttpRealityMarkerRustDurationNanosTotal  atomic.Uint64
	xhttpRealityMarkerRustDurationSamples     atomic.Uint64

	xhttpRealityMarkerKTLSPromoteAttempt atomic.Uint64
	xhttpRealityMarkerKTLSPromoteSuccess atomic.Uint64
	xhttpRealityMarkerKTLSPromoteFailed  atomic.Uint64

	xhttpRealityMarkerGoFallbackAttempt    atomic.Uint64
	xhttpRealityMarkerGoFallbackSuccess    atomic.Uint64
	xhttpRealityMarkerGoFallbackFailed     atomic.Uint64
	xhttpRealityMarkerGoFallbackNanosTotal atomic.Uint64
	xhttpRealityMarkerGoFallbackSamples    atomic.Uint64
	xhttpDecisionRustKTLS                  atomic.Uint64
	xhttpDecisionRustUserspace             atomic.Uint64
	xhttpDecisionGoFallback                atomic.Uint64
	xhttpDecisionDrop                      atomic.Uint64

	xhttpRealityMarkerLastRustAttempt             atomic.Uint64
	xhttpRealityMarkerLastRustSuccess             atomic.Uint64
	xhttpRealityMarkerLastRustFDExtractFailed     atomic.Uint64
	xhttpRealityMarkerLastRustAuthFallback        atomic.Uint64
	xhttpRealityMarkerLastRustPeekTimeoutFallback atomic.Uint64
	xhttpRealityMarkerLastRustWrapFailed          atomic.Uint64
	xhttpRealityMarkerLastRustHandshakeFailed     atomic.Uint64
	xhttpRealityMarkerLastRustDurationNanosTotal  atomic.Uint64
	xhttpRealityMarkerLastRustDurationSamples     atomic.Uint64
	xhttpRealityMarkerLastKTLSPromoteAttempt      atomic.Uint64
	xhttpRealityMarkerLastKTLSPromoteSuccess      atomic.Uint64
	xhttpRealityMarkerLastKTLSPromoteFailed       atomic.Uint64
	xhttpRealityMarkerLastGoFallbackAttempt       atomic.Uint64
	xhttpRealityMarkerLastGoFallbackSuccess       atomic.Uint64
	xhttpRealityMarkerLastGoFallbackFailed        atomic.Uint64
	xhttpRealityMarkerLastGoFallbackNanosTotal    atomic.Uint64
	xhttpRealityMarkerLastGoFallbackSamples       atomic.Uint64
	xhttpDecisionLastRustKTLS                     atomic.Uint64
	xhttpDecisionLastRustUserspace                atomic.Uint64
	xhttpDecisionLastGoFallback                   atomic.Uint64
	xhttpDecisionLastDrop                         atomic.Uint64
	xhttpFallbackHandleConsumed                   atomic.Uint64
	xhttpFallbackHandleAlive                      atomic.Uint64
	xhttpInvalidateHook                           atomic.Value // func()
)

func xhttpTelemetryV2Enabled() bool {
	return platform.NewEnvFlag("xray.pipeline.telemetry.v2").GetValue(func() string { return "" }) != "off"
}

func xhttpCapabilitiesSummary() pipeline.CapabilitySummary {
	probeEpoch := tls.KTLSProbeRefreshEpoch()
	if v := xhttpCapsVal.Load(); v != nil {
		s := v.(pipeline.CapabilitySummary)
		if (s.KTLSSupported || s.SockmapSupported || s.SpliceSupported) &&
			xhttpCapsProbeSeen.Load() == probeEpoch {
			return s
		}
	}
	caps := xhttpComposeCapabilitiesSummary(
		native.CapabilitiesSummary(),
		ebpf.GetCapabilities().SockmapSupported,
		tls.NativeFullKTLSSupported(),
	)
	xhttpCapsVal.Store(caps)
	xhttpCapsProbeSeen.Store(probeEpoch)
	return caps
}

func xhttpInvalidateCapabilitiesSummary() {
	xhttpCapsVal.Store(pipeline.CapabilitySummary{})
	xhttpCapsProbeSeen.Store(tls.KTLSProbeRefreshEpoch())
	xhttpCapsEpoch.Add(1)
	if hook, ok := xhttpInvalidateHook.Load().(func()); ok && hook != nil {
		hook()
	}
}

// xhttpCapabilityEpoch returns the current epoch counter (for tests/metrics).
func xhttpCapabilityEpoch() uint64 {
	return xhttpCapsEpoch.Load()
}

func xhttpComposeCapabilitiesSummary(summary pipeline.CapabilitySummary, sockmapSupported, ktlsSupported bool) pipeline.CapabilitySummary {
	if sockmapSupported {
		summary.SockmapSupported = true
	}
	if ktlsSupported {
		summary.KTLSSupported = true
	}
	return summary
}

func logXHTTPDecision(ctx context.Context, path, reason string, caps pipeline.CapabilitySummary, rustNs, fallbackNs int64, ktlsAttempt, ktlsSuccess bool) {
	errors.LogInfo(ctx, "reality markers[kind=xhttp-handover-summary]: ",
		"path=", path,
		" reason=", reason,
		" rust_duration_ns=", rustNs,
		" fallback_duration_ns=", fallbackNs,
		" ktls_attempt=", ktlsAttempt,
		" ktls_success=", ktlsSuccess,
		" ktls_supported=", caps.KTLSSupported,
		" sockmap_supported=", caps.SockmapSupported,
		" splice_supported=", caps.SpliceSupported,
		" fallback_handle_consumed=", xhttpFallbackHandleConsumed.Load(),
		" fallback_handle_alive=", xhttpFallbackHandleAlive.Load(),
	)
}

func logXHTTPSummary(ctx context.Context, snap pipeline.DecisionSnapshot) {
	kind := snap.Kind
	if kind == "" {
		kind = "xhttp"
	}
	errors.LogInfo(ctx, "reality markers[kind=xhttp-pipeline-summary]: ",
		"kind=", kind,
		" path=", string(snap.Path),
		" reason=", snap.Reason,
		" tls_offload_path=", snap.TLSOffloadPath,
		" copy_path=", snap.CopyPath,
		" copy_gate_state=", snap.CopyGateState,
		" copy_gate_reason=", snap.CopyGateReason,
		" splice_bytes=", snap.SpliceBytes,
		" splice_duration_ns=", snap.SpliceDurationNs,
		" userspace_bytes=", snap.UserspaceBytes,
		" userspace_duration_ns=", snap.UserspaceDurationNs,
		" sockmap_success=", snap.SockmapSuccess,
		" ktls_supported=", snap.Caps.KTLSSupported,
		" sockmap_supported=", snap.Caps.SockmapSupported,
		" splice_supported=", snap.Caps.SpliceSupported,
	)
}

func xhttpRecordTerminalDecision(snap pipeline.DecisionSnapshot, err error) {
	if err != nil {
		xhttpDecisionDrop.Add(1)
		return
	}
	if snap.Path == pipeline.PathKTLS {
		xhttpDecisionRustKTLS.Add(1)
		return
	}
	if snap.Reason != pipeline.ReasonFallbackSuccess {
		xhttpDecisionRustUserspace.Add(1)
		return
	}
	xhttpDecisionGoFallback.Add(1)
}

func xhttpKREALITYListenerEligible(
	port net.Port,
	socketSettings *internet.SocketConfig,
	realityConfig *reality.Config,
	nativeAvailable, fullKTLSSupported bool,
	caps pipeline.CapabilitySummary,
) bool {
	if port == 0 || !nativeAvailable || !fullKTLSSupported || realityConfig == nil {
		return false
	}
	if socketSettings != nil && socketSettings.AcceptProxyProtocol {
		return false
	}
	// Go REALITY derives ML-DSA signing key from mldsa65_seed.
	// Keep Go REALITY server path when configured.
	if len(realityConfig.Mldsa65Seed) > 0 {
		return false
	}
	// Require capability cache to say kTLS is supported before enabling acceleration listener.
	if !caps.KTLSSupported {
		return false
	}
	return true
}

func xhttpMarkerSnapshot(total *atomic.Uint64, last *atomic.Uint64) (current uint64, delta uint64) {
	current = total.Load()
	previous := last.Swap(current)
	return current, current - previous
}

func maybeLogXHTTPRealityHandoverMarkers(ctx context.Context) {
	if xhttpTelemetryV2Enabled() {
		return
	}
	now := time.Now().UnixNano()
	last := xhttpRealityMarkerLastLogUnix.Load()
	if last != 0 && now-last < int64(xhttpRealityMarkerLogInterval) {
		return
	}
	if !xhttpRealityMarkerLastLogUnix.CompareAndSwap(last, now) {
		return
	}

	rustAttempt, rustAttemptDelta := xhttpMarkerSnapshot(&xhttpRealityMarkerRustAttempt, &xhttpRealityMarkerLastRustAttempt)
	rustSuccess, rustSuccessDelta := xhttpMarkerSnapshot(&xhttpRealityMarkerRustSuccess, &xhttpRealityMarkerLastRustSuccess)
	rustFDExtractFailed, rustFDExtractFailedDelta := xhttpMarkerSnapshot(&xhttpRealityMarkerRustFDExtractFailed, &xhttpRealityMarkerLastRustFDExtractFailed)
	rustAuthFallback, rustAuthFallbackDelta := xhttpMarkerSnapshot(&xhttpRealityMarkerRustAuthFallback, &xhttpRealityMarkerLastRustAuthFallback)
	rustPeekFallback, rustPeekFallbackDelta := xhttpMarkerSnapshot(&xhttpRealityMarkerRustPeekTimeoutFallback, &xhttpRealityMarkerLastRustPeekTimeoutFallback)
	rustWrapFailed, rustWrapFailedDelta := xhttpMarkerSnapshot(&xhttpRealityMarkerRustWrapFailed, &xhttpRealityMarkerLastRustWrapFailed)
	rustHandshakeFailed, rustHandshakeFailedDelta := xhttpMarkerSnapshot(&xhttpRealityMarkerRustHandshakeFailed, &xhttpRealityMarkerLastRustHandshakeFailed)
	rustNanos, rustNanosDelta := xhttpMarkerSnapshot(&xhttpRealityMarkerRustDurationNanosTotal, &xhttpRealityMarkerLastRustDurationNanosTotal)
	rustSamples, rustSamplesDelta := xhttpMarkerSnapshot(&xhttpRealityMarkerRustDurationSamples, &xhttpRealityMarkerLastRustDurationSamples)

	ktlsAttempt, ktlsAttemptDelta := xhttpMarkerSnapshot(&xhttpRealityMarkerKTLSPromoteAttempt, &xhttpRealityMarkerLastKTLSPromoteAttempt)
	ktlsSuccess, ktlsSuccessDelta := xhttpMarkerSnapshot(&xhttpRealityMarkerKTLSPromoteSuccess, &xhttpRealityMarkerLastKTLSPromoteSuccess)
	ktlsFailed, ktlsFailedDelta := xhttpMarkerSnapshot(&xhttpRealityMarkerKTLSPromoteFailed, &xhttpRealityMarkerLastKTLSPromoteFailed)

	goFallbackAttempt, goFallbackAttemptDelta := xhttpMarkerSnapshot(&xhttpRealityMarkerGoFallbackAttempt, &xhttpRealityMarkerLastGoFallbackAttempt)
	goFallbackSuccess, goFallbackSuccessDelta := xhttpMarkerSnapshot(&xhttpRealityMarkerGoFallbackSuccess, &xhttpRealityMarkerLastGoFallbackSuccess)
	goFallbackFailed, goFallbackFailedDelta := xhttpMarkerSnapshot(&xhttpRealityMarkerGoFallbackFailed, &xhttpRealityMarkerLastGoFallbackFailed)
	goFallbackNanos, goFallbackNanosDelta := xhttpMarkerSnapshot(&xhttpRealityMarkerGoFallbackNanosTotal, &xhttpRealityMarkerLastGoFallbackNanosTotal)
	goFallbackSamples, goFallbackSamplesDelta := xhttpMarkerSnapshot(&xhttpRealityMarkerGoFallbackSamples, &xhttpRealityMarkerLastGoFallbackSamples)
	decisionRustKTLS, decisionRustKTLSDelta := xhttpMarkerSnapshot(&xhttpDecisionRustKTLS, &xhttpDecisionLastRustKTLS)
	decisionRustUserspace, decisionRustUserspaceDelta := xhttpMarkerSnapshot(&xhttpDecisionRustUserspace, &xhttpDecisionLastRustUserspace)
	decisionGoFallback, decisionGoFallbackDelta := xhttpMarkerSnapshot(&xhttpDecisionGoFallback, &xhttpDecisionLastGoFallback)
	decisionDrop, decisionDropDelta := xhttpMarkerSnapshot(&xhttpDecisionDrop, &xhttpDecisionLastDrop)

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

	errors.LogInfo(ctx, "reality markers[kind=xhttp-handover]: ",
		"rust_attempt=", rustAttempt, "(+", rustAttemptDelta, ") ",
		"rust_success=", rustSuccess, "(+", rustSuccessDelta, ") ",
		"rust_fd_extract_failed=", rustFDExtractFailed, "(+", rustFDExtractFailedDelta, ") ",
		"rust_auth_fallback=", rustAuthFallback, "(+", rustAuthFallbackDelta, ") ",
		"rust_peek_timeout_fallback=", rustPeekFallback, "(+", rustPeekFallbackDelta, ") ",
		"rust_wrap_failed=", rustWrapFailed, "(+", rustWrapFailedDelta, ") ",
		"rust_handshake_failed=", rustHandshakeFailed, "(+", rustHandshakeFailedDelta, ") ",
		"rust_duration_ns=", rustNanos, "(+", rustNanosDelta, ") ",
		"rust_samples=", rustSamples, "(+", rustSamplesDelta, ") ",
		"rust_avg_ns=", rustAvgNs, "(+", rustAvgNsDelta, ") ",
		"ktls_promote_attempt=", ktlsAttempt, "(+", ktlsAttemptDelta, ") ",
		"ktls_promote_success=", ktlsSuccess, "(+", ktlsSuccessDelta, ") ",
		"ktls_promote_failed=", ktlsFailed, "(+", ktlsFailedDelta, ") ",
		"go_fallback_attempt=", goFallbackAttempt, "(+", goFallbackAttemptDelta, ") ",
		"go_fallback_success=", goFallbackSuccess, "(+", goFallbackSuccessDelta, ") ",
		"go_fallback_failed=", goFallbackFailed, "(+", goFallbackFailedDelta, ") ",
		"go_fallback_duration_ns=", goFallbackNanos, "(+", goFallbackNanosDelta, ") ",
		"go_fallback_samples=", goFallbackSamples, "(+", goFallbackSamplesDelta, ") ",
		"go_fallback_avg_ns=", goFallbackAvgNs, "(+", goFallbackAvgNsDelta, ") ",
		"decision_rust_ktls=", decisionRustKTLS, "(+", decisionRustKTLSDelta, ") ",
		"decision_rust_userspace=", decisionRustUserspace, "(+", decisionRustUserspaceDelta, ") ",
		"decision_go_fallback=", decisionGoFallback, "(+", decisionGoFallbackDelta, ") ",
		"decision_drop=", decisionDrop, "(+", decisionDropDelta, ")",
	)
}

func newKREALITYListener(inner net.Listener, realityConfig *goreality.Config, realityXrayConfig *reality.Config, timeout time.Duration) *kREALITYListener {
	l := &kREALITYListener{
		inner:             inner,
		realityConfig:     realityConfig,
		realityXrayConfig: realityXrayConfig,
		timeout:           timeout,
		handshakeSem:      make(chan struct{}, xhttpMaxConcurrentRealityHandshakes),
		conns:             make(chan net.Conn),
		done:              make(chan struct{}),
	}
	go l.keepAccepting()
	return l
}

func xhttpIsTemporaryAcceptErr(err error) bool {
	if err == nil {
		return false
	}
	var temporary interface{ Temporary() bool }
	if stderrors.As(err, &temporary) && temporary.Temporary() {
		return true
	}
	var timeout interface{ Timeout() bool }
	return stderrors.As(err, &timeout) && timeout.Timeout()
}

func xhttpIsClosedListenerErr(err error) bool {
	if err == nil {
		return false
	}
	if stderrors.Is(err, io.EOF) || stderrors.Is(err, stdnet.ErrClosed) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "use of closed network connection") ||
		strings.Contains(msg, "listener closed")
}

func (l *kREALITYListener) shutdown(err error) {
	l.closeOnce.Do(func() {
		l.mu.Lock()
		if l.err == nil {
			l.err = err
		}
		l.mu.Unlock()
		close(l.done)
	})
}

func (l *kREALITYListener) keepAccepting() {
	for {
		rawConn, err := l.inner.Accept()
		if err != nil {
			if xhttpIsClosedListenerErr(err) {
				l.shutdown(io.EOF)
				return
			}
			if xhttpIsTemporaryAcceptErr(err) {
				errors.LogWarningInner(context.Background(), err, "XHTTP kREALITY accept temporary error; retrying")
				xhttpListenerSleepFn(xhttpRealityAcceptRetryDelay)
				continue
			}
			l.shutdown(err)
			return
		}
		select {
		case l.handshakeSem <- struct{}{}:
		default:
			errors.LogWarning(context.Background(),
				"XHTTP kREALITY handshake limit reached (",
				xhttpMaxConcurrentRealityHandshakes,
				"), rejecting connection from ",
				rawConn.RemoteAddr(),
			)
			_ = rawConn.Close()
			continue
		}
		go l.handshakeAndEnqueue(rawConn)
	}
}

func (l *kREALITYListener) handshakeAndEnqueue(rawConn net.Conn) {
	conn := rawConn
	defer func() {
		<-l.handshakeSem
		if r := recover(); r != nil {
			errors.LogError(context.Background(), "panic in XHTTP kREALITY handshake worker: ", r)
			_ = conn.Close()
		}
	}()
	conn, err := l.processConn(rawConn)
	if err != nil {
		if err != io.EOF {
			errors.LogDebugInner(context.Background(), err, "XHTTP kREALITY handshake worker dropped connection")
		}
		_ = rawConn.Close()
		return
	}
	select {
	case <-l.done:
		_ = conn.Close()
	case l.conns <- conn:
	}
}

func (l *kREALITYListener) processConn(rawConn net.Conn) (conn net.Conn, err error) {
	caps := xhttpCapabilitiesSummary()
	decision := pipeline.DecisionSnapshot{
		Path:           pipeline.PathUserspace,
		Reason:         pipeline.ReasonDefault,
		Caps:           caps,
		Kind:           "xhttp",
		CopyPath:       pipeline.CopyPathUnknown,
		TLSOffloadPath: pipeline.TLSOffloadUserspace,
		CopyGateState:  pipeline.CopyGateUnset,
		CopyGateReason: pipeline.CopyGateReasonUnspecified,
	}
	applyXHTTPCopyGate(&decision)
	var rustDurationNs int64
	var fallbackDurationNs int64
	var ktlsAttempt bool
	var ktlsSuccess bool
	defer func() {
		xhttpRecordTerminalDecision(decision, err)
		logXHTTPDecision(context.Background(), string(decision.Path), decision.Reason, caps, rustDurationNs, fallbackDurationNs, ktlsAttempt, ktlsSuccess)
		logXHTTPSummary(context.Background(), decision)
	}()

	tryGoFallback := false
	defer maybeLogXHTTPRealityHandoverMarkers(context.Background())

	scope := "xhttp"
	if addr := rawConn.LocalAddr(); addr != nil {
		scope = "xhttp:" + addr.String()
	}

	if deferredKTLSPromotionDisabledFn(scope) {
		// Skip Rust path when global cooldown is active; use Go fallback deterministically.
		tryGoFallback = true
		decision.Reason = pipeline.ReasonKTLSPromotionCooldown
	} else {
		fd, fdErr := tls.ExtractFd(rawConn)
		if fdErr != nil {
			xhttpRealityMarkerRustFDExtractFailed.Add(1)
			errors.LogDebugInner(context.Background(), fdErr, "[kind=xhttp-handover.rust_fd_extract_failed] XHTTP Rust REALITY path skipped: failed to extract fd")
			tryGoFallback = true
			decision.Reason = pipeline.ReasonFDExtractFailed
		} else {
			xhttpRealityMarkerRustAttempt.Add(1)
			if err := rawConn.SetDeadline(time.Now().Add(l.timeout)); err != nil {
				return nil, errors.New("XHTTP Rust REALITY path: failed to set handshake deadline").Base(err)
			}
			rustStart := time.Now()
			deferredResult, deferredErr := l.doRustRealityDeferred(fd)
			rustDurationNs = time.Since(rustStart).Nanoseconds()
			xhttpRealityMarkerRustDurationNanosTotal.Add(uint64(time.Since(rustStart).Nanoseconds()))
			xhttpRealityMarkerRustDurationSamples.Add(1)
			if err := rawConn.SetDeadline(time.Time{}); err != nil {
				errors.LogWarningInner(context.Background(), err, "XHTTP Rust REALITY path: failed to clear handshake deadline")
			}
			if deferredErr == nil {
				deferredConn, wrapErr := tls.NewDeferredRustConn(rawConn, deferredResult)
				if wrapErr != nil {
					xhttpRealityMarkerRustWrapFailed.Add(1)
					errors.LogWarningInner(context.Background(), wrapErr, "[kind=xhttp-handover.rust_wrap_failed] XHTTP Rust REALITY deferred handshake succeeded but wrap failed")
					if deferredResult != nil && deferredResult.Handle != nil {
						native.DeferredFree(deferredResult.Handle)
					}
					decision.Path = pipeline.PathUserspace
					decision.Reason = pipeline.ReasonRustWrapFailedDrop
					return nil, errors.New("XHTTP Rust REALITY deferred handshake succeeded but wrap failed").Base(wrapErr)
				}
				decision = pipeline.DecideVisionPath(pipeline.DecisionInput{
					DeferredTLSActive: false,
					LoopbackPair:      false,
					Caps:              caps,
				})
				decision.Kind = "xhttp"
				applyXHTTPCopyGate(&decision)
				xhttpRealityMarkerKTLSPromoteAttempt.Add(1)
				ktlsAttempt = true
				deferredConn.SetKTLSPromotionScope(scope)
				outcome, promoteErr := deferredConn.EnableKTLSOutcome()
				failAndClose := func(reason string, marker *atomic.Uint64) (net.Conn, error) {
					if marker != nil {
						marker.Add(1)
					}
					xhttpFallbackHandleConsumed.Add(1)
					decision.Path = pipeline.PathUserspace
					decision.Reason = reason
					decision.TLSOffloadPath = pipeline.TLSOffloadUserspace
					decision.CopyPath = pipeline.CopyPathNotApplicable
					_ = deferredConn.Close()
					return nil, errors.New("XHTTP Rust REALITY: kTLS promotion not usable (" + reason + ")")
				}
				fallbackWithDeferred := func(reason string, marker *atomic.Uint64) (net.Conn, error) {
					if marker != nil {
						marker.Add(1)
					}
					decision.Path = pipeline.PathUserspace
					decision.Reason = reason
					decision.TLSOffloadPath = pipeline.TLSOffloadUserspace
					decision.CopyPath = pipeline.CopyPathNotApplicable
					// Promotion status was non-fatal; keep the deferred rustls
					// session alive and continue in userspace TLS.
					if deferredConn.HasDeferredHandle() {
						xhttpFallbackHandleAlive.Add(1)
						xhttpRealityMarkerRustSuccess.Add(1)
						return deferredConn, nil
					}
					xhttpFallbackHandleConsumed.Add(1)
					_ = deferredConn.Close()
					return nil, errors.New("XHTTP Rust REALITY: deferred handle unavailable for userspace fallback (" + reason + ")")
				}
				switch {
				case promoteErr != nil:
					errors.LogWarningInner(context.Background(), promoteErr, "[kind=xhttp-handover.ktls_promote_failed] XHTTP Rust REALITY deferred kTLS promotion failed")
					return failAndClose(pipeline.ReasonKTLSPromoteFailedFallback, &xhttpRealityMarkerKTLSPromoteFailed)
				case outcome.Status == tls.KTLSPromotionCooldown:
					return fallbackWithDeferred(pipeline.ReasonKTLSPromotionCooldown, nil)
				case outcome.Status == tls.KTLSPromotionUnsupported:
					return fallbackWithDeferred(pipeline.ReasonKTLSUnsupported, &xhttpRealityMarkerKTLSPromoteFailed)
				case outcome.Status != tls.KTLSPromotionEnabled:
					return fallbackWithDeferred(pipeline.ReasonKTLSNotEnabled, &xhttpRealityMarkerKTLSPromoteFailed)
				default:
					xhttpRealityMarkerKTLSPromoteSuccess.Add(1)
					ktlsSuccess = true
					xhttpRealityMarkerRustSuccess.Add(1)
					decision.Path = pipeline.PathKTLS
					decision.Reason = pipeline.ReasonKTLSSuccess
					decision.SpliceDurationNs = rustDurationNs
					decision.TLSOffloadPath = pipeline.TLSOffloadKTLS
					decision.CopyPath = pipeline.CopyPathNotApplicable
					return tls.NewKTLSPlaintextConn(deferredConn), nil
				}
			}
			if stderrors.Is(deferredErr, native.ErrRealityAuthFailed) {
				xhttpRealityMarkerRustAuthFallback.Add(1)
				errors.LogInfo(context.Background(), "[kind=xhttp-handover.rust_auth_fallback] XHTTP Rust REALITY auth failed, falling back to Go REALITY camouflage")
				errors.LogDebug(context.Background(), "XHTTP REALITY auth detail: ", deferredErr)
				tryGoFallback = true
				decision.Reason = pipeline.ReasonRustAuthFailed
			} else if xhttpIsDeferredRealityPeekTimeout(deferredErr) {
				xhttpRealityMarkerRustPeekTimeoutFallback.Add(1)
				errors.LogDebugInner(context.Background(), deferredErr, "[kind=xhttp-handover.rust_peek_timeout] XHTTP Rust REALITY deferred peek timed out, falling back to Go REALITY")
				tryGoFallback = true
				decision.Reason = pipeline.ReasonRustPeekTimeout
			} else {
				xhttpRealityMarkerRustHandshakeFailed.Add(1)
				errors.LogWarningInner(context.Background(), deferredErr, "[kind=xhttp-handover.rust_deferred_failed] XHTTP Rust REALITY deferred handshake failed")
				decision.Reason = pipeline.ReasonRustHandshakeFailed
				return nil, errors.New("XHTTP Rust REALITY deferred handshake failed").Base(deferredErr)
			}
		}
	}
	if tryGoFallback {
		// Go fallback keeps userspace TLS; defer zero-copy decisions early.
		decision = pipeline.DecideVisionPath(pipeline.DecisionInput{
			DeferredTLSActive: true,
			LoopbackPair:      false,
			Caps:              caps,
		})
		decision.Kind = "xhttp"
		applyXHTTPCopyGate(&decision)
		xhttpRealityMarkerGoFallbackAttempt.Add(1)
		// Keep fallback behavior aligned with upstream REALITY listener: no extra
		// deadline wrapper around reality.Server(), so camouflage timing/flow
		// matches the main Go path.
		goFallbackStart := time.Now()
		realityConn, fallbackErr := reality.Server(rawConn, l.realityConfig)
		fallbackDurationNs = time.Since(goFallbackStart).Nanoseconds()
		xhttpRealityMarkerGoFallbackNanosTotal.Add(uint64(time.Since(goFallbackStart).Nanoseconds()))
		xhttpRealityMarkerGoFallbackSamples.Add(1)
		if fallbackErr != nil {
			xhttpRealityMarkerGoFallbackFailed.Add(1)
			errors.LogInfo(context.Background(), "[kind=xhttp-handover.go_fallback_failed] ", fallbackErr.Error())
			decision.Path = pipeline.PathUserspace
			decision.Reason = pipeline.ReasonFallbackFailed
			return nil, fallbackErr
		}
		xhttpRealityMarkerGoFallbackSuccess.Add(1)
		decision.Reason = pipeline.ReasonFallbackSuccess
		if decision.Path != pipeline.PathUserspace {
			// Ensure we don’t over-report acceleration on userspace fallback.
			decision.Path = pipeline.PathUserspace
		}
		return realityConn, nil
	}

	decision.Path = pipeline.PathUserspace
	if decision.Reason == pipeline.ReasonDefault {
		decision.Reason = pipeline.ReasonUnexpectedDrop
	}
	return nil, io.EOF
}

func (l *kREALITYListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err != nil {
		return nil, l.err
	}
	return nil, io.EOF
}

func (l *kREALITYListener) Close() error {
	err := l.inner.Close()
	if err != nil {
		l.shutdown(err)
		return err
	}
	l.shutdown(io.EOF)
	return nil
}

func (l *kREALITYListener) Addr() net.Addr { return l.inner.Addr() }

func (l *kREALITYListener) doRustRealityDeferred(fd int) (*native.DeferredResult, error) {
	cfg := native.RealityConfigNew(false)
	if cfg == nil {
		return nil, errors.New("failed to create native REALITY server config")
	}
	defer native.RealityConfigFree(cfg)

	rc := l.realityXrayConfig
	native.RealityConfigSetPrivateKey(cfg, rc.PrivateKey)

	if serverNames := xhttpEncodeRealityServerNames(rc.ServerNames); len(serverNames) > 0 {
		native.RealityConfigSetServerNames(cfg, serverNames)
	}

	for _, sid := range rc.ShortIds {
		if len(sid) > 0 {
			native.RealityConfigAddShortId(cfg, sid)
		}
	}

	native.RealityConfigSetMaxTimeDiff(cfg, rc.MaxTimeDiff)

	if hasVersionRange, minVer, maxVer := xhttpRealityVersionRange(rc.MinClientVer, rc.MaxClientVer); hasVersionRange {
		native.RealityConfigSetVersionRange(cfg,
			minVer[0], minVer[1], minVer[2],
			maxVer[0], maxVer[1], maxVer[2])
	}

	return native.RealityServerDeferred(fd, cfg, l.timeout)
}

func xhttpEncodeRealityServerNames(serverNames []string) []byte {
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

func xhttpRealityVersionRange(minClientVer, maxClientVer []byte) (bool, [3]uint8, [3]uint8) {
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

func xhttpIsDeferredRealityPeekTimeout(err error) bool {
	return native.IsRealityDeferredPeekTimeout(err)
}

type Listener struct {
	sync.Mutex
	server     http.Server
	h3server   *http3.Server
	listener   net.Listener
	h3listener *quic.EarlyListener
	config     *Config
	addConn    internet.ConnHandler
	isH3       bool
}

func ListenXH(ctx context.Context, address net.Address, port net.Port, streamSettings *internet.MemoryStreamConfig, addConn internet.ConnHandler) (internet.Listener, error) {
	l := &Listener{
		addConn: addConn,
	}
	l.config = streamSettings.ProtocolSettings.(*Config)
	if l.config != nil {
		if streamSettings.SocketSettings == nil {
			streamSettings.SocketSettings = &internet.SocketConfig{}
		}
	}
	handler := &requestHandler{
		config:         l.config,
		host:           l.config.Host,
		path:           l.config.GetNormalizedPath(),
		ln:             l,
		sessionMu:      &sync.Mutex{},
		sessions:       sync.Map{},
		maxSessions:    getMaxConcurrentSessions(),
		socketSettings: streamSettings.SocketSettings,
	}
	caps := xhttpCapabilitiesSummary()
	errors.LogInfo(ctx, "reality markers[kind=xhttp-capabilities]: ",
		"ktls_supported=", caps.KTLSSupported,
		" sockmap_supported=", caps.SockmapSupported,
		" splice_supported=", caps.SpliceSupported)
	tlsConfig := getTLSConfig(streamSettings)
	l.isH3 = len(tlsConfig.NextProtos) == 1 && tlsConfig.NextProtos[0] == "h3"

	var err error
	if port == net.Port(0) { // unix
		l.listener, err = internet.ListenSystem(ctx, &net.UnixAddr{
			Name: address.Domain(),
			Net:  "unix",
		}, streamSettings.SocketSettings)
		if err != nil {
			return nil, errors.New("failed to listen UNIX domain socket for XHTTP on ", address).Base(err)
		}
		errors.LogInfo(ctx, "listening UNIX domain socket for XHTTP on ", address)
	} else if l.isH3 { // quic
		Conn, err := internet.ListenSystemPacket(context.Background(), &net.UDPAddr{
			IP:   address.IP(),
			Port: int(port),
		}, streamSettings.SocketSettings)
		if err != nil {
			return nil, errors.New("failed to listen UDP for XHTTP/3 on ", address, ":", port).Base(err)
		}
		l.h3listener, err = quic.ListenEarly(Conn, tlsConfig, nil)
		if err != nil {
			return nil, errors.New("failed to listen QUIC for XHTTP/3 on ", address, ":", port).Base(err)
		}
		errors.LogInfo(ctx, "listening QUIC for XHTTP/3 on ", address, ":", port)

		handler.localAddr = l.h3listener.Addr()

		l.h3server = &http3.Server{
			Handler: handler,
		}
		go func() {
			defer func() {
				if r := recover(); r != nil {
					errors.LogError(ctx, "panic in XHTTP/3 server: ", r)
				}
			}()
			if err := l.h3server.ServeListener(l.h3listener); err != nil {
				errors.LogErrorInner(ctx, err, "failed to serve HTTP/3 for XHTTP/3")
			}
		}()
	} else { // tcp
		l.listener, err = internet.ListenSystem(ctx, &net.TCPAddr{
			IP:   address.IP(),
			Port: int(port),
		}, streamSettings.SocketSettings)
		if err != nil {
			return nil, errors.New("failed to listen TCP for XHTTP on ", address, ":", port).Base(err)
		}
		errors.LogInfo(ctx, "listening TCP for XHTTP on ", address, ":", port)
	}

	// tcp/unix (h1/h2)
	if l.listener != nil {
		if config := tls.ConfigFromStreamSettings(streamSettings); config != nil {
			acceptProxyProtocol := streamSettings.SocketSettings != nil && streamSettings.SocketSettings.AcceptProxyProtocol
			if acceptProxyProtocol {
				errors.LogDebug(ctx, "XHTTP kTLS listener disabled: accept_proxy_protocol requires Go TLS listener")
			}
			if xhttpKTLSListenerEligible(port, streamSettings.SocketSettings, native.Available(), tls.NativeFullKTLSSupportedForTLSConfig(config)) {
				l.listener = &kTLSListener{
					inner:     l.listener,
					tlsConfig: config,
					timeout:   4 * time.Second,
				}
				errors.LogInfo(ctx, "XHTTP using kTLS-accelerated TLS listener")
			} else if tlsConfig := config.GetTLSConfig(); tlsConfig != nil {
				l.listener = gotls.NewListener(l.listener, tlsConfig)
			}
		}
		if config := reality.ConfigFromStreamSettings(streamSettings); config != nil {
			acceptProxyProtocol := streamSettings.SocketSettings != nil && streamSettings.SocketSettings.AcceptProxyProtocol
			if acceptProxyProtocol {
				errors.LogDebug(ctx, "XHTTP kREALITY listener disabled: accept_proxy_protocol requires Go REALITY listener")
			}
			if xhttpKREALITYListenerEligible(
				port,
				streamSettings.SocketSettings,
				config,
				native.Available(),
				tls.NativeFullKTLSSupported(),
				caps,
			) {
				l.listener = newKREALITYListener(l.listener, config.GetREALITYConfig(), config, 8*time.Second)
				errors.LogInfo(ctx, "XHTTP using kTLS-accelerated REALITY listener")
			} else {
				l.listener = goreality.NewListener(l.listener, config.GetREALITYConfig())
			}
		}

		handler.localAddr = l.listener.Addr()

		// server can handle both plaintext HTTP/1.1 and h2c
		protocols := new(http.Protocols)
		protocols.SetHTTP1(true)
		protocols.SetUnencryptedHTTP2(true)
		l.server = http.Server{
			Handler:           handler,
			ReadHeaderTimeout: time.Second * 4,
			IdleTimeout:       time.Second * 120,
			MaxHeaderBytes:    8192,
			Protocols:         protocols,
		}
		go func() {
			defer func() {
				if r := recover(); r != nil {
					errors.LogError(ctx, "panic in XHTTP server: ", r)
				}
			}()
			if err := l.server.Serve(l.listener); err != nil {
				errors.LogErrorInner(ctx, err, "failed to serve HTTP for XHTTP")
			}
		}()
	}

	return l, err
}

// Addr implements net.Listener.Addr().
func (ln *Listener) Addr() net.Addr {
	if ln.h3listener != nil {
		return ln.h3listener.Addr()
	}
	if ln.listener != nil {
		return ln.listener.Addr()
	}
	return nil
}

// Close implements net.Listener.Close().
func (ln *Listener) Close() error {
	if ln.h3server != nil {
		return ln.h3server.Close()
	}
	if ln.listener != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return ln.server.Shutdown(ctx)
	}
	return errors.New("listener does not have an HTTP/3 server or a net.listener")
}
func getTLSConfig(streamSettings *internet.MemoryStreamConfig) *gotls.Config {
	config := tls.ConfigFromStreamSettings(streamSettings)
	if config == nil {
		return &gotls.Config{}
	}
	return config.GetTLSConfig()
}
func init() {
	// Initialize optional hook storage so Load is safe before any custom hook is set.
	xhttpInvalidateHook.Store((func())(nil))
	common.Must(internet.RegisterTransportListener(protocolName, ListenXH))
}
