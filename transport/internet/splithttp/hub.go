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
	http_proto "github.com/xtls/xray-core/common/protocol/http"
	"github.com/xtls/xray-core/common/signal/done"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
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

func xhttpKREALITYListenerEligible(
	port net.Port,
	socketSettings *internet.SocketConfig,
	realityConfig *reality.Config,
	nativeAvailable, fullKTLSSupported, deferredPromotionDisabled bool,
) bool {
	if port == 0 || !nativeAvailable || !fullKTLSSupported || deferredPromotionDisabled || realityConfig == nil {
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
	return true
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

func (l *kREALITYListener) processConn(rawConn net.Conn) (net.Conn, error) {
	tryGoFallback := false
	fd, fdErr := tls.ExtractFd(rawConn)
	if fdErr != nil {
		errors.LogDebugInner(context.Background(), fdErr, "XHTTP Rust REALITY path skipped: failed to extract fd")
		tryGoFallback = true
	} else {
		if err := rawConn.SetDeadline(time.Now().Add(l.timeout)); err != nil {
			return nil, errors.New("XHTTP Rust REALITY path: failed to set handshake deadline").Base(err)
		}
		deferredResult, deferredErr := l.doRustRealityDeferred(fd)
		if err := rawConn.SetDeadline(time.Time{}); err != nil {
			errors.LogWarningInner(context.Background(), err, "XHTTP Rust REALITY path: failed to clear handshake deadline")
		}
		if deferredErr == nil {
			deferredConn, wrapErr := tls.NewDeferredRustConn(rawConn, deferredResult)
			if wrapErr != nil {
				if deferredResult != nil && deferredResult.Handle != nil {
					native.DeferredFree(deferredResult.Handle)
				}
				return nil, errors.New("XHTTP Rust REALITY deferred handshake succeeded but wrap failed").Base(wrapErr)
			}
			if err := deferredConn.EnableKTLS(); err != nil {
				// Rust REALITY handshake already consumed TLS bytes; Go fallback
				// cannot safely re-handshake on this socket. Don't close deferredConn
				// here — the handle is already consumed by EnableKTLS FFI, and
				// handshakeAndEnqueue closes rawConn on error return.
				return nil, errors.New("XHTTP Rust REALITY deferred kTLS promotion failed").Base(err)
			}
			return tls.NewKTLSPlaintextConn(deferredConn), nil
		}
		if stderrors.Is(deferredErr, native.ErrRealityAuthFailed) {
			errors.LogInfo(context.Background(), "XHTTP Rust REALITY auth failed, falling back to Go REALITY camouflage")
			errors.LogDebug(context.Background(), "XHTTP REALITY auth detail: ", deferredErr)
			tryGoFallback = true
		} else if xhttpIsDeferredRealityPeekTimeout(deferredErr) {
			// Timeout happened before auth/handshake consumed bytes.
			errors.LogDebugInner(context.Background(), deferredErr, "XHTTP Rust REALITY deferred peek timed out, falling back to Go REALITY")
			tryGoFallback = true
		} else {
			return nil, errors.New("XHTTP Rust REALITY deferred handshake failed").Base(deferredErr)
		}
	}

	if tryGoFallback {
		// Keep fallback behavior aligned with upstream REALITY listener: no extra
		// deadline wrapper around reality.Server(), so camouflage timing/flow
		// matches the main Go path.
		realityConn, fallbackErr := reality.Server(rawConn, l.realityConfig)
		if fallbackErr != nil {
			return nil, fallbackErr
		}
		return realityConn, nil
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
				tls.DeferredKTLSPromotionDisabled(),
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
	common.Must(internet.RegisterTransportListener(protocolName, ListenXH))
}
