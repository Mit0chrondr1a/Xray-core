package inbound

import (
	"bytes"
	"context"
	gotls "crypto/tls"
	"encoding/base64"
	"io"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/reverse"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/retry"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/dns"
	feature_inbound "github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vless/encoding"
	"github.com/xtls/xray-core/proxy/vless/encryption"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/splithttp"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

var (
	reverseOutboundWaitTimeout  = 5 * time.Second
	reverseOutboundPollInterval = 200 * time.Millisecond
	visionInputFieldType        = reflect.TypeOf(bytes.Reader{})
	visionRawInputFieldType     = reflect.TypeOf(bytes.Buffer{})
)

func resolveVisionInternalReaders(t reflect.Type, base uintptr) (*bytes.Reader, *bytes.Buffer, error) {
	if t == nil {
		return nil, nil, nil
	}
	inputField, inputOK := t.FieldByName("input")
	rawInputField, rawInputOK := t.FieldByName("rawInput")
	if !inputOK || !rawInputOK {
		return nil, nil, errors.New("XTLS Vision internal layout mismatch for ", t.String(), ": missing input/rawInput fields").AtWarning()
	}
	if inputField.Type != visionInputFieldType || rawInputField.Type != visionRawInputFieldType {
		return nil, nil, errors.New(
			"XTLS Vision internal layout mismatch for ", t.String(),
			": unexpected input/rawInput types (input=", inputField.Type.String(),
			", rawInput=", rawInputField.Type.String(), ")",
		).AtWarning()
	}
	input := (*bytes.Reader)(unsafe.Pointer(base + inputField.Offset))
	rawInput := (*bytes.Buffer)(unsafe.Pointer(base + rawInputField.Offset))
	return input, rawInput, nil
}

func applyVisionExecutionGate(inbound *session.Inbound, deferredVisionPath bool) {
	if inbound == nil {
		return
	}
	if deferredVisionPath {
		inbound.SetCanSpliceCopy(session.CopyGatePendingDetach)
		return
	}
	// The legacy Go TLS/REALITY path does not have a reliable detach signal
	// boundary. Keep it on the userspace path from the start instead of sending
	// the generic copy loop into pending-detach prediction mode.
	inbound.SetCopyGate(session.CopyGateForcedUserspace, session.CopyGateReasonUnspecified)
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		var dc dns.Client
		if err := core.RequireFeatures(ctx, func(d dns.Client) error {
			dc = d
			return nil
		}); err != nil {
			return nil, err
		}

		c := config.(*Config)

		validator := new(vless.MemoryValidator)
		for _, user := range c.Clients {
			u, err := user.ToMemoryUser()
			if err != nil {
				return nil, errors.New("failed to get VLESS user").Base(err).AtError()
			}
			if err := validator.Add(u); err != nil {
				return nil, errors.New("failed to initiate user").Base(err).AtError()
			}
		}

		return New(ctx, c, dc, validator)
	}))
}

// Handler is an inbound connection handler that handles messages in VLess protocol.
type Handler struct {
	inboundHandlerManager  feature_inbound.Manager
	policyManager          policy.Manager
	stats                  stats.Manager
	validator              vless.Validator
	decryption             *encryption.ServerInstance
	outboundHandlerManager outbound.Manager
	defaultDispatcher      routing.Dispatcher
	ctx                    context.Context
	fallbacks              map[string]map[string]map[string]*Fallback // or nil
	// regexps               map[string]*regexp.Regexp       // or nil
}

// New creates a new VLess inbound handler.
func New(ctx context.Context, config *Config, dc dns.Client, validator vless.Validator) (*Handler, error) {
	v := core.MustFromContext(ctx)
	handler := &Handler{
		inboundHandlerManager:  v.GetFeature(feature_inbound.ManagerType()).(feature_inbound.Manager),
		policyManager:          v.GetFeature(policy.ManagerType()).(policy.Manager),
		stats:                  v.GetFeature(stats.ManagerType()).(stats.Manager),
		validator:              validator,
		outboundHandlerManager: v.GetFeature(outbound.ManagerType()).(outbound.Manager),
		defaultDispatcher:      v.GetFeature(routing.DispatcherType()).(routing.Dispatcher),
		ctx:                    ctx,
	}

	if config.Decryption != "" && config.Decryption != "none" {
		s := strings.Split(config.Decryption, ".")
		var nfsSKeysBytes [][]byte
		for _, r := range s {
			b, _ := base64.RawURLEncoding.DecodeString(r)
			nfsSKeysBytes = append(nfsSKeysBytes, b)
		}
		handler.decryption = &encryption.ServerInstance{}
		if err := handler.decryption.Init(nfsSKeysBytes, config.XorMode, config.SecondsFrom, config.SecondsTo, config.Padding); err != nil {
			return nil, errors.New("failed to use decryption").Base(err).AtError()
		}
	}

	if config.Fallbacks != nil {
		handler.fallbacks = make(map[string]map[string]map[string]*Fallback)
		// handler.regexps = make(map[string]*regexp.Regexp)
		for _, fb := range config.Fallbacks {
			if handler.fallbacks[fb.Name] == nil {
				handler.fallbacks[fb.Name] = make(map[string]map[string]*Fallback)
			}
			if handler.fallbacks[fb.Name][fb.Alpn] == nil {
				handler.fallbacks[fb.Name][fb.Alpn] = make(map[string]*Fallback)
			}
			handler.fallbacks[fb.Name][fb.Alpn][fb.Path] = fb
			/*
				if fb.Path != "" {
					if r, err := regexp.Compile(fb.Path); err != nil {
						return nil, errors.New("invalid path regexp").Base(err).AtError()
					} else {
						handler.regexps[fb.Path] = r
					}
				}
			*/
		}
		if handler.fallbacks[""] != nil {
			for name, apfb := range handler.fallbacks {
				if name != "" {
					for alpn := range handler.fallbacks[""] {
						if apfb[alpn] == nil {
							apfb[alpn] = make(map[string]*Fallback)
						}
					}
				}
			}
		}
		for _, apfb := range handler.fallbacks {
			if apfb[""] != nil {
				for alpn, pfb := range apfb {
					if alpn != "" { // && alpn != "h2" {
						for path, fb := range apfb[""] {
							if pfb[path] == nil {
								pfb[path] = fb
							}
						}
					}
				}
			}
		}
		if handler.fallbacks[""] != nil {
			for name, apfb := range handler.fallbacks {
				if name != "" {
					for alpn, pfb := range handler.fallbacks[""] {
						for path, fb := range pfb {
							if apfb[alpn][path] == nil {
								apfb[alpn][path] = fb
							}
						}
					}
				}
			}
		}
	}

	return handler, nil
}

func isMuxAndNotXUDP(request *protocol.RequestHeader, first *buf.Buffer) bool {
	if request.Command != protocol.RequestCommandMux {
		return false
	}
	if first.Len() < 7 {
		return true
	}
	firstBytes := first.Bytes()
	return !(firstBytes[2] == 0 && // ID high
		firstBytes[3] == 0 && // ID low
		firstBytes[6] == 2) // Network type: UDP
}

func (h *Handler) GetReverse(a *vless.MemoryAccount) (*Reverse, error) {
	u := h.validator.Get(a.ID.UUID())
	if u == nil {
		return nil, errors.New("reverse: user " + a.ID.String() + " doesn't exist anymore")
	}
	a = u.Account.(*vless.MemoryAccount)
	if a.Reverse == nil || a.Reverse.Tag == "" {
		return nil, errors.New("reverse: user " + a.ID.String() + " is not allowed to create reverse proxy")
	}
	r := h.outboundHandlerManager.GetHandler(a.Reverse.Tag)
	if r == nil {
		picker, _ := reverse.NewStaticMuxPicker()
		r = &Reverse{tag: a.Reverse.Tag, picker: picker, client: &mux.ClientManager{Picker: picker}}
		// Wait for at least one outbound handler to be registered before adding
		// the reverse handler, preventing it from becoming the default outbound.
		// Keep the wait short and responsive: this is cold-path startup protection,
		// not a session hot path, and long stalls hurt operability more than they help.
		waitTimer := time.NewTimer(reverseOutboundWaitTimeout)
		defer waitTimer.Stop()
		pollTicker := time.NewTicker(reverseOutboundPollInterval)
		defer pollTicker.Stop()
		for len(h.outboundHandlerManager.ListHandlers(h.ctx)) == 0 {
			select {
			case <-h.ctx.Done():
				return nil, errors.New("reverse: context cancelled while waiting for outbound handlers")
			case <-waitTimer.C:
				return nil, errors.New("reverse: timed out waiting for outbound handlers to register")
			case <-pollTicker.C:
			}
		}
		if err := h.outboundHandlerManager.AddHandler(h.ctx, r); err != nil {
			return nil, err
		}
	}
	if r, ok := r.(*Reverse); ok {
		return r, nil
	}
	return nil, errors.New("reverse: outbound " + a.Reverse.Tag + " is not type Reverse")
}

func (h *Handler) RemoveReverse(u *protocol.MemoryUser) {
	if u != nil {
		a := u.Account.(*vless.MemoryAccount)
		if a.Reverse != nil && a.Reverse.Tag != "" {
			h.outboundHandlerManager.RemoveHandler(h.ctx, a.Reverse.Tag)
		}
	}
}

// Close implements common.Closable.Close().
func (h *Handler) Close() error {
	if h.decryption != nil {
		h.decryption.Close()
	}
	for _, u := range h.validator.GetAll() {
		h.RemoveReverse(u)
	}
	return errors.Combine(common.Close(h.validator))
}

// AddUser implements proxy.UserManager.AddUser().
func (h *Handler) AddUser(ctx context.Context, u *protocol.MemoryUser) error {
	return h.validator.Add(u)
}

// RemoveUser implements proxy.UserManager.RemoveUser().
func (h *Handler) RemoveUser(ctx context.Context, e string) error {
	h.RemoveReverse(h.validator.GetByEmail(e))
	return h.validator.Del(e)
}

// GetUser implements proxy.UserManager.GetUser().
func (h *Handler) GetUser(ctx context.Context, email string) *protocol.MemoryUser {
	return h.validator.GetByEmail(email)
}

// GetUsers implements proxy.UserManager.GetUsers().
func (h *Handler) GetUsers(ctx context.Context) []*protocol.MemoryUser {
	return h.validator.GetAll()
}

// GetUsersCount implements proxy.UserManager.GetUsersCount().
func (h *Handler) GetUsersCount(context.Context) int64 {
	return h.validator.GetCount()
}

// Network implements proxy.Inbound.Network().
func (*Handler) Network() []net.Network {
	return []net.Network{net.Network_TCP, net.Network_UNIX}
}

// Process implements proxy.Inbound.Process().
func (h *Handler) Process(ctx context.Context, network net.Network, connection stat.Connection, dispatch routing.Dispatcher) error {
	iConn := stat.TryUnwrapStatsConn(connection)

	if h.decryption != nil {
		var err error
		if connection, err = h.decryption.Handshake(connection, nil); err != nil {
			return errors.New("ML-KEM-768 handshake failed").Base(err).AtInfo()
		}
	}

	sessionPolicy := h.policyManager.ForLevel(0)
	if err := proxy.SetHandshakeReadDeadline(connection, time.Now().Add(sessionPolicy.Timeouts.Handshake)); err != nil {
		return errors.New("unable to set read deadline").Base(err).AtWarning()
	}

	first := buf.FromBytes(make([]byte, buf.Size))
	first.Clear()
	firstLen, errR := first.ReadFrom(connection)
	if errR != nil {
		return errR
	}

	reader := &buf.BufferedReader{
		Reader: buf.NewReader(connection),
		Buffer: buf.MultiBuffer{first},
	}

	var userSentID []byte // not MemoryAccount.ID
	var request *protocol.RequestHeader
	var requestAddons *encoding.Addons
	var err error

	napfb := h.fallbacks
	isfb := napfb != nil

	if isfb && firstLen < 18 {
		err = errors.New("fallback directly")
	} else {
		userSentID, request, requestAddons, isfb, err = encoding.DecodeRequestHeader(isfb, first, reader, h.validator)
	}

	if err != nil {
		if isfb {
			if err := proxy.ClearHandshakeReadDeadline(connection); err != nil {
				errors.LogWarningInner(ctx, err, "unable to set back read deadline")
			}
			errors.LogInfoInner(ctx, err, "fallback starts")

			name := ""
			alpn := ""
			if tlsConn, ok := iConn.(*tls.Conn); ok {
				cs := tlsConn.ConnectionState()
				name = cs.ServerName
				alpn = cs.NegotiatedProtocol
				errors.LogInfo(ctx, "realName = "+name)
				errors.LogInfo(ctx, "realAlpn = "+alpn)
			} else if realityConn, ok := iConn.(*reality.Conn); ok {
				cs := realityConn.ConnectionState()
				name = cs.ServerName
				alpn = cs.NegotiatedProtocol
				errors.LogInfo(ctx, "realName = "+name)
				errors.LogInfo(ctx, "realAlpn = "+alpn)
			} else if dc, ok := iConn.(*tls.DeferredRustConn); ok {
				cs := dc.ConnectionState()
				name = cs.ServerName
				alpn = cs.NegotiatedProtocol
				errors.LogInfo(ctx, "realName = "+name)
				errors.LogInfo(ctx, "realAlpn = "+alpn)
				inbound := session.InboundFromContext(ctx)
				tag := ""
				if inbound != nil {
					tag = inbound.Tag
				}
				if outcome, ktlsErr := dc.EnableKTLSOutcome(); ktlsErr != nil {
					return errors.New("deferred kTLS enable failed in fallback").Base(ktlsErr).AtWarning()
				} else if outcome.Status == tls.KTLSPromotionEnabled {
					errors.LogInfo(
						ctx,
						"[kind=fallback.ktls_enabled] tag=",
						tag,
						" transport=deferred_rust status=",
						outcome.Status.String(),
						" server_name=",
						name,
						" alpn=",
						alpn,
					)
				} else if outcome.Status != tls.KTLSPromotionEnabled {
					errors.LogWarning(
						ctx,
						"[kind=fallback.ktls_status] tag=",
						tag,
						" transport=deferred_rust status=",
						outcome.Status.String(),
						" server_name=",
						name,
						" alpn=",
						alpn,
					)
					errors.LogWarning(ctx, "deferred kTLS not enabled in fallback path: ", outcome.Status)
					// Continue on rustls; handle is still valid.
				}
			}
			name = strings.ToLower(name)
			alpn = strings.ToLower(alpn)

			if len(napfb) > 1 || napfb[""] == nil {
				if name != "" && napfb[name] == nil {
					match := ""
					for n := range napfb {
						if n != "" && strings.Contains(name, n) && len(n) > len(match) {
							match = n
						}
					}
					name = match
				}
			}

			if napfb[name] == nil {
				name = ""
			}
			apfb := napfb[name]
			if apfb == nil {
				return errors.New(`failed to find the default "name" config`).AtWarning()
			}

			if apfb[alpn] == nil {
				alpn = ""
			}
			pfb := apfb[alpn]
			if pfb == nil {
				return errors.New(`failed to find the default "alpn" config`).AtWarning()
			}

			path := ""
			if len(pfb) > 1 || pfb[""] == nil {
				/*
					if lines := bytes.Split(firstBytes, []byte{'\r', '\n'}); len(lines) > 1 {
						if s := bytes.Split(lines[0], []byte{' '}); len(s) == 3 {
							if len(s[0]) < 8 && len(s[1]) > 0 && len(s[2]) == 8 {
								errors.New("realPath = " + string(s[1])).AtInfo().WriteToLog(sid)
								for _, fb := range pfb {
									if fb.Path != "" && h.regexps[fb.Path].Match(s[1]) {
										path = fb.Path
										break
									}
								}
							}
						}
					}
				*/
				if firstLen >= 18 && first.Byte(4) != '*' { // not h2c
					firstBytes := first.Bytes()
					for i := 4; i <= 8; i++ { // 5 -> 9
						if firstBytes[i] == '/' && firstBytes[i-1] == ' ' {
							search := len(firstBytes)
							if search > 64 {
								search = 64 // up to about 60
							}
							for j := i + 1; j < search; j++ {
								k := firstBytes[j]
								if k == '\r' || k == '\n' { // avoid logging \r or \n
									break
								}
								if k == '?' || k == ' ' {
									path = string(firstBytes[i:j])
									errors.LogInfo(ctx, "realPath = "+path)
									if pfb[path] == nil {
										path = ""
									}
									break
								}
							}
							break
						}
					}
				}
			}
			fb := pfb[path]
			if fb == nil {
				return errors.New(`failed to find the default "path" config`).AtWarning()
			}

			ctx, cancel := context.WithCancel(ctx)
			timer := signal.CancelAfterInactivity(ctx, cancel, sessionPolicy.Timeouts.ConnectionIdle)
			ctx = policy.ContextWithBufferPolicy(ctx, sessionPolicy.Buffer)

			var conn net.Conn
			if err := retry.ExponentialBackoff(5, 100).On(func() error {
				var dialer net.Dialer
				conn, err = dialer.DialContext(ctx, fb.Type, fb.Dest)
				if err != nil {
					return err
				}
				return nil
			}); err != nil {
				return errors.New("failed to dial to " + fb.Dest).Base(err).AtWarning()
			}
			defer conn.Close()

			serverReader := buf.NewReader(conn)
			serverWriter := buf.NewWriter(conn)

			postRequest := func() error {
				defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)
				if fb.Xver != 0 {
					ipType := 4
					remoteAddr, remotePort, err := net.SplitHostPort(connection.RemoteAddr().String())
					if err != nil {
						ipType = 0
					}
					localAddr, localPort, err := net.SplitHostPort(connection.LocalAddr().String())
					if err != nil {
						ipType = 0
					}
					if ipType == 4 {
						for i := 0; i < len(remoteAddr); i++ {
							if remoteAddr[i] == ':' {
								ipType = 6
								break
							}
						}
					}
					pro := buf.New()
					defer pro.Release()
					switch fb.Xver {
					case 1:
						if ipType == 0 {
							pro.Write([]byte("PROXY UNKNOWN\r\n"))
							break
						}
						if ipType == 4 {
							pro.Write([]byte("PROXY TCP4 " + remoteAddr + " " + localAddr + " " + remotePort + " " + localPort + "\r\n"))
						} else {
							pro.Write([]byte("PROXY TCP6 " + remoteAddr + " " + localAddr + " " + remotePort + " " + localPort + "\r\n"))
						}
					case 2:
						pro.Write([]byte("\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A")) // signature
						if ipType == 0 {
							pro.Write([]byte("\x20\x00\x00\x00")) // v2 + LOCAL + UNSPEC + UNSPEC + 0 bytes
							break
						}
						if ipType == 4 {
							pro.Write([]byte("\x21\x11\x00\x0C")) // v2 + PROXY + AF_INET + STREAM + 12 bytes
							pro.Write(net.ParseIP(remoteAddr).To4())
							pro.Write(net.ParseIP(localAddr).To4())
						} else {
							pro.Write([]byte("\x21\x21\x00\x24")) // v2 + PROXY + AF_INET6 + STREAM + 36 bytes
							pro.Write(net.ParseIP(remoteAddr).To16())
							pro.Write(net.ParseIP(localAddr).To16())
						}
						p1, _ := strconv.ParseUint(remotePort, 10, 16)
						p2, _ := strconv.ParseUint(localPort, 10, 16)
						pro.Write([]byte{byte(p1 >> 8), byte(p1), byte(p2 >> 8), byte(p2)})
					}
					if err := serverWriter.WriteMultiBuffer(buf.MultiBuffer{pro}); err != nil {
						return errors.New("failed to set PROXY protocol v", fb.Xver).Base(err).AtWarning()
					}
				}
				if err := proxy.CopyFallbackRequest(ctx, connection, conn, reader, serverWriter, timer); err != nil {
					return errors.New("failed to fallback request payload").Base(err).AtInfo()
				}
				return nil
			}

			writer := buf.NewWriter(connection)

			getResponse := func() error {
				defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)
				if err := proxy.CopyFallbackResponse(ctx, conn, connection, writer, timer); err != nil {
					return errors.New("failed to deliver response payload").Base(err).AtInfo()
				}
				return nil
			}

			ctx = proxy.WithFallbackRuntimeRecoveryContext(ctx, connection)

			if err := task.Run(ctx, task.OnSuccess(postRequest, task.Close(serverWriter)), task.OnSuccess(getResponse, task.Close(writer))); err != nil {
				common.Interrupt(serverReader)
				common.Interrupt(serverWriter)
				return errors.New("fallback ends").Base(err).AtInfo()
			}
			return nil
		}

		if errors.Cause(err) != io.EOF {
			log.Record(&log.AccessMessage{
				From:   connection.RemoteAddr(),
				To:     "",
				Status: log.AccessRejected,
				Reason: err,
			})
			err = errors.New("invalid request from ", connection.RemoteAddr()).Base(err).AtInfo()
		}
		return err
	}

	if err := proxy.ClearHandshakeReadDeadline(connection); err != nil {
		errors.LogWarningInner(ctx, err, "unable to set back read deadline")
	}
	errors.LogInfo(ctx, "received request for ", request.Destination())

	inbound := session.InboundFromContext(ctx)
	if inbound == nil {
		return errors.New("no inbound metadata in context")
	}
	inbound.Name = "vless"
	inbound.User = request.User
	inbound.VlessRoute = net.PortFromBytes(userSentID[6:8])

	account := request.User.Account.(*vless.MemoryAccount)

	if account.Reverse != nil && request.Command != protocol.RequestCommandRvs {
		return errors.New("for safety reasons, user " + account.ID.String() + " is not allowed to use forward proxy")
	}

	responseAddons := &encoding.Addons{
		// Flow: requestAddons.Flow,
	}

	var input *bytes.Reader
	var rawInput *bytes.Buffer
	deferredVisionPath := false
	switch requestAddons.Flow {
	case vless.XRV:
		if account.Flow == requestAddons.Flow {
			switch request.Command {
			case protocol.RequestCommandUDP:
				return errors.New(requestAddons.Flow + " doesn't support UDP").AtWarning()
			case protocol.RequestCommandMux, protocol.RequestCommandRvs:
				inbound.SetCopyGate(session.CopyGateForcedUserspace, session.CopyGateReasonSecurityGuard)
				fallthrough // we will break Mux connections that contain TCP requests
			case protocol.RequestCommandTCP:
				var t reflect.Type
				var p uintptr
				if commonConn, ok := connection.(*encryption.CommonConn); ok {
					if _, ok := commonConn.Conn.(*encryption.XorConn); ok || !proxy.IsRAWTransportWithoutSecurity(iConn) {
						inbound.SetCopyGate(session.CopyGateForcedUserspace, session.CopyGateReasonSecurityGuard) // full-random xorConn / non-RAW transport / another securityConn should not be penetrated
					}
					t = reflect.TypeOf(commonConn).Elem()
					p = uintptr(unsafe.Pointer(commonConn))
				} else if tlsConn, ok := iConn.(*tls.Conn); ok {
					if tlsConn.ConnectionState().Version != gotls.VersionTLS13 {
						return errors.New(`failed to use `+requestAddons.Flow+`, found outer tls version `, tlsConn.ConnectionState().Version).AtWarning()
					}
					t = reflect.TypeOf(tlsConn.Conn).Elem()
					p = uintptr(unsafe.Pointer(tlsConn.Conn))
				} else if realityConn, ok := iConn.(*reality.Conn); ok {
					t = reflect.TypeOf(realityConn.Conn).Elem()
					p = uintptr(unsafe.Pointer(realityConn.Conn))
				} else if rc, ok := iConn.(*tls.RustConn); ok {
					if ktls := rc.KTLSEnabled(); !ktls.TxReady || !ktls.RxReady {
						return errors.New("RustConn without full kTLS cannot use " + requestAddons.Flow).AtWarning()
					}
					// kTLS + Vision is unsupported; refuse early to avoid corrupting streams.
					return errors.New("Vision is incompatible with kTLS-native RustConn; use non-Vision or disable kTLS for this flow").AtWarning()
				} else if _, ok := iConn.(*tls.DeferredRustConn); ok {
					// Deferred kTLS: rustls handles TLS. Vision will strip at command=2.
					// VisionReader will call DeferredRustConn.DrainAndDetach().
					deferredVisionPath = true
					input = nil
					rawInput = nil
				} else {
					return errors.New("XTLS only supports TLS and REALITY directly for now.").AtWarning()
				}
				if t != nil {
					var layoutErr error
					input, rawInput, layoutErr = resolveVisionInternalReaders(t, p)
					if layoutErr != nil {
						return layoutErr
					}
				}
				applyVisionExecutionGate(inbound, deferredVisionPath)
			}
		} else {
			return errors.New("account " + account.ID.String() + " is not able to use the flow " + requestAddons.Flow).AtWarning()
		}
	case "":
		gateState, gateReason := flowEmptyGate(iConn)
		allowRawAccel := os.Getenv("XRAY_FEATURE_FLOW_EMPTY_RAW_ACCEL") == "1"
		ktlsReady := false
		allowFlowDowngrade := allowVisionFlowDowngrade(inbound, account.Flow, request.Destination())
		if strings.HasPrefix(account.Flow, vless.XRV) &&
			(request.Command == protocol.RequestCommandTCP || isMuxAndNotXUDP(request, first)) &&
			!allowFlowDowngrade {
			return errors.New("account " + account.ID.String() + " is rejected since the client flow is empty. Note that the pure TLS proxy has certain TLS in TLS characters.").AtWarning()
		}
		if dc, ok := iConn.(*tls.DeferredRustConn); ok {
			if outcome, err := dc.EnableKTLSOutcome(); err != nil {
				return errors.New("deferred kTLS enable failed for non-Vision VLESS").Base(err).AtWarning()
			} else if outcome.Status == tls.KTLSPromotionEnabled {
				errors.LogDebug(ctx, "non-Vision VLESS: kTLS enabled on DeferredRustConn")
				ktlsReady = true
			} else {
				errors.LogWarning(ctx, "non-Vision VLESS: kTLS not enabled (", outcome.Status, "); continuing with rustls path")
			}
		} else if tlsConn, ok := iConn.(*tls.Conn); ok {
			if err := tlsConn.HandshakeAndEnableKTLS(context.Background()); err != nil {
				return errors.New("kTLS enable failed for non-Vision VLESS TLS connection").Base(err).AtWarning()
			}
			ktlsReady = true
		}
		// Optional ROI path: allow raw TCP + kTLS-ready empty-flow to be copy-eligible.
		if allowRawAccel && ktlsReady && gateState != session.CopyGateNotApplicable && proxy.IsRAWTransportWithoutSecurity(iConn) {
			inbound.SetCopyGate(session.CopyGateEligible, session.CopyGateReasonUnspecified)
		} else {
			inbound.SetCopyGate(gateState, gateReason)
		}
		if allowFlowDowngrade {
			ctx = session.ContextWithDNSPlane(ctx, session.DNSPlaneOther)
			errors.LogDebug(ctx, "loopback TCP DNS flow: accepting plain VLESS downgrade on Vision account")
		}
	default:
		return errors.New("unknown request flow " + requestAddons.Flow).AtWarning()
	}

	if request.Command != protocol.RequestCommandMux {
		ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
			From:   connection.RemoteAddr(),
			To:     request.Destination(),
			Status: log.AccessAccepted,
			Reason: "",
			Email:  request.User.Email,
		})
	} else if account.Flow == vless.XRV {
		ctx = session.ContextWithAllowedNetwork(ctx, net.Network_UDP)
	}

	trafficState := proxy.NewTrafficState(userSentID)
	if deferredVisionPath {
		trafficState.NumberOfPacketToFilter = 32
	}
	visionReaderCtx := ctx
	visionWriterCtx := ctx
	var visionSignalCh chan session.VisionSignal
	// Vision uplink/downlink processing can run concurrently, so each direction
	// needs its own arena because buf.Arena is not thread-safe.
	if requestAddons.Flow == vless.XRV {
		visionSignalCh = make(chan session.VisionSignal, 1)
		ctx = session.ContextWithVisionSignal(ctx, visionSignalCh)
		ctx = session.ContextWithVisionTimestamps(ctx, &session.VisionTimestamps{})
		readerArena := buf.NewArena(8 * buf.Size)
		writerArena := buf.NewArena(8 * buf.Size)
		visionReaderCtx = buf.ContextWithArena(ctx, readerArena)
		visionWriterCtx = buf.ContextWithArena(ctx, writerArena)
		defer readerArena.Close()
		defer writerArena.Close()
	}
	bypassVision := requestAddons.Flow == vless.XRV &&
		encoding.ShouldHonorInboundVisionPayloadBypass(requestAddons, ctx, request.Destination())
	if bypassVision {
		responseAddons.BypassVisionPayload = true
		trafficState.VisionPayloadBypassObserved = true
		inbound.SetCopyGate(session.CopyGateForcedUserspace, session.CopyGateReasonVisionBypass)
		ctx = session.ContextWithDNSPlane(ctx, session.DNSPlaneVisionGuard)
		visionReaderCtx = ctx
		visionWriterCtx = ctx
	}
	clientReader := encoding.DecodeBodyAddons(reader, request, requestAddons)
	if requestAddons.Flow == vless.XRV && !bypassVision {
		clientReader = proxy.NewVisionReader(clientReader, trafficState, true, visionReaderCtx, connection, visionSignalCh, input, rawInput, nil)
	}

	bufferWriter := buf.NewBufferedWriter(buf.NewWriter(connection))
	if err := encoding.EncodeResponseHeader(bufferWriter, request, responseAddons); err != nil {
		return errors.New("failed to encode response header").Base(err).AtWarning()
	}
	var clientWriter buf.Writer
	if bypassVision {
		clientWriter = bufferWriter
	} else {
		clientWriter = encoding.EncodeBodyAddons(bufferWriter, request, requestAddons, trafficState, false, visionWriterCtx, connection, nil)
	}
	bufferWriter.SetFlushNext()

	if request.Command == protocol.RequestCommandRvs {
		r, err := h.GetReverse(account)
		if err != nil {
			return err
		}
		return r.NewMux(ctx, dispatcher.WrapLink(ctx, h.policyManager, h.stats, &transport.Link{Reader: clientReader, Writer: clientWriter}))
	}

	if err := dispatch.DispatchLink(ctx, request.Destination(), &transport.Link{
		Reader: clientReader,
		Writer: clientWriter},
	); err != nil {
		return errors.New("failed to dispatch request").Base(err)
	}
	return nil
}

// flowEmptyGate computes copy gate state/reason for flow=="" without TLS side effects.
func flowEmptyGate(iConn net.Conn) (session.CopyGateState, session.CopyGateReason) {
	state := session.CopyGateForcedUserspace
	reason := session.CopyGateReasonFlowNonVisionPolicy
	if splithttp.IsSplitConn(iConn) {
		state = session.CopyGateNotApplicable
		reason = session.CopyGateReasonTransportNonRawSplitConn
	}
	return state, reason
}

func allowVisionFlowDowngrade(inbound *session.Inbound, accountFlow string, dest net.Destination) bool {
	if !strings.HasPrefix(accountFlow, vless.XRV) {
		return false
	}
	if !session.IsControlPlaneLoopbackIngress(inbound) {
		return false
	}
	return session.ClassifyDNSFlow(dest) == session.DNSFlowClassTCPControl
}

type Reverse struct {
	tag    string
	picker *reverse.StaticMuxPicker
	client *mux.ClientManager
}

func (r *Reverse) Tag() string {
	return r.tag
}

func (r *Reverse) NewMux(ctx context.Context, link *transport.Link) error {
	muxClient, err := mux.NewClientWorker(*link, mux.ClientStrategy{})
	if err != nil {
		return errors.New("failed to create mux client worker").Base(err).AtWarning()
	}
	worker, err := reverse.NewPortalWorker(muxClient)
	if err != nil {
		return errors.New("failed to create portal worker").Base(err).AtWarning()
	}
	r.picker.AddWorker(worker)
	select {
	case <-ctx.Done():
	case <-muxClient.WaitClosed():
	}
	return nil
}

func (r *Reverse) Dispatch(ctx context.Context, link *transport.Link) {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	if ob != nil {
		if ob.Target.Network == net.Network_UDP && ob.OriginalTarget.Address != nil && ob.OriginalTarget.Address != ob.Target.Address {
			link.Reader = &buf.EndpointOverrideReader{Reader: link.Reader, Dest: ob.Target.Address, OriginalDest: ob.OriginalTarget.Address}
			link.Writer = &buf.EndpointOverrideWriter{Writer: link.Writer, Dest: ob.Target.Address, OriginalDest: ob.OriginalTarget.Address}
		}
		r.client.Dispatch(session.ContextWithIsReverseMux(ctx, true), link)
	}
}

func (r *Reverse) Start() error {
	return nil
}

func (r *Reverse) Close() error {
	return nil
}

func (r *Reverse) SenderSettings() *serial.TypedMessage {
	return nil
}

func (r *Reverse) ProxySettings() *serial.TypedMessage {
	return nil
}
