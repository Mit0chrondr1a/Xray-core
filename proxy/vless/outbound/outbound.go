package outbound

import (
	"bytes"
	"context"
	gotls "crypto/tls"
	"encoding/base64"
	"reflect"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	gonet "net"

	utls "github.com/refraction-networking/utls"
	proxyman "github.com/xtls/xray-core/app/proxyman/outbound"
	"github.com/xtls/xray-core/app/reverse"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	xctx "github.com/xtls/xray-core/common/ctx"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/retry"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/common/xudp"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vless/encoding"
	"github.com/xtls/xray-core/proxy/vless/encryption"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
	"github.com/xtls/xray-core/transport/pipe"
)

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*Config))
	}))
}

// Handler is an outbound connection handler for VLess protocol.
type Handler struct {
	server        *protocol.ServerSpec
	policyManager policy.Manager
	cone          bool
	encryption    *encryption.ClientInstance
	reverse       *Reverse

	testpre       uint32
	initpre       sync.Once
	preConns      chan *ConnExpire
	preConnsVFlow chan *ConnExpire
	preCtx        context.Context
	preCancel     context.CancelFunc
	preWG         sync.WaitGroup
	preVisionFlow atomic.Bool
}

type ConnExpire struct {
	Conn   stat.Connection
	Expire time.Time
}

func (h *Handler) preConnPool(visionFlow bool) chan *ConnExpire {
	if visionFlow {
		return h.preConnsVFlow
	}
	return h.preConns
}

func (h *Handler) closePreConnPool(pool chan *ConnExpire) {
	if pool == nil {
		return
	}
	close(pool)
	for ce := range pool {
		if ce != nil && ce.Conn != nil {
			ce.Conn.Close()
		}
	}
}

func shouldRewriteUDPToMux(cmd protocol.RequestCommand, flow string, cone bool, port net.Port) bool {
	if cmd != protocol.RequestCommandUDP {
		return false
	}
	if flow == vless.XRV {
		return true
	}
	return cone && port != 53 && port != 443
}

func isVisionSharedParentCommand(cmd protocol.RequestCommand) bool {
	switch cmd {
	case protocol.RequestCommandMux, protocol.RequestCommandRvs:
		return true
	default:
		return false
	}
}

func getVisionBuffersForRustConn(conn gonet.Conn, flow string) (handled bool, input *bytes.Reader, rawInput *bytes.Buffer, err error) {
	if flow != vless.XRV {
		return false, nil, nil, nil
	}
	rc, ok := conn.(*tls.RustConn)
	if !ok {
		return false, nil, nil, nil
	}
	// This path should be unreachable now: the Vision flow gate in outbound.go
	// sets ContextWithVisionFlow(ctx, true) before dialing, which skips Rust
	// native paths in the transport layer.  If we reach here, a code path
	// bypassed the gate (e.g., pre-connect without VisionFlow propagation).
	errors.LogWarning(context.Background(), "Vision flow on RustConn — gating bypassed; kTLS+Vision is unsupported and will be rejected")
	if ktls := rc.KTLSEnabled(); !ktls.TxReady || !ktls.RxReady {
		return true, nil, nil, errors.New("RustConn without full kTLS cannot use " + flow).AtWarning()
	}
	return true, nil, nil, errors.New("Vision is incompatible with kTLS-native RustConn; aborting outbound Vision flow").AtWarning()
}

// New creates a new VLess outbound handler.
func New(ctx context.Context, config *Config) (*Handler, error) {
	if config.Vnext == nil {
		return nil, errors.New(`no vnext found`)
	}
	server, err := protocol.NewServerSpecFromPB(config.Vnext)
	if err != nil {
		return nil, errors.New("failed to get server spec").Base(err).AtError()
	}

	v := core.MustFromContext(ctx)
	handler := &Handler{
		server:        server,
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
		cone:          xctx.ConeFromContext(ctx),
	}

	a := handler.server.User.Account.(*vless.MemoryAccount)
	if a.Encryption != "" && a.Encryption != "none" {
		s := strings.Split(a.Encryption, ".")
		var nfsPKeysBytes [][]byte
		for _, r := range s {
			b, _ := base64.RawURLEncoding.DecodeString(r)
			nfsPKeysBytes = append(nfsPKeysBytes, b)
		}
		handler.encryption = &encryption.ClientInstance{}
		if err := handler.encryption.Init(nfsPKeysBytes, a.XorMode, a.Seconds, a.Padding); err != nil {
			return nil, errors.New("failed to use encryption").Base(err).AtError()
		}
	}

	if a.Reverse != nil {
		handler.reverse = &Reverse{
			tag:        a.Reverse.Tag,
			dispatcher: v.GetFeature(routing.DispatcherType()).(routing.Dispatcher),
			ctx: session.ContextWithInbound(ctx, &session.Inbound{
				Tag:  a.Reverse.Tag,
				User: handler.server.User, // TODO: email
			}),
			handler: handler,
		}
		handler.reverse.monitorTask = &task.Periodic{
			Execute:  handler.reverse.monitor,
			Interval: time.Second * 2,
		}
		go func() {
			time.Sleep(2 * time.Second)
			handler.reverse.Start()
		}()
	}

	handler.testpre = a.Testpre

	return handler, nil
}

// Close implements common.Closable.Close().
func (h *Handler) Close() error {
	if h.preCancel != nil {
		h.preCancel()
		h.preWG.Wait()
	}
	h.closePreConnPool(h.preConns)
	h.closePreConnPool(h.preConnsVFlow)
	if h.reverse != nil {
		return h.reverse.Close()
	}
	return nil
}

// Process implements proxy.Outbound.Process().
func (h *Handler) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() && ob.Target.Address.String() != "v1.rvs.cool" {
		return errors.New("target not specified").AtError()
	}
	ob.Name = "vless"

	rec := h.server
	var conn stat.Connection
	accountFlow := rec.User.Account.(*vless.MemoryAccount).Flow
	target := ob.Target
	requestFlow := accountFlow
	ctx = session.ContextWithVisionFlow(ctx, strings.HasPrefix(requestFlow, vless.XRV))
	visionFlowActive := session.VisionFlowFromContext(ctx)
	h.preVisionFlow.Store(visionFlowActive)

	if h.testpre > 0 && h.reverse == nil {
		h.initpre.Do(func() {
			poolCap := int(h.testpre)
			if poolCap < 1 {
				poolCap = 1
			}
			h.preConns = make(chan *ConnExpire, poolCap)
			h.preConnsVFlow = make(chan *ConnExpire, poolCap)
			h.preCtx, h.preCancel = context.WithCancel(context.Background())
			for range h.testpre {
				h.preWG.Add(1)
				go func() {
					defer h.preWG.Done()
					defer func() {
						if r := recover(); r != nil {
							errors.LogError(h.preCtx, "panic in VLESS pre-connect goroutine: ", r, "\n", string(debug.Stack()))
						}
					}()
					backoff := time.Millisecond * 200
					for {
						select {
						case <-h.preCtx.Done():
							return
						default:
						}
						vf := h.preVisionFlow.Load()
						ctx := session.ContextWithVisionFlow(xctx.ContextWithID(h.preCtx, session.NewID()), vf)
						conn, err := dialer.Dial(ctx, rec.Destination)
						if err != nil {
							errors.LogWarningInner(ctx, err, "pre-connect failed")
							select {
							case <-h.preCtx.Done():
								return
							case <-time.After(backoff):
							}
							backoff = min(backoff*2, 30*time.Second)
							continue
						}
						backoff = time.Millisecond * 200
						pool := h.preConnPool(vf)
						select {
						case <-h.preCtx.Done():
							conn.Close()
							return
						default:
						}
						select {
						case pool <- &ConnExpire{Conn: conn, Expire: time.Now().Add(2 * time.Minute)}:
						default:
							// Keep workers adaptive when flow mode flips by dropping
							// stale/overflow preconnects instead of blocking on send.
							conn.Close()
						}
						select {
						case <-h.preCtx.Done():
							return
						case <-time.After(time.Millisecond * 200):
						}
					}
				}()
			}
		})
		prePool := h.preConnPool(visionFlowActive)
	preconnectLoop:
		for {
			var connTime *ConnExpire
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-h.preCtx.Done():
				return errors.New("closed handler").AtWarning()
			case connTime = <-prePool:
			case <-time.After(150 * time.Millisecond):
				// Preconnect is best-effort. Fall back to direct dial when the
				// matching pool is temporarily empty.
				break preconnectLoop
			}
			if connTime == nil {
				return errors.New("closed handler").AtWarning()
			}
			if time.Now().Before(connTime.Expire) {
				conn = connTime.Conn
				break
			}
			connTime.Conn.Close()
		}
	}

	if conn == nil {
		if err := retry.ExponentialBackoff(5, 200).On(func() error {
			var err error
			conn, err = dialer.Dial(ctx, rec.Destination)
			if err != nil {
				return err
			}
			return nil
		}); err != nil {
			return errors.New("failed to find an available destination").Base(err).AtWarning()
		}
	}
	defer conn.Close()

	ob.Conn = conn // for Vision's pre-connect

	iConn := stat.TryUnwrapStatsConn(conn)
	errors.LogInfo(ctx, "tunneling request to ", target, " via ", rec.Destination.NetAddr())

	if h.encryption != nil {
		var err error
		if conn, err = h.encryption.Handshake(conn); err != nil {
			return errors.New("ML-KEM-768 handshake failed").Base(err).AtInfo()
		}
	}

	command := protocol.RequestCommandTCP
	if target.Network == net.Network_UDP {
		command = protocol.RequestCommandUDP
	}
	if target.Address.Family().IsDomain() {
		switch target.Address.Domain() {
		case "v1.mux.cool":
			command = protocol.RequestCommandMux
		case "v1.rvs.cool":
			if target.Network != net.Network_Unknown {
				return errors.New("nice try baby").AtError()
			}
			command = protocol.RequestCommandRvs
		}
	}

	request := &protocol.RequestHeader{
		Version: encoding.Version,
		User:    rec.User,
		Command: command,
		Address: target.Address,
		Port:    target.Port,
	}

	account := request.User.Account.(*vless.MemoryAccount)

	requestAddons := &encoding.Addons{
		Flow: requestFlow,
	}

	var input *bytes.Reader
	var rawInput *bytes.Buffer
	allowUDP443 := false
	switch requestAddons.Flow {
	case vless.XRV + "-udp443":
		allowUDP443 = true
		requestAddons.Flow = requestAddons.Flow[:16]
		fallthrough
	case vless.XRV:
		ob.SetCanSpliceCopy(session.CopyGatePendingDetach)
		switch request.Command {
		case protocol.RequestCommandUDP:
			if !allowUDP443 && request.Port == 443 {
				return errors.New("XTLS rejected UDP/443 traffic").AtInfo()
			}
		case protocol.RequestCommandMux:
			fallthrough // let server break Mux connections that contain TCP requests
		case protocol.RequestCommandTCP, protocol.RequestCommandRvs:
			var t reflect.Type
			var p uintptr
			if commonConn, ok := conn.(*encryption.CommonConn); ok {
				if _, ok := commonConn.Conn.(*encryption.XorConn); ok || !proxy.IsRAWTransportWithoutSecurity(iConn) {
					ob.SetCopyGate(session.CopyGateForcedUserspace, session.CopyGateReasonSecurityGuard) // full-random xorConn / non-RAW transport / another securityConn should not be penetrated
				}
				t = reflect.TypeOf(commonConn).Elem()
				p = uintptr(unsafe.Pointer(commonConn))
			} else if tlsConn, ok := iConn.(*tls.Conn); ok {
				t = reflect.TypeOf(tlsConn.Conn).Elem()
				p = uintptr(unsafe.Pointer(tlsConn.Conn))
			} else if utlsConn, ok := iConn.(*tls.UConn); ok {
				t = reflect.TypeOf(utlsConn.Conn).Elem()
				p = uintptr(unsafe.Pointer(utlsConn.Conn))
			} else if realityConn, ok := iConn.(*reality.UConn); ok {
				t = reflect.TypeOf(realityConn.Conn).Elem()
				p = uintptr(unsafe.Pointer(realityConn.Conn))
			} else {
				handled, rustInput, rustRaw, err := getVisionBuffersForRustConn(iConn, requestAddons.Flow)
				if err != nil {
					return err
				}
				if handled {
					input = rustInput
					rawInput = rustRaw
				} else {
					return errors.New("XTLS only supports TLS and REALITY directly for now.").AtWarning()
				}
			}
			if t != nil {
				i, iOK := t.FieldByName("input")
				r, rOK := t.FieldByName("rawInput")
				if !iOK || !rOK {
					return errors.New("XTLS Vision internal layout mismatch for ", t.String(), ": missing input/rawInput fields").AtWarning()
				}
				input = (*bytes.Reader)(unsafe.Pointer(p + i.Offset))
				rawInput = (*bytes.Buffer)(unsafe.Pointer(p + r.Offset))
			}
		default:
			return errors.New("unknown VLESS request command: ", request.Command)
		}
	default:
		ob.SetCopyGate(session.CopyGateForcedUserspace, session.CopyGateReasonSecurityGuard)
	}

	var newCtx context.Context
	var newCancel context.CancelFunc
	if session.TimeoutOnlyFromContext(ctx) {
		newCtx, newCancel = context.WithCancel(context.Background())
	}

	sessionPolicy := h.policyManager.ForLevel(request.User.Level)
	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, func() {
		cancel()
		if newCancel != nil {
			newCancel()
		}
	}, sessionPolicy.Timeouts.ConnectionIdle)

	clientReader := link.Reader // .(*pipe.Reader)
	clientWriter := link.Writer // .(*pipe.Writer)
	muxGlobalID := [8]byte{}
	if shouldRewriteUDPToMux(request.Command, requestAddons.Flow, h.cone, request.Port) {
		muxGlobalID = xudp.GetGlobalID(ctx)
		request.Command = protocol.RequestCommandMux
		request.Address = net.DomainAddress("v1.mux.cool")
		request.Port = net.Port(666)
	}
	visionSharedParent := requestAddons.Flow == vless.XRV && isVisionSharedParentCommand(request.Command)
	trafficState := proxy.NewTrafficState(account.ID.Bytes())
	if visionSharedParent {
		ctx = proxy.ApplyVisionSharedParentCompat(ctx, trafficState)
		ob.SetCopyGate(session.CopyGateForcedUserspace, session.CopyGateReasonSecurityGuard)
	}
	var visionSignalCh chan session.VisionSignal
	if requestAddons.Flow == vless.XRV {
		if !visionSharedParent {
			visionSignalCh = make(chan session.VisionSignal, 1)
			ctx = session.ContextWithVisionSignal(ctx, visionSignalCh)
			ctx = session.ContextWithVisionTimestamps(ctx, &session.VisionTimestamps{})
		}
	}

	postRequest := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)

		bufferWriter := buf.NewBufferedWriter(buf.NewWriter(conn))
		if err := encoding.EncodeRequestHeader(bufferWriter, request, requestAddons); err != nil {
			return errors.New("failed to encode request header").Base(err).AtWarning()
		}

		// default: serverWriter := bufferWriter
		serverWriter := encoding.EncodeBodyAddons(bufferWriter, request, requestAddons, trafficState, true, ctx, conn, ob)
		if request.Command == protocol.RequestCommandMux && request.Port == 666 {
			serverWriter = xudp.NewPacketWriter(serverWriter, target, muxGlobalID)
		}
		timeoutReader, ok := clientReader.(buf.TimeoutReader)
		if ok {
			multiBuffer, err1 := timeoutReader.ReadMultiBufferTimeout(time.Millisecond * 500)
			if err1 == nil {
				if err := serverWriter.WriteMultiBuffer(multiBuffer); err != nil {
					return err // ...
				}
			} else if err1 != buf.ErrReadTimeout {
				return err1
			} else if requestAddons.Flow == vless.XRV {
				mb := make(buf.MultiBuffer, 1)
				errors.LogInfo(ctx, "Insert padding with empty content to camouflage VLESS header ", mb.Len())
				if err := serverWriter.WriteMultiBuffer(mb); err != nil {
					return err // ...
				}
			}
		} else {
			errors.LogDebug(ctx, "Reader is not timeout reader, will send out vless header separately from first payload")
		}
		// Flush; bufferWriter.WriteMultiBuffer now is bufferWriter.writer.WriteMultiBuffer
		if err := bufferWriter.SetBuffered(false); err != nil {
			return errors.New("failed to write A request payload").Base(err).AtWarning()
		}

		if requestAddons.Flow == vless.XRV {
			if tlsConn, ok := iConn.(*tls.Conn); ok {
				if tlsConn.ConnectionState().Version != gotls.VersionTLS13 {
					return errors.New(`failed to use `+requestAddons.Flow+`, found outer tls version `, tlsConn.ConnectionState().Version).AtWarning()
				}
			} else if utlsConn, ok := iConn.(*tls.UConn); ok {
				if utlsConn.ConnectionState().Version != utls.VersionTLS13 {
					return errors.New(`failed to use `+requestAddons.Flow+`, found outer tls version `, utlsConn.ConnectionState().Version).AtWarning()
				}
			}
		}
		err := buf.Copy(clientReader, serverWriter, buf.UpdateActivity(timer))
		if err != nil {
			return errors.New("failed to transfer request payload").Base(err).AtInfo()
		}

		// Indicates the end of request payload.
		switch requestAddons.Flow {
		default:
		}
		return nil
	}

	getResponse := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)

		responseAddons, err := encoding.DecodeResponseHeader(conn, request)
		if err != nil {
			return errors.New("failed to decode response header").Base(err).AtInfo()
		}

		// default: serverReader := buf.NewReader(conn)
		serverReader := encoding.DecodeBodyAddons(conn, request, responseAddons)
		if requestAddons.Flow == vless.XRV {
			serverReader = proxy.NewVisionReader(serverReader, trafficState, false, ctx, conn, visionSignalCh, input, rawInput, ob)
		}
		if request.Command == protocol.RequestCommandMux && request.Port == 666 {
			if requestAddons.Flow == vless.XRV {
				serverReader = xudp.NewPacketReader(&buf.BufferedReader{Reader: serverReader})
			} else {
				serverReader = xudp.NewPacketReader(conn)
			}
		}

		if requestAddons.Flow == vless.XRV {
			err = encoding.XtlsRead(serverReader, clientWriter, timer, conn, trafficState, false, ctx)
		} else {
			// from serverReader.ReadMultiBuffer to clientWriter.WriteMultiBuffer
			err = buf.Copy(serverReader, clientWriter, buf.UpdateActivity(timer))
		}

		if err != nil {
			return errors.New("failed to transfer response payload").Base(err).AtInfo()
		}

		return nil
	}

	if newCtx != nil {
		ctx = newCtx
	}

	if err := task.Run(ctx, postRequest, task.OnSuccess(getResponse, task.Close(clientWriter))); err != nil {
		return errors.New("connection ends").Base(err).AtInfo()
	}

	return nil
}

type Reverse struct {
	tag         string
	dispatcher  routing.Dispatcher
	ctx         context.Context
	handler     *Handler
	workers     []*reverse.BridgeWorker
	monitorTask *task.Periodic
}

func (r *Reverse) monitor() error {
	var activeWorkers []*reverse.BridgeWorker
	for _, w := range r.workers {
		if w.IsActive() {
			activeWorkers = append(activeWorkers, w)
		}
	}
	if len(activeWorkers) != len(r.workers) {
		r.workers = activeWorkers
	}

	var numConnections uint32
	var numWorker uint32
	for _, w := range r.workers {
		if w.IsActive() {
			numConnections += w.Connections()
			numWorker++
		}
	}
	if numWorker == 0 || numConnections/numWorker > 16 {
		reader1, writer1 := pipe.New(pipe.WithSizeLimit(2 * buf.Size))
		reader2, writer2 := pipe.New(pipe.WithSizeLimit(2 * buf.Size))
		link1 := &transport.Link{Reader: reader1, Writer: writer2}
		link2 := &transport.Link{Reader: reader2, Writer: writer1}
		w := &reverse.BridgeWorker{
			Tag:        r.tag,
			Dispatcher: r.dispatcher,
		}
		worker, err := mux.NewServerWorker(session.ContextWithIsReverseMux(r.ctx, true), w, link1)
		if err != nil {
			errors.LogWarningInner(r.ctx, err, "failed to create mux server worker")
			return nil
		}
		w.Worker = worker
		r.workers = append(r.workers, w)
		go func() {
			ctx := session.ContextWithOutbounds(r.ctx, []*session.Outbound{{
				Target: net.Destination{Address: net.DomainAddress("v1.rvs.cool")},
			}})
			r.handler.Process(ctx, link2, session.FullHandlerFromContext(ctx).(*proxyman.Handler))
			common.Interrupt(reader1)
			common.Interrupt(reader2)
		}()
	}
	return nil
}

func (r *Reverse) Start() error {
	return r.monitorTask.Start()
}

func (r *Reverse) Close() error {
	return r.monitorTask.Close()
}
