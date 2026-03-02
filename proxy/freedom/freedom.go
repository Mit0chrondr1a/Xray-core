package freedom

import (
	"context"
	"crypto/rand"
	goerrors "errors"
	"io"
	gonet "net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/pires/go-proxyproto"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/crypto"
	"github.com/xtls/xray-core/common/dice"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/platform"
	"github.com/xtls/xray-core/common/retry"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/common/utils"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

var useSplice bool

const (
	egressPenaltyArmThresholdDefault = 2
	egressPenaltyResetAfter          = 30 * time.Second
	egressPenaltyPruneAfter          = 2 * time.Minute
	egressMarkerLogInterval          = 30 * time.Second
	egressFastFailShadowEnvFlag      = "xray.freedom.egress.fastfail.shadow"
)

var (
	egressDialPenalty sync.Map // key: net.Destination.String(), value: *egressDialPenaltyState

	egressMarkerDialFailTotal         atomic.Uint64
	egressMarkerDialFailTimeout       atomic.Uint64
	egressMarkerDialFailNoRoute       atomic.Uint64
	egressMarkerDialFailRefused       atomic.Uint64
	egressMarkerPenaltyArm            atomic.Uint64
	egressMarkerFastFailCandidate     atomic.Uint64
	egressMarkerFastFailHit           atomic.Uint64
	egressMarkerPenaltyClear          atomic.Uint64
	egressMarkerLastSummaryUnix       atomic.Int64
	egressMarkerFastFailShadowEnabled atomic.Bool
)

type egressDialPenaltyState struct {
	mu                  sync.Mutex
	consecutiveFailures uint32
	blockedUntilUnix    int64
	blockedClass        string
	lastFailureUnix     int64
	lastFailureClass    string
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		h := new(Handler)
		if err := core.RequireFeatures(ctx, func(pm policy.Manager) error {
			return h.Init(config.(*Config), pm)
		}); err != nil {
			return nil, err
		}
		return h, nil
	}))
	const defaultFlagValue = "NOT_DEFINED_AT_ALL"
	value := platform.NewEnvFlag(platform.UseFreedomSplice).GetValue(func() string { return defaultFlagValue })
	switch value {
	case defaultFlagValue, "auto", "enable":
		useSplice = true
	}
	// Default to active fast-fail so repeatedly dead destinations don't keep
	// consuming retry slots and dial latency. Set shadow mode via:
	// xray.freedom.egress.fastfail.shadow=true
	egressMarkerFastFailShadowEnabled.Store(parseEgressFastFailShadowMode())
}

func parseEgressFastFailShadowMode() bool {
	raw := strings.TrimSpace(strings.ToLower(platform.NewEnvFlag(egressFastFailShadowEnvFlag).GetValue(func() string { return "" })))
	switch raw {
	case "", "0", "false", "f", "no", "n", "off", "disable", "disabled", "enforce", "active":
		return false
	case "1", "true", "t", "yes", "y", "on", "enable", "enabled", "shadow":
		return true
	default:
		v, err := strconv.ParseBool(raw)
		return err == nil && v
	}
}

// Handler handles Freedom connections.
type Handler struct {
	policyManager policy.Manager
	config        *Config
}

// Init initializes the Handler with necessary parameters.
func (h *Handler) Init(config *Config, pm policy.Manager) error {
	h.config = config
	h.policyManager = pm
	return nil
}

func (h *Handler) policy() policy.Session {
	p := h.policyManager.ForLevel(h.config.UserLevel)
	return p
}

func isValidAddress(addr *net.IPOrDomain) bool {
	if addr == nil {
		return false
	}

	a := addr.AsAddress()
	return a != net.AnyIP && a != net.AnyIPv6
}

func classifyEgressDialFailure(err error) (string, bool) {
	if err == nil {
		return "", false
	}
	cause := errors.Cause(err)
	if cause == nil {
		cause = err
	}
	if goerrors.Is(cause, context.Canceled) || goerrors.Is(cause, context.DeadlineExceeded) {
		return "", false
	}

	msg := strings.ToLower(cause.Error())
	if strings.Contains(msg, "no route to host") ||
		goerrors.Is(cause, syscall.ENETUNREACH) ||
		goerrors.Is(cause, syscall.EHOSTUNREACH) ||
		goerrors.Is(cause, syscall.ENETDOWN) ||
		goerrors.Is(cause, syscall.EHOSTDOWN) {
		return "no_route", true
	}
	if strings.Contains(msg, "connection refused") || goerrors.Is(cause, syscall.ECONNREFUSED) {
		return "refused", true
	}

	if netErr, ok := cause.(interface{ Timeout() bool }); ok && netErr.Timeout() {
		return "timeout", true
	}
	if strings.Contains(msg, "connection timed out") || strings.Contains(msg, "i/o timeout") {
		return "timeout", true
	}
	return "", false
}

func egressPenaltyArmThreshold(class string) uint32 {
	if class == "refused" {
		return 1
	}
	return egressPenaltyArmThresholdDefault
}

func egressPenaltyDelayForFailure(class string, consecutive uint32) time.Duration {
	threshold := egressPenaltyArmThreshold(class)
	if consecutive < threshold {
		return 0
	}

	switch class {
	case "refused":
		switch consecutive - threshold {
		case 0:
			return 1 * time.Second
		case 1:
			return 2 * time.Second
		case 2:
			return 4 * time.Second
		default:
			return 6 * time.Second
		}
	case "no_route":
		switch consecutive - threshold {
		case 0:
			return 3 * time.Second
		case 1:
			return 6 * time.Second
		case 2:
			return 12 * time.Second
		default:
			return 20 * time.Second
		}
	default:
		switch consecutive - threshold {
		case 0:
			return 2 * time.Second
		case 1:
			return 4 * time.Second
		case 2:
			return 8 * time.Second
		default:
			return 12 * time.Second
		}
	}
}

func (s *egressDialPenaltyState) shouldFastFail(nowUnix int64) (time.Duration, bool, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.blockedUntilUnix <= nowUnix {
		return 0, false, ""
	}
	return time.Duration(s.blockedUntilUnix - nowUnix), true, s.blockedClass
}

func (s *egressDialPenaltyState) noteFailure(nowUnix int64, class string) (time.Duration, bool, uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.lastFailureUnix == 0 || nowUnix-s.lastFailureUnix > int64(egressPenaltyResetAfter) {
		s.consecutiveFailures = 0
	}
	if s.lastFailureClass != "" && s.lastFailureClass != class {
		s.consecutiveFailures = 0
	}

	s.lastFailureUnix = nowUnix
	s.lastFailureClass = class
	s.consecutiveFailures++
	delay := egressPenaltyDelayForFailure(class, s.consecutiveFailures)
	if delay <= 0 {
		return 0, false, s.consecutiveFailures
	}

	armed := s.blockedUntilUnix <= nowUnix
	s.blockedUntilUnix = nowUnix + int64(delay)
	s.blockedClass = class
	return delay, armed, s.consecutiveFailures
}

func (s *egressDialPenaltyState) shouldPrune(nowUnix int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.blockedUntilUnix > nowUnix {
		return false
	}
	if s.lastFailureUnix == 0 {
		return true
	}
	return nowUnix-s.lastFailureUnix > int64(egressPenaltyPruneAfter)
}

func getEgressDialPenaltyState(dest net.Destination) *egressDialPenaltyState {
	key := dest.String()
	if s, ok := egressDialPenalty.Load(key); ok {
		return s.(*egressDialPenaltyState)
	}
	state := &egressDialPenaltyState{}
	actual, _ := egressDialPenalty.LoadOrStore(key, state)
	return actual.(*egressDialPenaltyState)
}

func shouldFastFailEgressDial(dest net.Destination) (time.Duration, bool, string) {
	state, ok := egressDialPenalty.Load(dest.String())
	if !ok {
		return 0, false, ""
	}
	return state.(*egressDialPenaltyState).shouldFastFail(time.Now().UnixNano())
}

func noteEgressDialFailure(dest net.Destination, class string) (time.Duration, bool, uint32) {
	return getEgressDialPenaltyState(dest).noteFailure(time.Now().UnixNano(), class)
}

func clearEgressDialPenalty(dest net.Destination) bool {
	_, existed := egressDialPenalty.LoadAndDelete(dest.String())
	return existed
}

func pruneAndCountEgressDialPenalty(nowUnix int64) int {
	tracked := 0
	egressDialPenalty.Range(func(key, value any) bool {
		state, ok := value.(*egressDialPenaltyState)
		if !ok {
			egressDialPenalty.Delete(key)
			return true
		}
		if state.shouldPrune(nowUnix) {
			egressDialPenalty.Delete(key)
			return true
		}
		tracked++
		return true
	})
	return tracked
}

func maybeLogEgressDialSummary(ctx context.Context) {
	nowUnix := time.Now().Unix()
	last := egressMarkerLastSummaryUnix.Load()
	if nowUnix-last < int64(egressMarkerLogInterval/time.Second) {
		return
	}
	if !egressMarkerLastSummaryUnix.CompareAndSwap(last, nowUnix) {
		return
	}

	tracked := pruneAndCountEgressDialPenalty(time.Now().UnixNano())
	errors.LogInfo(ctx, "proxy markers[kind=egress]: ",
		"dial_fail_total=", egressMarkerDialFailTotal.Load(),
		" dial_fail_timeout=", egressMarkerDialFailTimeout.Load(),
		" dial_fail_no_route=", egressMarkerDialFailNoRoute.Load(),
		" dial_fail_refused=", egressMarkerDialFailRefused.Load(),
		" penalty_arm=", egressMarkerPenaltyArm.Load(),
		" fast_fail_candidate=", egressMarkerFastFailCandidate.Load(),
		" fast_fail_hit=", egressMarkerFastFailHit.Load(),
		" penalty_clear=", egressMarkerPenaltyClear.Load(),
		" shadow_mode=", egressMarkerFastFailShadowEnabled.Load(),
		" tracked=", tracked)
}

// Process implements proxy.Outbound.
func (h *Handler) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbounds := session.OutboundsFromContext(ctx)
	if len(outbounds) == 0 {
		return errors.New("no outbound metadata in context")
	}
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() {
		return errors.New("target not specified.")
	}
	ob.Name = "freedom"
	ob.SetCanSpliceCopy(1)
	inbound := session.InboundFromContext(ctx)

	destination := ob.Target
	origTargetAddr := ob.OriginalTarget.Address
	if origTargetAddr == nil {
		origTargetAddr = ob.Target.Address
	}
	dialer.SetOutboundGateway(ctx, ob)
	outGateway := ob.Gateway
	UDPOverride := net.UDPDestination(nil, 0)
	if h.config.DestinationOverride != nil {
		server := h.config.DestinationOverride.Server
		if isValidAddress(server.Address) {
			destination.Address = server.Address.AsAddress()
			UDPOverride.Address = destination.Address
		}
		if server.Port != 0 {
			destination.Port = net.Port(server.Port)
			UDPOverride.Port = destination.Port
		}
	}
	proxy.RecordPipelineFlowMix(ctx, destination.Network, session.AllowedNetworkFromContext(ctx))

	input := link.Reader
	output := link.Writer

	var conn stat.Connection
	var fastFailErr error
	err := retry.ExponentialBackoff(5, 100).On(func() error {
		dialDest := destination
		if h.config.DomainStrategy.HasStrategy() && dialDest.Address.Family().IsDomain() {
			strategy := h.config.DomainStrategy
			if destination.Network == net.Network_UDP && origTargetAddr != nil && outGateway == nil {
				strategy = strategy.GetDynamicStrategy(origTargetAddr.Family())
			}
			ips, err := internet.LookupForIP(dialDest.Address.Domain(), strategy, outGateway)
			if err != nil {
				errors.LogDebugInner(ctx, err, "failed to get IP address for domain ", dialDest.Address.Domain())
				if h.config.DomainStrategy.ForceIP() {
					return err
				}
			} else {
				dialDest = net.Destination{
					Network: dialDest.Network,
					Address: net.IPAddress(ips[dice.Roll(len(ips))]),
					Port:    dialDest.Port,
				}
				errors.LogDebug(ctx, "dialing to ", dialDest)
			}
		}

		if delay, blocked, class := shouldFastFailEgressDial(dialDest); blocked {
			// Shadow mode: mark would-have-fast-failed destinations but continue
			// normal retry/dial behavior to avoid reducing resilience.
			egressMarkerFastFailCandidate.Add(1)
			if !egressMarkerFastFailShadowEnabled.Load() {
				egressMarkerFastFailHit.Add(1)
				fastFailErr = errors.New("[kind=egress.fast_fail] destination ", dialDest, ", class=", class, ", cooldown=", delay)
				maybeLogEgressDialSummary(ctx)
				return nil
			}
		}

		rawConn, err := dialer.Dial(ctx, dialDest)
		if err != nil {
			if class, ok := classifyEgressDialFailure(err); ok {
				egressMarkerDialFailTotal.Add(1)
				switch class {
				case "timeout":
					egressMarkerDialFailTimeout.Add(1)
				case "no_route":
					egressMarkerDialFailNoRoute.Add(1)
				case "refused":
					egressMarkerDialFailRefused.Add(1)
				}
				delay, armed, consecutive := noteEgressDialFailure(dialDest, class)
				if armed {
					egressMarkerPenaltyArm.Add(1)
					errors.LogWarning(ctx, "[kind=egress.penalty_arm] destination ", dialDest, ", class=", class, ", consecutive=", consecutive, ", cooldown=", delay)
				}
				maybeLogEgressDialSummary(ctx)
			} else if clearEgressDialPenalty(dialDest) {
				egressMarkerPenaltyClear.Add(1)
			}
			return err
		}
		if clearEgressDialPenalty(dialDest) {
			egressMarkerPenaltyClear.Add(1)
		}

		if h.config.ProxyProtocol > 0 && h.config.ProxyProtocol <= 2 {
			version := byte(h.config.ProxyProtocol)
			srcAddr := inbound.Source.RawNetAddr()
			dstAddr := rawConn.RemoteAddr()
			header := proxyproto.HeaderProxyFromAddrs(version, srcAddr, dstAddr)
			if _, err = header.WriteTo(rawConn); err != nil {
				rawConn.Close()
				return err
			}
		}

		conn = rawConn
		return nil
	})
	if fastFailErr != nil {
		return errors.New("failed to open connection to ", destination).Base(fastFailErr)
	}
	if err != nil {
		return errors.New("failed to open connection to ", destination).Base(err)
	}
	defer conn.Close()
	errors.LogDebug(ctx, "connection opened to ", destination, ", local endpoint ", conn.LocalAddr(), ", remote endpoint ", conn.RemoteAddr())

	var newCtx context.Context
	var newCancel context.CancelFunc
	if session.TimeoutOnlyFromContext(ctx) {
		newCtx, newCancel = context.WithCancel(context.Background())
	}

	plcy := h.policy()
	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, func() {
		cancel()
		if newCancel != nil {
			newCancel()
		}
	}, plcy.Timeouts.ConnectionIdle)

	requestDone := func() error {
		defer timer.SetTimeout(plcy.Timeouts.DownlinkOnly)

		var writer buf.Writer
		if destination.Network == net.Network_TCP {
			if h.config.Fragment != nil {
				errors.LogDebug(ctx, "FRAGMENT", h.config.Fragment.PacketsFrom, h.config.Fragment.PacketsTo, h.config.Fragment.LengthMin, h.config.Fragment.LengthMax,
					h.config.Fragment.IntervalMin, h.config.Fragment.IntervalMax, h.config.Fragment.MaxSplitMin, h.config.Fragment.MaxSplitMax)
				writer = buf.NewWriter(&FragmentWriter{
					fragment: h.config.Fragment,
					writer:   conn,
				})
			} else {
				writer = buf.NewWriter(conn)
			}
		} else {
			writer = NewPacketWriter(conn, h, UDPOverride, destination)
			if h.config.Noises != nil {
				errors.LogDebug(ctx, "NOISE", h.config.Noises)
				writer = &NoisePacketWriter{
					Writer:      writer,
					noises:      h.config.Noises,
					firstWrite:  true,
					UDPOverride: UDPOverride,
					remoteAddr:  net.DestinationFromAddr(conn.RemoteAddr()).Address,
				}
			}
		}

		if err := buf.Copy(input, writer, buf.UpdateActivity(timer)); err != nil {
			if isExpectedRequestReadError(err) {
				errors.LogDebugInner(ctx, err, "freedom: request stream closed by peer")
				return nil
			}
			return errors.New("failed to process request").Base(err)
		}

		return nil
	}

	responseDone := func() error {
		defer timer.SetTimeout(plcy.Timeouts.UplinkOnly)
		if destination.Network == net.Network_TCP && useSplice && proxy.IsRAWTransportWithoutSecurity(conn) { // it would be tls conn in special use case of MITM, we need to let link handle traffic
			var writeConn net.Conn
			var inTimer *signal.ActivityTimer
			if inbound := session.InboundFromContext(ctx); inbound != nil && inbound.Conn != nil {
				writeConn = inbound.Conn
				inTimer = inbound.Timer
			}
			return proxy.CopyRawConnIfExist(ctx, conn, writeConn, link.Writer, timer, inTimer)
		}
		var reader buf.Reader
		if destination.Network == net.Network_TCP {
			reader = buf.NewReader(conn)
		} else {
			reader = NewPacketReader(conn, UDPOverride, destination)
		}
		if err := buf.Copy(reader, output, buf.UpdateActivity(timer)); err != nil {
			return errors.New("failed to process response").Base(err)
		}
		return nil
	}

	if newCtx != nil {
		ctx = newCtx
	}

	if err := task.Run(ctx, requestDone, task.OnSuccess(responseDone, task.Close(output))); err != nil {
		return errors.New("connection ends").Base(err)
	}

	return nil
}

func isExpectedRequestReadError(err error) bool {
	if err == nil || !buf.IsReadError(err) {
		return false
	}
	cause := errors.Cause(err)
	if cause == nil {
		return false
	}
	if goerrors.Is(cause, io.EOF) ||
		goerrors.Is(cause, io.ErrClosedPipe) ||
		goerrors.Is(cause, context.Canceled) ||
		goerrors.Is(cause, gonet.ErrClosed) {
		return true
	}
	if isExpectedStreamCancel(cause) {
		return true
	}

	return goerrors.Is(cause, syscall.ECONNRESET) ||
		goerrors.Is(cause, syscall.EPIPE) ||
		goerrors.Is(cause, syscall.ENOTCONN) ||
		goerrors.Is(cause, syscall.ESHUTDOWN) ||
		goerrors.Is(cause, syscall.EIO)
}

func isExpectedStreamCancel(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "stream error") && strings.Contains(msg, "cancel")
}

func NewPacketReader(conn net.Conn, UDPOverride net.Destination, DialDest net.Destination) buf.Reader {
	iConn := conn
	statConn, ok := iConn.(*stat.CounterConnection)
	if ok {
		iConn = statConn.Connection
	}
	var counter stats.Counter
	if statConn != nil {
		counter = statConn.ReadCounter
	}
	if c, ok := iConn.(*internet.PacketConnWrapper); ok {
		isOverridden := false
		if UDPOverride.Address != nil || UDPOverride.Port != 0 {
			isOverridden = true
		}

		return &PacketReader{
			PacketConnWrapper: c,
			Counter:           counter,
			IsOverridden:      isOverridden,
			InitUnchangedAddr: DialDest.Address,
			InitChangedAddr:   net.DestinationFromAddr(conn.RemoteAddr()).Address,
		}
	}
	return &buf.PacketReader{Reader: conn}
}

type PacketReader struct {
	*internet.PacketConnWrapper
	stats.Counter
	IsOverridden      bool
	InitUnchangedAddr net.Address
	InitChangedAddr   net.Address
}

func (r *PacketReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	b := buf.New()
	b.Resize(0, buf.Size)
	n, d, err := r.PacketConnWrapper.ReadFrom(b.Bytes())
	if err != nil {
		b.Release()
		return nil, err
	}
	b.Resize(0, int32(n))
	// if udp dest addr is changed, we are unable to get the correct src addr
	// so we don't attach src info to udp packet, break cone behavior, assuming the dial dest is the expected scr addr
	if !r.IsOverridden {
		address := net.IPAddress(d.(*net.UDPAddr).IP)
		if r.InitChangedAddr == address {
			address = r.InitUnchangedAddr
		}
		b.UDP = &net.Destination{
			Address: address,
			Port:    net.Port(d.(*net.UDPAddr).Port),
			Network: net.Network_UDP,
		}
	}
	if r.Counter != nil {
		r.Counter.Add(int64(n))
	}
	return buf.MultiBuffer{b}, nil
}

// DialDest means the dial target used in the dialer when creating conn
func NewPacketWriter(conn net.Conn, h *Handler, UDPOverride net.Destination, DialDest net.Destination) buf.Writer {
	iConn := conn
	statConn, ok := iConn.(*stat.CounterConnection)
	if ok {
		iConn = statConn.Connection
	}
	var counter stats.Counter
	if statConn != nil {
		counter = statConn.WriteCounter
	}
	if c, ok := iConn.(*internet.PacketConnWrapper); ok {
		// If DialDest is a domain, it will be resolved in dialer
		// check this behavior and add it to map
		resolvedUDPAddr := utils.NewTypedSyncMap[string, net.Address]()
		if DialDest.Address.Family().IsDomain() {
			resolvedUDPAddr.Store(DialDest.Address.Domain(), net.DestinationFromAddr(conn.RemoteAddr()).Address)
		}
		return &PacketWriter{
			PacketConnWrapper: c,
			Counter:           counter,
			Handler:           h,
			UDPOverride:       UDPOverride,
			ResolvedUDPAddr:   resolvedUDPAddr,
			LocalAddr:         net.DestinationFromAddr(conn.LocalAddr()).Address,
		}

	}
	return &buf.SequentialWriter{Writer: conn}
}

type PacketWriter struct {
	*internet.PacketConnWrapper
	stats.Counter
	*Handler
	UDPOverride net.Destination

	// Dest of udp packets might be a domain, we will resolve them to IP
	// But resolver will return a random one if the domain has many IPs
	// Resulting in these packets being sent to many different IPs randomly
	// So, cache and keep the resolve result
	ResolvedUDPAddr *utils.TypedSyncMap[string, net.Address]
	LocalAddr       net.Address
}

func (w *PacketWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	for {
		mb2, b := buf.SplitFirst(mb)
		mb = mb2
		if b == nil {
			break
		}
		var n int
		var err error
		if b.UDP != nil {
			if w.UDPOverride.Address != nil {
				b.UDP.Address = w.UDPOverride.Address
			}
			if w.UDPOverride.Port != 0 {
				b.UDP.Port = w.UDPOverride.Port
			}
			if b.UDP.Address.Family().IsDomain() {
				if ip, ok := w.ResolvedUDPAddr.Load(b.UDP.Address.Domain()); ok {
					b.UDP.Address = ip
				} else {
					ShouldUseSystemResolver := true
					if w.Handler.config.DomainStrategy.HasStrategy() {
						ips, err := internet.LookupForIP(b.UDP.Address.Domain(), w.Handler.config.DomainStrategy, w.LocalAddr)
						if err != nil {
							// drop packet if resolve failed when forceIP
							if w.Handler.config.DomainStrategy.ForceIP() {
								b.Release()
								continue
							}
						} else {
							ip = net.IPAddress(ips[dice.Roll(len(ips))])
							ShouldUseSystemResolver = false
						}
					}
					if ShouldUseSystemResolver {
						udpAddr, err := net.ResolveUDPAddr("udp", b.UDP.NetAddr())
						if err != nil {
							b.Release()
							continue
						} else {
							ip = net.IPAddress(udpAddr.IP)
						}
					}
					if ip != nil {
						b.UDP.Address, _ = w.ResolvedUDPAddr.LoadOrStore(b.UDP.Address.Domain(), ip)
					}
				}
			}
			destAddr := b.UDP.RawNetAddr()
			if destAddr == nil {
				b.Release()
				continue
			}
			n, err = w.PacketConnWrapper.WriteTo(b.Bytes(), destAddr)
		} else {
			n, err = w.PacketConnWrapper.Write(b.Bytes())
		}
		b.Release()
		if err != nil {
			buf.ReleaseMulti(mb)
			return err
		}
		if w.Counter != nil {
			w.Counter.Add(int64(n))
		}
	}
	return nil
}

type NoisePacketWriter struct {
	buf.Writer
	noises      []*Noise
	firstWrite  bool
	UDPOverride net.Destination
	remoteAddr  net.Address
}

// MultiBuffer writer with Noise before first packet
func (w *NoisePacketWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if w.firstWrite {
		w.firstWrite = false
		//Do not send Noise for dns requests(just to be safe)
		if w.UDPOverride.Port == 53 {
			return w.Writer.WriteMultiBuffer(mb)
		}
		var noise []byte
		var err error
		if w.remoteAddr.Family().IsDomain() {
			return errors.New("remoteAddr is unexpectedly a domain")
		}
		for _, n := range w.noises {
			switch n.ApplyTo {
			case "ipv4":
				if w.remoteAddr.Family().IsIPv6() {
					continue
				}
			case "ipv6":
				if w.remoteAddr.Family().IsIPv4() {
					continue
				}
			case "ip":
			default:
				return errors.New("invalid noise applyTo value: ", n.ApplyTo)
			}
			//User input string or base64 encoded string or hex string
			if n.Packet != nil {
				noise = n.Packet
			} else {
				//Random noise
				noise, err = GenerateRandomBytes(crypto.RandBetween(int64(n.LengthMin),
					int64(n.LengthMax)))
			}
			if err != nil {
				return err
			}
			err = w.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(noise)})
			if err != nil {
				return err
			}

			if n.DelayMin != 0 || n.DelayMax != 0 {
				time.Sleep(time.Duration(crypto.RandBetween(int64(n.DelayMin), int64(n.DelayMax))) * time.Millisecond)
			}
		}

	}
	return w.Writer.WriteMultiBuffer(mb)
}

type FragmentWriter struct {
	fragment *Fragment
	writer   io.Writer
	count    uint64
}

func (f *FragmentWriter) Write(b []byte) (int, error) {
	f.count++

	if f.fragment.PacketsFrom == 0 && f.fragment.PacketsTo == 1 {
		if f.count != 1 || len(b) <= 5 || b[0] != 22 {
			return f.writer.Write(b)
		}
		recordLen := 5 + ((int(b[3]) << 8) | int(b[4]))
		if len(b) < recordLen { // maybe already fragmented somehow
			return f.writer.Write(b)
		}
		data := b[5:recordLen]
		buff := make([]byte, 2048)
		var hello []byte
		maxSplit := crypto.RandBetween(int64(f.fragment.MaxSplitMin), int64(f.fragment.MaxSplitMax))
		var splitNum int64
		for from := 0; ; {
			to := from + int(crypto.RandBetween(int64(f.fragment.LengthMin), int64(f.fragment.LengthMax)))
			splitNum++
			if to > len(data) || (maxSplit > 0 && splitNum >= maxSplit) {
				to = len(data)
			}
			l := to - from
			if 5+l > len(buff) {
				buff = make([]byte, 5+l)
			}
			copy(buff[:3], b)
			copy(buff[5:], data[from:to])
			from = to
			buff[3] = byte(l >> 8)
			buff[4] = byte(l)
			if f.fragment.IntervalMax == 0 { // combine fragmented tlshello if interval is 0
				hello = append(hello, buff[:5+l]...)
			} else {
				_, err := f.writer.Write(buff[:5+l])
				time.Sleep(time.Duration(crypto.RandBetween(int64(f.fragment.IntervalMin), int64(f.fragment.IntervalMax))) * time.Millisecond)
				if err != nil {
					return 0, err
				}
			}
			if from == len(data) {
				if len(hello) > 0 {
					_, err := f.writer.Write(hello)
					if err != nil {
						return 0, err
					}
				}
				if len(b) > recordLen {
					n, err := f.writer.Write(b[recordLen:])
					if err != nil {
						return recordLen + n, err
					}
				}
				return len(b), nil
			}
		}
	}

	if f.fragment.PacketsFrom != 0 && (f.count < f.fragment.PacketsFrom || f.count > f.fragment.PacketsTo) {
		return f.writer.Write(b)
	}
	maxSplit := crypto.RandBetween(int64(f.fragment.MaxSplitMin), int64(f.fragment.MaxSplitMax))
	var splitNum int64
	for from := 0; ; {
		to := from + int(crypto.RandBetween(int64(f.fragment.LengthMin), int64(f.fragment.LengthMax)))
		splitNum++
		if to > len(b) || (maxSplit > 0 && splitNum >= maxSplit) {
			to = len(b)
		}
		n, err := f.writer.Write(b[from:to])
		from += n
		if err != nil {
			return from, err
		}
		time.Sleep(time.Duration(crypto.RandBetween(int64(f.fragment.IntervalMin), int64(f.fragment.IntervalMax))) * time.Millisecond)
		if from >= len(b) {
			return from, nil
		}
	}
}

func GenerateRandomBytes(n int64) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}

	return b, nil
}
