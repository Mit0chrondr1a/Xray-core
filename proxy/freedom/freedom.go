package freedom

import (
	"context"
	"crypto/rand"
	goerrors "errors"
	"io"
	gonet "net"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/pires/go-proxyproto"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/crypto"
	"github.com/xtls/xray-core/common/dice"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/geodata"
	"github.com/xtls/xray-core/common/log"
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

var (
	useSplice               atomic.Bool
	allNetworks             [8]bool
	defaultBlockPrivateRule *FinalRule
	defaultBlockAllRule     *FinalRule
)

func reloadEnvSettings() error {
	const defaultFlagValue = "NOT_DEFINED_AT_ALL"
	value := platform.NewEnvFlag(platform.UseFreedomSplice).GetValue(func() string { return defaultFlagValue })
	enabled := false
	switch value {
	case defaultFlagValue, "auto", "enable":
		enabled = true
	}
	useSplice.Store(enabled)
	return nil
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		h := new(Handler)
		if streamSettings, ok := session.StreamSettingsFromContext(ctx).(*internet.MemoryStreamConfig); ok && streamSettings.SocketSettings != nil {
			h.resolveStrategy = streamSettings.SocketSettings.DomainStrategy
			h.usesDialerProxy = len(streamSettings.SocketSettings.DialerProxy) > 0
		}
		if err := core.RequireFeatures(ctx, func(pm policy.Manager) error {
			return h.Init(config.(*Config), pm)
		}); err != nil {
			return nil, err
		}
		return h, nil
	}))

	platform.RegisterEnvReload(reloadEnvSettings)

	for i := range allNetworks {
		allNetworks[i] = true
	}

	defaultBlockPrivateRule = &FinalRule{
		action:   RuleAction_Block,
		network:  allNetworks,
		ip:       geodata.GetPrivateIPMatcher(),
		logLevel: log.Severity_Warning.Enum(),
	}

	defaultBlockAllRule = &FinalRule{
		action:   RuleAction_Block,
		network:  allNetworks,
		logLevel: log.Severity_Warning.Enum(),
	}
}

type FinalRule struct {
	action   RuleAction
	network  [8]bool
	port     net.MemoryPortList
	ip       geodata.IPMatcher
	delay    *Range
	logLevel *log.Severity
}

// Handler handles Freedom connections.
type Handler struct {
	policyManager   policy.Manager
	config          *Config
	finalRules      []*FinalRule
	resolveStrategy internet.DomainStrategy
	usesDialerProxy bool
}

func buildFinalRule(config *FinalRuleConfig) (*FinalRule, error) {
	rule := &FinalRule{
		action:   config.GetAction(),
		delay:    config.GetDelay(),
		logLevel: config.LogLevel,
	}

	if len(config.Networks) == 0 {
		rule.network = allNetworks
	} else {
		for _, network := range config.Networks {
			rule.network[int(network)] = true
		}
	}

	if config.PortList != nil {
		rule.port = net.PortListFromProto(config.PortList)
	}

	if len(config.Ip) > 0 {
		matcher, err := geodata.IPReg.BuildIPMatcher(config.Ip)
		if err != nil {
			return nil, err
		}
		rule.ip = matcher
	}

	return rule, nil
}

func (r *FinalRule) matchNetwork(network net.Network) bool {
	return r.network[int(network)]
}

func (r *FinalRule) matchPort(port net.Port) bool {
	if len(r.port) == 0 {
		return true
	}
	return r.port.Contains(port)
}

func (r *FinalRule) matchIP(addr net.Address) bool {
	if r.ip == nil {
		return true
	}
	return addr != nil && addr.Family().IsIP() && r.ip.Match(addr.IP())
}

func (r *FinalRule) Apply(network net.Network, address net.Address, port net.Port) bool {
	if !r.matchNetwork(network) {
		return false
	}
	if !r.matchPort(port) {
		return false
	}
	return r.matchIP(address)
}

func getDefaultFinalRule(inbound *session.Inbound) *FinalRule {
	if inbound == nil {
		return nil
	}
	switch inbound.Name {
	case "vless-reverse":
		return defaultBlockAllRule
	case "vless", "vmess", "trojan", "hysteria", "wireguard", "masque":
		return defaultBlockPrivateRule
	default:
		if strings.HasPrefix(inbound.Name, "shadowsocks") {
			return defaultBlockPrivateRule
		}
	}
	return nil
}

func (h *Handler) matchFinalRule(network net.Network, address net.Address, port net.Port, defaultRule *FinalRule) *FinalRule {
	for _, rule := range h.finalRules {
		if rule.Apply(network, address, port) {
			return rule
		}
	}
	if defaultRule != nil && defaultRule.Apply(network, address, port) {
		return defaultRule
	}
	return nil
}

type dnsUplinkDiagnostic struct {
	startedAt       time.Time
	destination     net.Destination
	flowClass       string
	dnsPlane        string
	firstWriteNs    atomic.Int64
	lastWriteNs     atomic.Int64
	totalBytes      atomic.Int64
	firstResponseNs atomic.Int64
	lastResponseNs  atomic.Int64
	responseBytes   atomic.Int64
}

type visionUplinkDiagnostic struct {
	startedAt    time.Time
	destination  net.Destination
	firstWriteNs int64
	lastWriteNs  int64
	totalBytes   int64
	timings      *session.FlowTimings
}

type dnsUplinkDiagnosticWriter struct {
	Writer buf.Writer
	dns    *dnsUplinkDiagnostic
	vision *visionUplinkDiagnostic
	guard  *udpFirstResponseGuard
}

type dnsResponseDiagnosticWriter struct {
	Writer  buf.Writer
	dns     *dnsUplinkDiagnostic
	timings *session.FlowTimings
}

const (
	dnsUDPFirstResponseTimeout      = 1500 * time.Millisecond
	dnsUDPFirstResponseMaxTotalWait = 1800 * time.Millisecond
)

var errDNSUDPFirstResponseTimeout = goerrors.New("dns_udp_first_response_timeout")

func (w *dnsUplinkDiagnosticWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	hadPayload := !mb.IsEmpty()
	if w.dns != nil {
		w.dns.observeWrite(int(mb.Len()))
	}
	if w.vision != nil {
		w.vision.observeWrite(int(mb.Len()))
	}
	if err := w.Writer.WriteMultiBuffer(mb); err != nil {
		return err
	}
	if hadPayload && w.guard != nil {
		w.guard.ObserveWrite()
	}
	return nil
}

func (w *dnsResponseDiagnosticWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if w.dns != nil {
		w.dns.observeResponse(int(mb.Len()))
	}
	if w.timings != nil && mb.Len() > 0 {
		w.timings.StoreFirstResponse(time.Now().UnixNano())
	}
	return w.Writer.WriteMultiBuffer(mb)
}

// Init initializes the Handler with necessary parameters.
func (h *Handler) Init(config *Config, pm policy.Manager) error {
	h.config = config
	h.policyManager = pm
	if h.usesDialerProxy { // freedom is not the final outbound, final rules do not apply
		if len(config.FinalRules) > 0 {
			errors.LogWarning(context.Background(), `The "finalRules" setting is ignored when "sockopt.dialerProxy" is set, since freedom is not the final outbound.`)
		}
		return nil
	}
	h.finalRules = make([]*FinalRule, 0, len(config.FinalRules))
	for _, rc := range config.FinalRules {
		rule, err := buildFinalRule(rc)
		if err != nil {
			return errors.New("failed to build final rule").Base(err)
		}
		h.finalRules = append(h.finalRules, rule)
	}
	return nil
}

func (h *Handler) policy() policy.Session {
	p := h.policyManager.ForLevel(h.config.UserLevel)
	return p
}

func (r *FinalRule) blockDuration() time.Duration {
	min := uint64(30)
	max := uint64(90)
	if r.delay != nil {
		min = r.delay.Min
		max = r.delay.Max
	}
	span := max - min
	if max < min {
		span = min - max
	}
	return time.Duration(min+uint64(dice.Roll(int(span+1)))) * time.Second
}

func (r *FinalRule) log(ctx context.Context, msg ...interface{}) {
	level := log.Severity_Info
	if r.logLevel != nil {
		level = *r.logLevel
	}
	switch level {
	case log.Severity_Debug:
		errors.LogDebug(ctx, msg...)
	case log.Severity_Info:
		errors.LogInfo(ctx, msg...)
	case log.Severity_Warning:
		errors.LogWarning(ctx, msg...)
	case log.Severity_Error:
		errors.LogError(ctx, msg...)
	}
}

func (h *Handler) blackhole(ctx context.Context, input buf.Reader, output buf.Writer, rule *FinalRule, dest *net.Destination) error {
	delay := rule.blockDuration()
	rule.log(ctx, "target blocked by a finalrule: ", *dest, ", blackholing connection for ", delay)
	defer common.Close(output)
	done := make(chan struct{})
	go func() { // a DispatchLink inbound's reader ignores Interrupt, so don't wait for this copy
		_ = buf.Copy(input, buf.Discard)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(delay):
		common.Interrupt(input)
		common.Interrupt(output)
		rule.log(ctx, "closed blackholed connection to blocked target: ", *dest)
	}
	return nil
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

func isDNSDest(dest net.Destination) bool {
	if dest.Port != net.Port(53) && dest.Port != net.Port(853) {
		return false
	}
	switch dest.Network {
	case net.Network_TCP, net.Network_UDP:
		return true
	default:
		return false
	}
}

func classifyDNSFlowString(dest net.Destination) string {
	if dest.Port != net.Port(53) && dest.Port != net.Port(853) {
		return "non_dns"
	}
	switch dest.Network {
	case net.Network_TCP:
		return "dns_tcp_control"
	case net.Network_UDP:
		return "dns_udp_control"
	default:
		return "non_dns"
	}
}

func newDNSUplinkDiagnostic(ctx context.Context, destination net.Destination) *dnsUplinkDiagnostic {
	_ = ctx
	if !isDNSDest(destination) {
		return nil
	}
	return &dnsUplinkDiagnostic{
		startedAt:   time.Now(),
		destination: destination,
		flowClass:   classifyDNSFlowString(destination),
		dnsPlane:    "unknown",
	}
}

func newVisionUplinkDiagnostic(inbound *session.Inbound, destination net.Destination, timings *session.FlowTimings) *visionUplinkDiagnostic {
	if inbound == nil || destination.Network != net.Network_TCP || isDNSDest(destination) {
		return nil
	}
	if inbound.GetCanSpliceCopy() != session.CopyGatePendingDetach {
		return nil
	}
	return &visionUplinkDiagnostic{
		startedAt:   time.Now(),
		destination: destination,
		timings:     timings,
	}
}

func (d *dnsUplinkDiagnostic) observeWrite(n int) {
	if d == nil || n <= 0 {
		return
	}
	nowNs := time.Since(d.startedAt).Nanoseconds()
	if d.firstWriteNs.Load() == 0 {
		d.firstWriteNs.CompareAndSwap(0, nowNs)
	}
	d.lastWriteNs.Store(nowNs)
	d.totalBytes.Add(int64(n))
}

func (d *dnsUplinkDiagnostic) observeResponse(n int) {
	if d == nil || n <= 0 {
		return
	}
	nowNs := time.Since(d.startedAt).Nanoseconds()
	if d.firstResponseNs.Load() == 0 {
		d.firstResponseNs.CompareAndSwap(0, nowNs)
	}
	d.lastResponseNs.Store(nowNs)
	d.responseBytes.Add(int64(n))
}

func (d *dnsUplinkDiagnostic) requestTTFBNs() int64 {
	if d == nil {
		return 0
	}
	firstWrite := d.firstWriteNs.Load()
	firstResponse := d.firstResponseNs.Load()
	if firstWrite <= 0 || firstResponse < firstWrite {
		return 0
	}
	return firstResponse - firstWrite
}

func (d *dnsUplinkDiagnostic) responseCompleteNs() int64 {
	if d == nil {
		return 0
	}
	firstWrite := d.firstWriteNs.Load()
	lastResponse := d.lastResponseNs.Load()
	if firstWrite <= 0 || lastResponse < firstWrite {
		return 0
	}
	return lastResponse - firstWrite
}

func (d *visionUplinkDiagnostic) observeWrite(n int) {
	if d == nil || n <= 0 {
		return
	}
	now := time.Now()
	nowNs := now.Sub(d.startedAt).Nanoseconds()
	if d.firstWriteNs == 0 {
		d.firstWriteNs = nowNs
	}
	d.lastWriteNs = nowNs
	d.totalBytes += int64(n)
	if d.timings != nil {
		d.timings.ObserveUplinkWrite(now.UnixNano(), n)
	}
}

func (d *dnsUplinkDiagnostic) log(ctx context.Context, result string, opErr error, inbound *session.Inbound, outbound *session.Outbound) {
	if d == nil {
		return
	}
	inboundGate := session.CopyGateUnset
	if inbound != nil {
		inboundGate = inbound.GetCanSpliceCopy()
	}
	outboundGate := session.CopyGateUnset
	if outbound != nil {
		outboundGate = outbound.GetCanSpliceCopy()
	}
	args := []any{
		"proxy markers[kind=dns-uplink-diagnostic]: ",
		"result=", result,
		" dns_flow_class=", d.flowClass,
		" dns_plane=", d.dnsPlane,
		" dns_destination=", d.destination.String(),
	}
	args = append(args,
		" uplink_first_write_ns=", d.firstWriteNs.Load(),
		" uplink_bytes=", d.totalBytes.Load(),
		" uplink_useful_duration_ns=", d.lastWriteNs.Load(),
		" uplink_total_duration_ns=", time.Since(d.startedAt).Nanoseconds(),
		" inbound_copy_gate=", inboundGate.String(),
		" outbound_copy_gate=", outboundGate.String(),
		" err_class=", classifyDNSUplinkErr(opErr),
	)
	errors.LogDebug(ctx, args...)
}

func (d *dnsUplinkDiagnostic) logResponseSummary(ctx context.Context, result string, opErr error, inbound *session.Inbound, outbound *session.Outbound) {
	if d == nil {
		return
	}
	inboundGate := session.CopyGateUnset
	if inbound != nil {
		inboundGate = inbound.GetCanSpliceCopy()
	}
	outboundGate := session.CopyGateUnset
	if outbound != nil {
		outboundGate = outbound.GetCanSpliceCopy()
	}
	args := []any{
		"proxy markers[kind=dns-control-summary]: ",
		"result=", result,
		" dns_flow_class=", d.flowClass,
		" dns_plane=", d.dnsPlane,
		" dns_destination=", d.destination.String(),
	}
	args = append(args,
		" dns_request_ttfb_ns=", d.requestTTFBNs(),
		" dns_response_complete_ns=", d.responseCompleteNs(),
		" dns_response_bytes=", d.responseBytes.Load(),
		" inbound_copy_gate=", inboundGate.String(),
		" outbound_copy_gate=", outboundGate.String(),
		" err_class=", classifyDNSUplinkErr(opErr),
	)
	errors.LogDebug(ctx, args...)
}

func (d *visionUplinkDiagnostic) log(ctx context.Context, result string, opErr error, inbound *session.Inbound, outbound *session.Outbound) {
	if d == nil {
		return
	}
	inboundGate := session.CopyGateUnset
	if inbound != nil {
		inboundGate = inbound.GetCanSpliceCopy()
	}
	outboundGate := session.CopyGateUnset
	if outbound != nil {
		outboundGate = outbound.GetCanSpliceCopy()
	}
	now := time.Now()
	if d.timings != nil {
		d.timings.StoreUplinkComplete(now.UnixNano())
	}
	errors.LogDebug(ctx, "proxy markers[kind=vision-uplink-diagnostic]: ",
		"result=", result,
		" destination=", d.destination.String(),
		" uplink_first_write_ns=", d.firstWriteNs,
		" uplink_bytes=", d.totalBytes,
		" uplink_useful_duration_ns=", d.lastWriteNs,
		" uplink_total_duration_ns=", now.Sub(d.startedAt).Nanoseconds(),
		" inbound_copy_gate=", inboundGate.String(),
		" outbound_copy_gate=", outboundGate.String(),
		" err_class=", classifyUplinkErr(opErr),
	)
}

func observeVisionPendingDetachOnUplinkComplete(ctx context.Context, inbound *session.Inbound, outbound *session.Outbound, result string, retErr error) {
	if retErr != nil {
		return
	}
	proxy.ObserveVisionUplinkComplete(ctx, inbound, outbound)
}

func classifyUplinkErr(err error) string {
	if err == nil {
		return "none"
	}
	cause := errors.Cause(err)
	if cause == nil {
		cause = err
	}
	switch {
	case goerrors.Is(cause, context.Canceled):
		return "context_canceled"
	case goerrors.Is(cause, context.DeadlineExceeded):
		return "context_deadline_exceeded"
	case goerrors.Is(cause, io.EOF):
		return "eof"
	case goerrors.Is(cause, gonet.ErrClosed),
		goerrors.Is(cause, io.ErrClosedPipe),
		goerrors.Is(cause, syscall.EPIPE),
		goerrors.Is(cause, syscall.ECONNRESET),
		goerrors.Is(cause, syscall.ENOTCONN),
		goerrors.Is(cause, syscall.ESHUTDOWN):
		return "conn_closed"
	}
	if ne, ok := cause.(interface{ Timeout() bool }); ok && ne.Timeout() {
		return "timeout"
	}
	return "other"
}

func classifyDNSUplinkErr(err error) string {
	cause := errors.Cause(err)
	if cause == nil {
		cause = err
	}
	if goerrors.Is(cause, errDNSUDPFirstResponseTimeout) {
		return "first_response_timeout"
	}
	return classifyUplinkErr(err)
}

func shouldFastFailDNSUDPFirstResponse(ctx context.Context, destination net.Destination) bool {
	if destination.Network != net.Network_UDP || destination.Port != net.Port(853) {
		return false
	}
	return session.IsControlPlaneLoopbackIngress(session.InboundFromContext(ctx))
}

func shouldBypassEgressFastFail(ctx context.Context, dest net.Destination) bool {
	if isDNSDest(dest) {
		return true
	}
	if dest.Network != net.Network_TCP {
		return false
	}
	// For Vision flows targeting a literal IP, retrying the exact same dead
	// address five times only stretches user-visible stalls. Domain targets keep
	// the normal retry path so later attempts can pick a different IP.
	return session.VisionFlowFromContext(ctx) && dest.Address != nil && dest.Address.Family().IsIP()
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
	ob.SetCanSpliceCopy(session.CopyGateEligible)
	inbound := session.InboundFromContext(ctx)
	var defaultRule *FinalRule
	if !h.usesDialerProxy { // freedom is not the final outbound, final rules do not apply (and the domain is not resolved)
		defaultRule = getDefaultFinalRule(inbound)
	}

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

	input := link.Reader
	output := link.Writer

	var conn stat.Connection
	var blockedDest *net.Destination
	var blockedRule *FinalRule
	flowTimings := session.FlowTimingsFromContext(ctx)
	if flowTimings == nil {
		flowTimings = &session.FlowTimings{}
		ctx = session.ContextWithFlowTimings(ctx, flowTimings)
	}
	flowTimings.StoreRequestStart(time.Now().UnixNano())

	// DNS/loopback control traffic gets a single-shot dial without
	// penalty/backoff to avoid long startup corks.
	dialAttempts := 5
	if shouldBypassEgressFastFail(ctx, destination) {
		dialAttempts = 1
	}
	err := retry.ExponentialBackoff(dialAttempts, 100).On(func() error {
		if destination.Address.Family().IsDomain() {
			if defaultRule != nil || len(h.finalRules) > 0 {
				if strategy := h.resolveStrategy; strategy.HasStrategy() {
					ips, err := internet.LookupForIP(destination.Address.Domain(), strategy, outGateway)
					if err != nil { // non-force may still dial with system DNS
						errors.LogInfoInner(ctx, err, "failed to get IP address for domain ", destination.Address.Domain())
						if strategy.ForceIP() {
							return err // retry
						}
					}
					for _, ip := range ips {
						if addr := net.IPAddress(ip); addr != nil {
							if rule := h.matchFinalRule(destination.Network, addr, destination.Port, defaultRule); rule != nil && rule.action == RuleAction_Block {
								blockedDest = &destination
								blockedDest.Address = addr
								blockedRule = rule
								return nil
							}
						}
					}
				} else {
					addrs, err := net.DefaultResolver.LookupIPAddr(ctx, destination.Address.Domain())
					if err != nil { // dialer may retry DNS
						errors.LogInfoInner(ctx, err, "failed to get IP address for domain ", destination.Address.Domain())
					}
					for _, addr := range addrs {
						if ipAddr := net.IPAddress(addr.IP); ipAddr != nil {
							if rule := h.matchFinalRule(destination.Network, ipAddr, destination.Port, defaultRule); rule != nil && rule.action == RuleAction_Block {
								blockedDest = &destination
								blockedDest.Address = ipAddr
								blockedRule = rule
								return nil
							}
						}
					}
				}
			}
		} else {
			if rule := h.matchFinalRule(destination.Network, destination.Address, destination.Port, defaultRule); rule != nil && rule.action == RuleAction_Block {
				blockedDest = &destination
				blockedRule = rule
				return nil
			}
		}

		flowTimings.StoreConnectStart(time.Now().UnixNano())
		rawConn, err := dialer.Dial(ctx, destination)
		if err != nil {
			return err
		}
		flowTimings.StoreConnectOpen(time.Now().UnixNano())

		conn = rawConn
		return nil
	})
	if err != nil {
		return errors.New("failed to open connection to ", destination).Base(err)
	}
	if blockedDest != nil {
		return h.blackhole(ctx, input, output, blockedRule, blockedDest)
	}
	if destination.Address.Family().IsDomain() && (defaultRule != nil || len(h.finalRules) > 0) {
		// pre-check may fail or dialer may select another IP
		remoteDest := net.DestinationFromAddr(conn.RemoteAddr())
		if rule := h.matchFinalRule(remoteDest.Network, remoteDest.Address, remoteDest.Port, defaultRule); rule != nil && rule.action == RuleAction_Block {
			conn.Close()
			return h.blackhole(ctx, input, output, rule, &remoteDest)
		}
	}

	if h.config.ProxyProtocol > 0 && h.config.ProxyProtocol <= 2 {
		version := byte(h.config.ProxyProtocol)
		srcAddr := inbound.Source.RawNetAddr()
		dstAddr := conn.RemoteAddr()
		header := proxyproto.HeaderProxyFromAddrs(version, srcAddr, dstAddr)
		if _, err = header.WriteTo(conn); err != nil {
			conn.Close()
			return errors.New("failed to set PROXY protocol v", version).Base(err)
		}
	}
	defer conn.Close()
	errors.LogDebug(ctx, "connection opened to ", destination, ", local endpoint ", conn.LocalAddr(), ", remote endpoint ", conn.RemoteAddr())

	var newCtx context.Context
	var newCancel context.CancelFunc
	if session.TimeoutOnlyFromContext(ctx) {
		newCtx, newCancel = context.WithCancel(context.Background())
		newCtx = session.ContextWithFlowTimings(newCtx, flowTimings)
	}

	plcy := h.policy()
	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, func() {
		cancel()
		if newCancel != nil {
			newCancel()
		}
	}, plcy.Timeouts.ConnectionIdle)
	dnsDiag := newDNSUplinkDiagnostic(ctx, destination)
	dnsFirstResponseGuard := (*udpFirstResponseGuard)(nil)
	if shouldFastFailDNSUDPFirstResponse(ctx, destination) {
		// Keep the DoQ fast-fail tied to outbound activity, but also clamp the
		// total wait budget so a dead path cannot stretch through a full QUIC
		// retransmission train before the client falls back to TCP DNS.
		dnsFirstResponseGuard = newUDPFirstResponseGuard(conn, dnsUDPFirstResponseTimeout)
	}

	requestDone := func() (retErr error) {
		downlinkTimeout := plcy.Timeouts.DownlinkOnly
		// Raw Vision response handling has its own phase-aware timeout policy in
		// CopyRawConnIfExist. Let that response loop own the shared inactivity
		// timer instead of steering it here from request-side transport signals.
		proxyOwnsResponseTimeout := false
		if destination.Network == net.Network_TCP && useSplice.Load() && proxy.IsRAWTransportWithoutSecurity(conn) {
			proxyOwnsResponseTimeout = true
		}
		defer func() {
			if !proxyOwnsResponseTimeout {
				timer.SetTimeout(downlinkTimeout)
			}
		}()
		visionDiag := newVisionUplinkDiagnostic(inbound, destination, flowTimings)
		uplinkResult := "copy_complete"
		flowTimings.StoreUplinkStart(time.Now().UnixNano())
		if dnsDiag != nil || visionDiag != nil {
			defer func() {
				if dnsDiag != nil {
					dnsDiag.log(ctx, uplinkResult, retErr, inbound, ob)
				}
				if visionDiag != nil {
					visionDiag.log(ctx, uplinkResult, retErr, inbound, ob)
				}
			}()
		}

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
			writer = NewPacketWriter(conn, h, defaultRule, UDPOverride, destination, outGateway)
			if h.config.Noises != nil {
				errors.LogDebug(ctx, "NOISE", h.config.Noises)
				writer = &NoisePacketWriter{
					Writer:      writer,
					noises:      h.config.Noises,
					firstWrite:  true,
					UDPOverride: UDPOverride,
					DestPort:    destination.Port,
					remoteAddr:  net.DestinationFromAddr(conn.RemoteAddr()).Address,
				}
			}
		}
		if dnsDiag != nil || visionDiag != nil {
			writer = &dnsUplinkDiagnosticWriter{
				Writer: writer,
				dns:    dnsDiag,
				vision: visionDiag,
				guard:  dnsFirstResponseGuard,
			}
		}

		if err := buf.Copy(input, writer, buf.UpdateActivity(timer)); err != nil {
			if isExpectedRequestReadError(err) {
				uplinkResult = "request_stream_closed"
				if visionDiag != nil {
					observeVisionPendingDetachOnUplinkComplete(ctx, inbound, ob, uplinkResult, retErr)
				}
				errors.LogDebugInner(ctx, err, "freedom: request stream closed by peer")
				return nil
			}
			uplinkResult = "copy_error"
			retErr = errors.New("failed to process request").Base(err)
			if visionDiag != nil {
				observeVisionPendingDetachOnUplinkComplete(ctx, inbound, ob, uplinkResult, retErr)
			}
			return retErr
		}

		uplinkResult = "copy_complete"
		if visionDiag != nil {
			observeVisionPendingDetachOnUplinkComplete(ctx, inbound, ob, uplinkResult, retErr)
		}
		return nil
	}

	responseDone := func() (retErr error) {
		defer timer.SetTimeout(plcy.Timeouts.UplinkOnly)
		responseResult := "copy_complete"
		if dnsDiag != nil {
			defer func() {
				dnsDiag.logResponseSummary(ctx, responseResult, retErr, inbound, ob)
			}()
		}
		if destination.Network == net.Network_TCP && useSplice.Load() && proxy.IsRAWTransportWithoutSecurity(conn) { // it would be tls conn in special use case of MITM, we need to let link handle traffic
			var writeConn net.Conn
			var inTimer *signal.ActivityTimer
			if inbound := session.InboundFromContext(ctx); inbound != nil && inbound.Conn != nil {
				writeConn = inbound.Conn
				inTimer = inbound.Timer
			}
			writer := link.Writer
			if dnsDiag != nil {
				writer = &dnsResponseDiagnosticWriter{
					Writer:  link.Writer,
					dns:     dnsDiag,
					timings: flowTimings,
				}
			}
			if err := proxy.CopyRawConnIfExist(ctx, conn, writeConn, writer, timer, inTimer); err != nil {
				responseResult = "copy_error"
				retErr = err
				return retErr
			}
			return nil
		}
		var reader buf.Reader
		if destination.Network == net.Network_TCP {
			reader = buf.NewReader(conn)
		} else {
			reader = NewPacketReader(conn, h, defaultRule, UDPOverride, destination)
			if dnsFirstResponseGuard != nil {
				// Dead DoQ paths can otherwise sit through multi-second QUIC
				// retransmission backoff before the client falls back to TCP DNS.
				// Refresh the deadline from each outbound packet until the first
				// response datagram arrives.
				reader = newUDPFirstResponseTimeoutReader(reader, dnsFirstResponseGuard)
			}
		}
		writer := output
		if dnsDiag != nil {
			writer = &dnsResponseDiagnosticWriter{
				Writer:  output,
				dns:     dnsDiag,
				timings: flowTimings,
			}
		}
		if err := buf.Copy(reader, writer, buf.UpdateActivity(timer)); err != nil {
			responseResult = "copy_error"
			retErr = errors.New("failed to process response").Base(err)
			return retErr
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

func NewPacketReader(conn net.Conn, h *Handler, defaultRule *FinalRule, UDPOverride net.Destination, DialDest net.Destination) buf.Reader {
	iConn := conn
	statConn, ok := iConn.(*stat.CounterConnection)
	if ok {
		iConn = statConn.Connection
	}
	var counter stats.Counter
	if statConn != nil {
		counter = statConn.ReadCounter
	}
	if c, ok := iConn.(*net.PacketConnWrapper); ok {
		isOverridden := false
		if UDPOverride.Address != nil || UDPOverride.Port != 0 {
			isOverridden = true
		}

		return &PacketReader{
			PacketConnWrapper: c,
			Counter:           counter,
			Handler:           h,
			DefaultRule:       defaultRule,
			IsOverridden:      isOverridden,
			InitUnchangedAddr: DialDest.Address,
			InitChangedAddr:   net.DestinationFromAddr(conn.RemoteAddr()).Address,
		}
	}
	return &buf.PacketReader{Reader: conn}
}

type PacketReader struct {
	*net.PacketConnWrapper
	stats.Counter
	Handler           *Handler
	DefaultRule       *FinalRule
	IsOverridden      bool
	InitUnchangedAddr net.Address
	InitChangedAddr   net.Address
}

type udpFirstResponseTimeoutReader struct {
	reader buf.Reader
	guard  *udpFirstResponseGuard
}

type udpFirstResponseGuard struct {
	conn         gonet.Conn
	timeout      time.Duration
	maxTotalWait time.Duration
	firstWriteNs atomic.Int64
	armed        atomic.Bool
	responseSeen atomic.Bool
}

func newUDPFirstResponseGuard(conn gonet.Conn, timeout time.Duration) *udpFirstResponseGuard {
	return newUDPFirstResponseGuardWithBudget(conn, timeout, dnsUDPFirstResponseMaxTotalWait)
}

func newUDPFirstResponseGuardWithBudget(conn gonet.Conn, timeout, maxTotalWait time.Duration) *udpFirstResponseGuard {
	if conn == nil || timeout <= 0 {
		return nil
	}
	return &udpFirstResponseGuard{
		conn:         conn,
		timeout:      timeout,
		maxTotalWait: maxTotalWait,
	}
}

func (g *udpFirstResponseGuard) ObserveWrite() {
	if g == nil || g.responseSeen.Load() {
		return
	}
	now := time.Now()
	firstWriteNs := g.firstWriteNs.Load()
	if firstWriteNs == 0 {
		firstWriteNs = now.UnixNano()
		if !g.firstWriteNs.CompareAndSwap(0, firstWriteNs) {
			firstWriteNs = g.firstWriteNs.Load()
		}
	}
	deadline := now.Add(g.timeout)
	if g.maxTotalWait > 0 && firstWriteNs > 0 {
		maxDeadline := time.Unix(0, firstWriteNs).Add(g.maxTotalWait)
		if maxDeadline.Before(deadline) {
			deadline = maxDeadline
		}
	}
	g.armed.Store(true)
	_ = g.conn.SetReadDeadline(deadline)
}

func (g *udpFirstResponseGuard) ObserveResponse() {
	if g == nil {
		return
	}
	if g.responseSeen.Swap(true) {
		return
	}
	_ = g.conn.SetReadDeadline(time.Time{})
}

func (g *udpFirstResponseGuard) TranslateReadError(err error) error {
	if g == nil || err == nil {
		return err
	}
	if ne, ok := err.(interface{ Timeout() bool }); ok && ne.Timeout() &&
		g.armed.Load() && !g.responseSeen.Load() {
		_ = g.conn.SetReadDeadline(time.Time{})
		return errDNSUDPFirstResponseTimeout
	}
	return err
}

func newUDPFirstResponseTimeoutReader(reader buf.Reader, guard *udpFirstResponseGuard) buf.Reader {
	if reader == nil || guard == nil {
		return reader
	}
	return &udpFirstResponseTimeoutReader{
		reader: reader,
		guard:  guard,
	}
}

func (r *udpFirstResponseTimeoutReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, err := r.reader.ReadMultiBuffer()
	if err != nil {
		return nil, r.guard.TranslateReadError(err)
	}
	if !mb.IsEmpty() {
		r.guard.ObserveResponse()
	}
	return mb, nil
}

func (r *PacketReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	b := buf.New()
	b.Resize(0, buf.Size)
	for {
		n, d, err := r.PacketConnWrapper.ReadFrom(b.Bytes())
		if err != nil {
			b.Release()
			return nil, err
		}
		udpAddr := d.(*net.UDPAddr)
		sourceAddr := net.IPAddress(udpAddr.IP)
		if rule := r.Handler.matchFinalRule(net.Network_UDP, sourceAddr, net.Port(udpAddr.Port), r.DefaultRule); rule != nil && rule.action == RuleAction_Block {
			continue
		}
		b.Resize(0, int32(n))

		// if udp dest addr is changed, we are unable to get the correct src addr
		// so we don't attach src info to udp packet, break cone behavior, assuming the dial dest is the expected scr addr
		if !r.IsOverridden {
			if r.InitChangedAddr == sourceAddr {
				sourceAddr = r.InitUnchangedAddr
			}
			b.UDP = &net.Destination{
				Address: sourceAddr,
				Port:    net.Port(udpAddr.Port),
				Network: net.Network_UDP,
			}
		}
		if r.Counter != nil {
			r.Counter.Add(int64(n))
		}
		return buf.MultiBuffer{b}, nil
	}
}

// DialDest means the dial target used in the dialer when creating conn
func NewPacketWriter(conn net.Conn, h *Handler, defaultRule *FinalRule, UDPOverride net.Destination, DialDest net.Destination, outGateway net.Address) buf.Writer {
	iConn := conn
	statConn, ok := iConn.(*stat.CounterConnection)
	if ok {
		iConn = statConn.Connection
	}
	var counter stats.Counter
	if statConn != nil {
		counter = statConn.WriteCounter
	}
	if c, ok := iConn.(*net.PacketConnWrapper); ok {
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
			DefaultRule:       defaultRule,
			UDPOverride:       UDPOverride,
			ResolvedUDPAddr:   resolvedUDPAddr,
			OutGateway:        outGateway,
		}
	}
	return &buf.SequentialWriter{Writer: conn}
}

type PacketWriter struct {
	*net.PacketConnWrapper
	stats.Counter
	*Handler
	DefaultRule *FinalRule
	UDPOverride net.Destination

	// Dest of udp packets might be a domain, we will resolve them to IP
	// But resolver will return a random one if the domain has many IPs
	// Resulting in these packets being sent to many different IPs randomly
	// So, cache and keep the resolve result
	ResolvedUDPAddr *utils.TypedSyncMap[string, net.Address]
	OutGateway      net.Address
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
					shouldUseSystemResolver := true
					if strategy := w.Handler.resolveStrategy; strategy.HasStrategy() {
						ips, err := internet.LookupForIP(b.UDP.Address.Domain(), strategy, w.OutGateway)
						if err != nil {
							// drop packet if resolve failed when forceIP
							if strategy.ForceIP() {
								b.Release()
								continue
							}
						} else {
							ip = net.IPAddress(ips[dice.Roll(len(ips))])
							shouldUseSystemResolver = false
						}
					}
					if shouldUseSystemResolver {
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
			if rule := w.matchFinalRule(net.Network_UDP, b.UDP.Address, b.UDP.Port, w.DefaultRule); rule != nil && rule.action == RuleAction_Block {
				b.Release()
				continue
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
	DestPort    net.Port
	remoteAddr  net.Address
}

func isDNSControlPort(port net.Port) bool {
	return port == 53 || port == 853
}

// MultiBuffer writer with Noise before first packet
func (w *NoisePacketWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if w.firstWrite {
		w.firstWrite = false
		// Do not send Noise for dns requests(just to be safe)
		if isDNSControlPort(w.UDPOverride.Port) || isDNSControlPort(w.DestPort) {
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
			// User input string or base64 encoded string or hex string
			if n.Packet != nil {
				noise = n.Packet
			} else {
				// Random noise
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
