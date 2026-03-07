// Package proxy contains all proxies used by Xray.
//
// To implement an inbound or outbound proxy, one needs to do the following:
// 1. Implement the interface(s) below.
// 2. Register a config creator through common.RegisterConfig.
package proxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	goerrors "errors"
	"io"
	gonet "net"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/pires/go-proxyproto"
	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/native"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/pipeline"
	"github.com/xtls/xray-core/common/platform"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy/vless/encryption"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/ebpf"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

var (
	Tls13SupportedVersions  = []byte{0x00, 0x2b, 0x00, 0x02, 0x03, 0x04}
	TlsClientHandShakeStart = []byte{0x16, 0x03}
	TlsServerHandShakeStart = []byte{0x16, 0x03, 0x03}
	TlsApplicationDataStart = []byte{0x17, 0x03, 0x03}

	Tls13CipherSuiteDic = map[uint16]string{
		0x1301: "TLS_AES_128_GCM_SHA256",
		0x1302: "TLS_AES_256_GCM_SHA384",
		0x1303: "TLS_CHACHA20_POLY1305_SHA256",
		0x1304: "TLS_AES_128_CCM_SHA256",
		0x1305: "TLS_AES_128_CCM_8_SHA256",
	}
)

const (
	TlsHandshakeTypeClientHello byte = 0x01
	TlsHandshakeTypeServerHello byte = 0x02

	CommandPaddingContinue byte = 0x00
	CommandPaddingEnd      byte = 0x01
	CommandPaddingDirect   byte = 0x02

	pipelineMarkerLogInterval = 30 * time.Second
)

// pipelineTelemetryV2Enabled gates legacy per-interval marker dumps.
func pipelineTelemetryV2Enabled() bool {
	return platform.NewEnvFlag("xray.pipeline.telemetry.v2").GetValue(func() string { return "" }) != "off"
}

func debugVisionExplicitOnly() bool {
	return os.Getenv("XRAY_DEBUG_VISION_EXPLICIT_ONLY") == "1"
}

func init() {
	startupHealthOnce.Do(logStartupHealth)
}

var (
	pipelineMarkerDeferredRawUnwrapWarning    atomic.Uint64
	pipelineMarkerRawUnwrapToDetachNanosTotal atomic.Uint64
	pipelineMarkerRawUnwrapToDetachSamples    atomic.Uint64
	pipelineMarkerRawUnwrapToDetachLt5ms      atomic.Uint64
	pipelineMarkerRawUnwrapToDetach5To20ms    atomic.Uint64
	pipelineMarkerRawUnwrapToDetach20To100ms  atomic.Uint64
	pipelineMarkerRawUnwrapToDetachGe100ms    atomic.Uint64
	pipelineMarkerDeferredSpliceGuardHit      atomic.Uint64
	pipelineMarkerVisionDrainDetachAttempt    atomic.Uint64
	pipelineMarkerVisionDrainDetachSuccess    atomic.Uint64
	pipelineMarkerVisionDrainDetachFail       atomic.Uint64
	pipelineMarkerVisionRestoreNBAttempt      atomic.Uint64
	pipelineMarkerVisionRestoreNBFail         atomic.Uint64
	pipelineMarkerVisionPaddingPhaseNanos     atomic.Uint64
	pipelineMarkerVisionPaddingPhaseCount     atomic.Uint64
	pipelineMarkerVisionDetachPhaseNanos      atomic.Uint64
	pipelineMarkerVisionDetachPhaseCount      atomic.Uint64
	pipelineMarkerVisionPostDetachNanos       atomic.Uint64
	pipelineMarkerVisionPostDetachCount       atomic.Uint64
	pipelineMarkerVisionPostDetachSplice      atomic.Uint64
	pipelineMarkerVisionPostDetachUserspace   atomic.Uint64
	pipelineMarkerVisionPostDetachSockmap     atomic.Uint64
	pipelineMarkerVisionDetachTimeout         atomic.Uint64
	pipelineMarkerSockmapPolicyRefresh        atomic.Uint64
	pipelineMarkerSockmapPolicyRefreshFail    atomic.Uint64
	pipelineMarkerSpliceAttempts              atomic.Uint64
	pipelineMarkerSpliceCompleted             atomic.Uint64
	pipelineMarkerSpliceExpectedTeardown      atomic.Uint64
	pipelineMarkerSpliceExpectedBrokenPipe    atomic.Uint64
	pipelineMarkerSpliceExpectedConnReset     atomic.Uint64
	pipelineMarkerSpliceExpectedClosedConn    atomic.Uint64
	pipelineMarkerSpliceExpectedCanceled      atomic.Uint64
	pipelineMarkerSpliceExpectedNotConn       atomic.Uint64
	pipelineMarkerSpliceExpectedShutdown      atomic.Uint64
	pipelineMarkerSpliceExpectedOther         atomic.Uint64
	pipelineMarkerSpliceUnexpectedError       atomic.Uint64
	pipelineMarkerSpliceBytesTotal            atomic.Uint64
	pipelineMarkerSpliceDurationNanosTotal    atomic.Uint64
	pipelineMarkerSpliceBytesLt4K             atomic.Uint64
	pipelineMarkerSpliceBytes4KTo64K          atomic.Uint64
	pipelineMarkerSpliceBytes64KTo1M          atomic.Uint64
	pipelineMarkerSpliceBytesGe1M             atomic.Uint64
	pipelineMarkerSpliceDurLt1ms              atomic.Uint64
	pipelineMarkerSpliceDur1To5ms             atomic.Uint64
	pipelineMarkerSpliceDur5To20ms            atomic.Uint64
	pipelineMarkerSpliceDur20To100ms          atomic.Uint64
	pipelineMarkerSpliceDurGe100ms            atomic.Uint64
	pipelineMarkerUserspaceCopyReads          atomic.Uint64
	pipelineMarkerUserspaceCopyBytesTotal     atomic.Uint64
	pipelineMarkerUserspaceRawReaderHits      atomic.Uint64
	pipelineMarkerUserspaceTLSReaderHits      atomic.Uint64
	pipelineMarkerEnsureRawFailOS             atomic.Uint64
	pipelineMarkerEnsureRawFailNilConn        atomic.Uint64
	pipelineMarkerEnsureRawFailWriterType     atomic.Uint64
	pipelineMarkerSockmapSkipMgr              atomic.Uint64
	pipelineMarkerSockmapSkipContention       atomic.Uint64
	pipelineMarkerSockmapSkipKTLSSockhash     atomic.Uint64
	pipelineMarkerSockmapSkipUserspaceTLS     atomic.Uint64
	pipelineMarkerSockmapSkipAsymmetric       atomic.Uint64
	pipelineMarkerSockmapSkipOther            atomic.Uint64
	pipelineMarkerSockmapRegisterAttempt      atomic.Uint64
	pipelineMarkerSockmapRegisterSuccess      atomic.Uint64
	pipelineMarkerSockmapRegisterFail         atomic.Uint64
	pipelineMarkerSockmapWaitSuccess          atomic.Uint64
	pipelineMarkerSockmapWaitFallback         atomic.Uint64
	pipelineMarkerSockmapWaitError            atomic.Uint64
	pipelineMarkerFlowMuxUDP                  atomic.Uint64
	pipelineMarkerFlowPureTCP                 atomic.Uint64
	pipelineMarkerFlowMuxTCP                  atomic.Uint64
	pipelineMarkerFlowOther                   atomic.Uint64
	pipelineMarkerDNSGuardFirstResponseNanos  atomic.Uint64
	pipelineMarkerDNSGuardFirstResponseCount  atomic.Uint64
	pipelineMarkerDNSGuardFirstRespLt20ms     atomic.Uint64
	pipelineMarkerDNSGuardFirstResp20To100ms  atomic.Uint64
	pipelineMarkerDNSGuardFirstResp100msTo1s  atomic.Uint64
	pipelineMarkerDNSGuardFirstRespGe1s       atomic.Uint64
	pipelineMarkerDNSGuardZeroByteTimeout     atomic.Uint64

	// previous snapshot totals for per-interval deltas
	pipelineMarkerLastDeferredRawUnwrapWarning    atomic.Uint64
	pipelineMarkerLastRawUnwrapToDetachNanosTotal atomic.Uint64
	pipelineMarkerLastRawUnwrapToDetachSamples    atomic.Uint64
	pipelineMarkerLastRawUnwrapToDetachLt5ms      atomic.Uint64
	pipelineMarkerLastRawUnwrapToDetach5To20ms    atomic.Uint64
	pipelineMarkerLastRawUnwrapToDetach20To100ms  atomic.Uint64
	pipelineMarkerLastRawUnwrapToDetachGe100ms    atomic.Uint64
	pipelineMarkerLastDeferredSpliceGuardHit      atomic.Uint64
	pipelineMarkerLastVisionDrainDetachAttempt    atomic.Uint64
	pipelineMarkerLastVisionDrainDetachSuccess    atomic.Uint64
	pipelineMarkerLastVisionDrainDetachFail       atomic.Uint64
	pipelineMarkerLastVisionRestoreNBAttempt      atomic.Uint64
	pipelineMarkerLastVisionRestoreNBFail         atomic.Uint64
	pipelineMarkerLastVisionPaddingPhaseNanos     atomic.Uint64
	pipelineMarkerLastVisionPaddingPhaseCount     atomic.Uint64
	pipelineMarkerLastVisionDetachPhaseNanos      atomic.Uint64
	pipelineMarkerLastVisionDetachPhaseCount      atomic.Uint64
	pipelineMarkerLastVisionPostDetachNanos       atomic.Uint64
	pipelineMarkerLastVisionPostDetachCount       atomic.Uint64
	pipelineMarkerLastVisionPostDetachSplice      atomic.Uint64
	pipelineMarkerLastVisionPostDetachUserspace   atomic.Uint64
	pipelineMarkerLastVisionPostDetachSockmap     atomic.Uint64
	pipelineMarkerLastVisionDetachTimeout         atomic.Uint64
	pipelineMarkerLastSockmapPolicyRefresh        atomic.Uint64
	pipelineMarkerLastSockmapPolicyRefreshFail    atomic.Uint64
	pipelineMarkerLastSpliceAttempts              atomic.Uint64
	pipelineMarkerLastSpliceCompleted             atomic.Uint64
	pipelineMarkerLastSpliceExpectedTeardown      atomic.Uint64
	pipelineMarkerLastSpliceExpectedBrokenPipe    atomic.Uint64
	pipelineMarkerLastSpliceExpectedConnReset     atomic.Uint64
	pipelineMarkerLastSpliceExpectedClosedConn    atomic.Uint64
	pipelineMarkerLastSpliceExpectedCanceled      atomic.Uint64
	pipelineMarkerLastSpliceExpectedNotConn       atomic.Uint64
	pipelineMarkerLastSpliceExpectedShutdown      atomic.Uint64
	pipelineMarkerLastSpliceExpectedOther         atomic.Uint64
	pipelineMarkerLastSpliceUnexpectedError       atomic.Uint64
	pipelineMarkerLastSpliceBytesTotal            atomic.Uint64
	pipelineMarkerLastSpliceDurationNanosTotal    atomic.Uint64
	pipelineMarkerLastSpliceBytesLt4K             atomic.Uint64
	pipelineMarkerLastSpliceBytes4KTo64K          atomic.Uint64
	pipelineMarkerLastSpliceBytes64KTo1M          atomic.Uint64
	pipelineMarkerLastSpliceBytesGe1M             atomic.Uint64
	pipelineMarkerLastSpliceDurLt1ms              atomic.Uint64
	pipelineMarkerLastSpliceDur1To5ms             atomic.Uint64
	pipelineMarkerLastSpliceDur5To20ms            atomic.Uint64
	pipelineMarkerLastSpliceDur20To100ms          atomic.Uint64
	pipelineMarkerLastSpliceDurGe100ms            atomic.Uint64
	pipelineMarkerLastUserspaceCopyReads          atomic.Uint64
	pipelineMarkerLastUserspaceCopyBytesTotal     atomic.Uint64
	pipelineMarkerLastUserspaceRawReaderHits      atomic.Uint64
	pipelineMarkerLastUserspaceTLSReaderHits      atomic.Uint64
	pipelineMarkerLastEnsureRawFailOS             atomic.Uint64
	pipelineMarkerLastEnsureRawFailNilConn        atomic.Uint64
	pipelineMarkerLastEnsureRawFailWriterType     atomic.Uint64
	pipelineMarkerLastSockmapSkipMgr              atomic.Uint64
	pipelineMarkerLastSockmapSkipContention       atomic.Uint64
	pipelineMarkerLastSockmapSkipKTLSSockhash     atomic.Uint64
	pipelineMarkerLastSockmapSkipUserspaceTLS     atomic.Uint64
	pipelineMarkerLastSockmapSkipAsymmetric       atomic.Uint64
	pipelineMarkerLastSockmapSkipOther            atomic.Uint64
	pipelineMarkerLastSockmapRegisterAttempt      atomic.Uint64
	pipelineMarkerLastSockmapRegisterSuccess      atomic.Uint64
	pipelineMarkerLastSockmapRegisterFail         atomic.Uint64
	pipelineMarkerLastSockmapWaitSuccess          atomic.Uint64
	pipelineMarkerLastSockmapWaitFallback         atomic.Uint64
	pipelineMarkerLastSockmapWaitError            atomic.Uint64
	pipelineMarkerLastFlowMuxUDP                  atomic.Uint64
	pipelineMarkerLastFlowPureTCP                 atomic.Uint64
	pipelineMarkerLastFlowMuxTCP                  atomic.Uint64
	pipelineMarkerLastFlowOther                   atomic.Uint64

	pipelineMarkerLastSummaryUnix     atomic.Int64
	pipelineVisionDetachUnixByConn    sync.Map
	pipelineVisionRawUnwrapUnixByConn sync.Map
	pipelineVisionUplinkUnixByConn    sync.Map
	pipelineVisionDetachFutureByConn  sync.Map
	pipelineVisionResponseWakeByConn  sync.Map
	startupHealthOnce                 sync.Once
)

const (
	visionDetachTimeoutMin   = 500 * time.Millisecond
	visionDetachTimeoutMax   = 1 * time.Second
	visionDetachTimeoutSlack = 150 * time.Millisecond
	// Healthy Vision direct-copy candidates usually reach detach within a
	// sub-second envelope. Keep speculative pre-detach grace short so
	// command-0-only residue does not build visible cork-pop cohorts.
	visionFirstResponseGrace = 750 * time.Millisecond
	visionFirstResponseMax   = 2 * time.Second
	visionUplinkQuietWindow  = 250 * time.Millisecond
	visionPreDetachPollTick  = 250 * time.Millisecond
)

var visionDetachBudgetNanos atomic.Int64

func clampVisionDetachBudget(d time.Duration) time.Duration {
	if d < visionDetachTimeoutMin {
		return visionDetachTimeoutMin
	}
	if d > visionDetachTimeoutMax {
		return visionDetachTimeoutMax
	}
	return d
}

func visionDetachWaitBudget() time.Duration {
	if budget := time.Duration(visionDetachBudgetNanos.Load()); budget > 0 {
		return clampVisionDetachBudget(budget)
	}
	return visionDetachTimeoutMin
}

func recordVisionDetachBudget(duration time.Duration) {
	if duration <= 0 {
		return
	}
	sample := clampVisionDetachBudget(duration + visionDetachTimeoutSlack)
	for {
		current := visionDetachBudgetNanos.Load()
		next := sample.Nanoseconds()
		if current > 0 {
			next = (current*3 + sample.Nanoseconds()) / 4
		}
		if visionDetachBudgetNanos.CompareAndSwap(current, next) {
			return
		}
	}
}

type visionDetachResult struct {
	plaintext []byte
	rawAhead  []byte
	err       error
	duration  time.Duration
}

type visionDetachFuture struct {
	once      sync.Once
	startedAt time.Time
	done      chan struct{}
	result    visionDetachResult
	state     atomic.Uint32
}

const (
	visionDetachPending uint32 = iota
	visionDetachDone
	visionDetachTimedOut
)

// An Inbound processes inbound connections.
type Inbound interface {
	// Network returns a list of networks that this inbound supports. Connections with not-supported networks will not be passed into Process().
	Network() []net.Network

	// Process processes a connection of given network. If necessary, the Inbound can dispatch the connection to an Outbound.
	Process(context.Context, net.Network, stat.Connection, routing.Dispatcher) error
}

// An Outbound process outbound connections.
type Outbound interface {
	// Process processes the given connection. The given dialer may be used to dial a system outbound connection.
	Process(context.Context, *transport.Link, internet.Dialer) error
}

// UserManager is the interface for Inbounds and Outbounds that can manage their users.
type UserManager interface {
	// AddUser adds a new user.
	AddUser(context.Context, *protocol.MemoryUser) error

	// RemoveUser removes a user by email.
	RemoveUser(context.Context, string) error

	// Get user by email.
	GetUser(context.Context, string) *protocol.MemoryUser

	// Get all users.
	GetUsers(context.Context) []*protocol.MemoryUser

	// Get users count.
	GetUsersCount(context.Context) int64
}

type GetInbound interface {
	GetInbound() Inbound
}

type GetOutbound interface {
	GetOutbound() Outbound
}

// TrafficState is used to track uplink and downlink of one connection
// It is used by XTLS to determine if switch to raw copy mode, It is used by Vision to calculate padding
type TrafficState struct {
	mu                          sync.Mutex // guards all fields below
	UserUUID                    []byte
	NumberOfPacketToFilter      int
	CreatedAtUnixNano           int64
	VisionPayloadBypassObserved bool
	EnableXtls                  bool
	IsTLS12orAbove              bool
	IsTLS                       bool
	Cipher                      uint16
	RemainingServerHello        int32
	Inbound                     InboundState
	Outbound                    OutboundState
}

// Lock exposes the internal mutex for cross-package consumers that need to
// safely coordinate Vision reader/writer state.
func (t *TrafficState) Lock() {
	t.mu.Lock()
}

// Unlock releases the TrafficState mutex.
func (t *TrafficState) Unlock() {
	t.mu.Unlock()
}

type InboundState struct {
	// reader link state
	WithinPaddingBuffers   bool
	UplinkReaderDirectCopy bool
	RemainingCommand       int32
	RemainingContent       int32
	RemainingPadding       int32
	CurrentCommand         int
	ContinueCommandsSeen   int32
	// write link state
	IsPadding                bool
	DownlinkWriterDirectCopy bool
}

type OutboundState struct {
	// reader link state
	WithinPaddingBuffers     bool
	DownlinkReaderDirectCopy bool
	RemainingCommand         int32
	RemainingContent         int32
	RemainingPadding         int32
	CurrentCommand           int
	ContinueCommandsSeen     int32
	// write link state
	IsPadding              bool
	UplinkWriterDirectCopy bool
}

const (
	visionPacketsToFilterDefault  = 16
	visionPacketsToFilterDeferred = 32
)

func NewTrafficState(userUUID []byte) *TrafficState {
	return &TrafficState{
		UserUUID: userUUID,
		// Keep a moderate default filter budget for mixed workloads.
		// Deferred REALITY paths can override this to a larger value.
		NumberOfPacketToFilter:      visionPacketsToFilterDefault,
		CreatedAtUnixNano:           time.Now().UnixNano(),
		VisionPayloadBypassObserved: false,
		EnableXtls:                  false,
		IsTLS12orAbove:              false,
		IsTLS:                       false,
		Cipher:                      0,
		RemainingServerHello:        -1,
		Inbound: InboundState{
			WithinPaddingBuffers:     true,
			UplinkReaderDirectCopy:   false,
			RemainingCommand:         -1,
			RemainingContent:         -1,
			RemainingPadding:         -1,
			CurrentCommand:           0,
			ContinueCommandsSeen:     0,
			IsPadding:                true,
			DownlinkWriterDirectCopy: false,
		},
		Outbound: OutboundState{
			WithinPaddingBuffers:     true,
			DownlinkReaderDirectCopy: false,
			RemainingCommand:         -1,
			RemainingContent:         -1,
			RemainingPadding:         -1,
			CurrentCommand:           0,
			ContinueCommandsSeen:     0,
			IsPadding:                true,
			UplinkWriterDirectCopy:   false,
		},
	}
}

func unwrapVisionDeferredConn(conn net.Conn) *tls.DeferredRustConn {
	return unwrapVisionDeferredConnRecurse(conn, 0)
}

type visionNetConnUnwrapper interface {
	NetConn() gonet.Conn
}

func unwrapVisionDeferredConnRecurse(conn net.Conn, depth int) *tls.DeferredRustConn {
	if conn == nil {
		return nil
	}
	if depth > 8 {
		return nil
	}
	if dc, ok := conn.(*tls.DeferredRustConn); ok {
		return dc
	}
	if sc := stat.TryUnwrapStatsConn(conn); sc != nil && sc != conn {
		return unwrapVisionDeferredConnRecurse(sc, depth+1)
	}
	if cc, ok := conn.(*encryption.CommonConn); ok && cc != nil {
		return unwrapVisionDeferredConnRecurse(cc.Conn, depth+1)
	}
	if unwrap, ok := conn.(visionNetConnUnwrapper); ok {
		if inner := unwrap.NetConn(); inner != nil && inner != conn {
			return unwrapVisionDeferredConnRecurse(inner, depth+1)
		}
	}
	return nil
}

func startVisionDetach(dc *tls.DeferredRustConn) *visionDetachFuture {
	if dc == nil {
		return nil
	}
	futAny, _ := pipelineVisionDetachFutureByConn.LoadOrStore(dc, &visionDetachFuture{
		done: make(chan struct{}),
	})
	fut := futAny.(*visionDetachFuture)

	fut.once.Do(func() {
		fut.state.Store(visionDetachPending)
		fut.startedAt = time.Now()
		pipelineMarkerVisionDrainDetachAttempt.Add(1)
		go func() {
			plaintext, rawAhead, err := dc.DrainAndDetach()
			duration := time.Since(fut.startedAt)
			if err != nil {
				pipelineMarkerVisionDrainDetachFail.Add(1)
			} else {
				pipelineMarkerVisionDrainDetachSuccess.Add(1)
				recordVisionDetachBudget(duration)
			}
			fut.result = visionDetachResult{
				plaintext: plaintext,
				rawAhead:  rawAhead,
				err:       err,
				duration:  duration,
			}
			// Monotonic: once timed out, state stays timed_out; late completions
			// are informational only.
			_ = fut.state.CompareAndSwap(visionDetachPending, visionDetachDone)
			close(fut.done)
		}()
	})
	return fut
}

// VisionReader is used to read xtls vision protocol
// Note Vision probably only make sense as the inner most layer of reader, since it need assess traffic state from origin proxy traffic
type VisionReader struct {
	buf.Reader
	trafficState *TrafficState
	ctx          context.Context
	isUplink     bool
	source       *VisionTransitionSource
	ob           *session.Outbound

	// internal
	directReadCounter stats.Counter
}

func NewVisionReader(reader buf.Reader, trafficState *TrafficState, isUplink bool, ctx context.Context, source *VisionTransitionSource, ob *session.Outbound) *VisionReader {
	return &VisionReader{
		Reader:       reader,
		trafficState: trafficState,
		ctx:          ctx,
		isUplink:     isUplink,
		source:       source,
		ob:           ob,
	}
}

func shouldObserveVisionPayloadBypass(ts *TrafficState, isUplink bool, ctx context.Context, buffer buf.MultiBuffer) bool {
	if ts == nil || ts.VisionPayloadBypassObserved || !isDNSPortOutbound(ctx) {
		return false
	}
	var (
		remainingCommand *int32
		remainingContent *int32
		remainingPadding *int32
	)
	if isUplink {
		remainingCommand = &ts.Inbound.RemainingCommand
		remainingContent = &ts.Inbound.RemainingContent
		remainingPadding = &ts.Inbound.RemainingPadding
	} else {
		remainingCommand = &ts.Outbound.RemainingCommand
		remainingContent = &ts.Outbound.RemainingContent
		remainingPadding = &ts.Outbound.RemainingPadding
	}
	if *remainingCommand != -1 || *remainingContent != -1 || *remainingPadding != -1 {
		return false
	}
	for _, b := range buffer {
		if b == nil || b.Len() == 0 {
			continue
		}
		if b.Len() < 21 {
			return false
		}
		return !bytes.Equal(ts.UserUUID, b.BytesTo(16))
	}
	return false
}

func markVisionPayloadBypassObserved(ctx context.Context, ts *TrafficState, ob *session.Outbound) {
	if ts == nil || ts.VisionPayloadBypassObserved {
		return
	}
	ts.VisionPayloadBypassObserved = true
	ctx = session.ContextWithDNSPlane(ctx, session.DNSPlaneVisionGuard)
	if inbound := session.InboundFromContext(ctx); inbound != nil {
		inbound.SetCopyGate(session.CopyGateForcedUserspace, session.CopyGateReasonVisionBypass)
	}
	if ob != nil {
		ob.SetCopyGate(session.CopyGateForcedUserspace, session.CopyGateReasonVisionBypass)
	}
	errors.LogInfo(ctx, "Vision: detected raw payload bypass on DNS control-plane flow; keeping payload unframed")
}

func markVisionNoDetachObserved(ctx context.Context, ob *session.Outbound) {
	changed := applyVisionNoDetachCopyGate(session.InboundFromContext(ctx), ob)
	if changed {
		errors.LogInfo(ctx, "Vision: command=1 observed; detach/direct-copy disabled for this flow, switching to userspace path")
	}
}

func applyVisionNoDetachCopyGate(inbound *session.Inbound, ob *session.Outbound) bool {
	changed := false
	if inbound != nil {
		switch inbound.GetCanSpliceCopy() {
		case session.CopyGatePendingDetach:
			inbound.SetCopyGate(session.CopyGateForcedUserspace, session.CopyGateReasonVisionNoDetach)
			changed = true
		case session.CopyGateForcedUserspace:
			if inbound.CopyGateReason() == session.CopyGateReasonVisionCommandContinue ||
				inbound.CopyGateReason() == session.CopyGateReasonVisionUplinkComplete {
				inbound.SetCopyGate(session.CopyGateForcedUserspace, session.CopyGateReasonVisionNoDetach)
				changed = true
			}
		}
	}
	if ob != nil {
		switch ob.GetCanSpliceCopy() {
		case session.CopyGatePendingDetach:
			ob.SetCopyGate(session.CopyGateForcedUserspace, session.CopyGateReasonVisionNoDetach)
			changed = true
		case session.CopyGateForcedUserspace:
			if ob.CopyGateReason() == session.CopyGateReasonVisionCommandContinue ||
				ob.CopyGateReason() == session.CopyGateReasonVisionUplinkComplete {
				ob.SetCopyGate(session.CopyGateForcedUserspace, session.CopyGateReasonVisionNoDetach)
				changed = true
			}
		}
	}
	return changed
}

func applyVisionUplinkCompleteCopyGate(inbound *session.Inbound, ob *session.Outbound) bool {
	changed := false
	if inbound != nil {
		switch inbound.GetCanSpliceCopy() {
		case session.CopyGatePendingDetach:
			inbound.SetCopyGate(session.CopyGateForcedUserspace, session.CopyGateReasonVisionUplinkComplete)
			changed = true
		case session.CopyGateForcedUserspace:
			if inbound.CopyGateReason() == session.CopyGateReasonVisionCommandContinue {
				inbound.SetCopyGate(session.CopyGateForcedUserspace, session.CopyGateReasonVisionUplinkComplete)
				changed = true
			}
		}
	}
	if ob != nil {
		switch ob.GetCanSpliceCopy() {
		case session.CopyGatePendingDetach:
			ob.SetCopyGate(session.CopyGateForcedUserspace, session.CopyGateReasonVisionUplinkComplete)
			changed = true
		case session.CopyGateForcedUserspace:
			if ob.CopyGateReason() == session.CopyGateReasonVisionCommandContinue {
				ob.SetCopyGate(session.CopyGateForcedUserspace, session.CopyGateReasonVisionUplinkComplete)
				changed = true
			}
		}
	}
	return changed
}

func registerVisionResponseWakeTarget(conn gonet.Conn, wakeTarget gonet.Conn) {
	if conn == nil || wakeTarget == nil {
		return
	}
	dc := unwrapVisionDeferredConn(conn)
	if dc == nil {
		return
	}
	pipelineVisionResponseWakeByConn.Store(dc, wakeTarget)
}

func unregisterVisionResponseWakeTarget(conn gonet.Conn) {
	dc := unwrapVisionDeferredConn(conn)
	if dc == nil {
		return
	}
	pipelineVisionResponseWakeByConn.Delete(dc)
}

func wakeVisionResponseLoop(ctx context.Context, conn gonet.Conn, reason string) {
	dc := unwrapVisionDeferredConn(conn)
	if dc == nil {
		return
	}
	value, ok := pipelineVisionResponseWakeByConn.Load(dc)
	if !ok {
		return
	}
	wakeTarget, ok := value.(gonet.Conn)
	if !ok || wakeTarget == nil {
		return
	}
	if err := wakeTarget.SetReadDeadline(time.Now()); err != nil {
		errors.LogDebugInner(ctx, err, "[kind=vision.response_wake_failed] unable to wake response loop; reason=", reason)
		return
	}
	errors.LogDebug(ctx, "[kind=vision.response_wake] explicit Vision signal woke response loop; reason=", reason)
}

// prepareVisionStableUserspaceRead transitions from a provisional response wait
// into the long-lived no-detach userspace path.
//
// Wakeups use an immediate read deadline only to interrupt the blocked
// pre-detach wait. Once we commit to stable userspace, that deadline must be
// cleared; otherwise the subsequent readV loop can fail immediately before any
// real response bytes have a chance to arrive.
func prepareVisionStableUserspaceRead(readerConn gonet.Conn, writerConn gonet.Conn) {
	if readerConn != nil {
		_ = readerConn.SetReadDeadline(time.Time{})
	}
	unregisterVisionResponseWakeTarget(writerConn)
}

// ObserveVisionUplinkComplete records that a pending-detach Vision request
// uplink completed from the outbound side.
//
// For a main-branch client, clean request completion is the strongest
// compatibility-safe signal that a command=0-only flow will never produce a
// later command=2. Once the request side is truly complete, collapse the
// provisional pending-detach metadata to an inferred no-detach userspace class
// and wake the waiting response loop so it can re-evaluate immediately.
func ObserveVisionUplinkComplete(ctx context.Context, inbound *session.Inbound, ob *session.Outbound) bool {
	pending := false
	if inbound != nil && inbound.GetCanSpliceCopy() == session.CopyGatePendingDetach {
		pending = true
	}
	if ob != nil && ob.GetCanSpliceCopy() == session.CopyGatePendingDetach {
		pending = true
	}
	if pending {
		if debugVisionExplicitOnly() {
			errors.LogDebug(ctx, "[kind=vision.uplink_complete_handoff] request uplink completed without direct-copy signal; telemetry only because XRAY_DEBUG_VISION_EXPLICIT_ONLY=1")
			return true
		}
		if applyVisionUplinkCompleteCopyGate(inbound, ob) {
			errors.LogDebug(ctx, "[kind=vision.uplink_complete_handoff] request uplink completed without direct-copy signal; promoting to inferred no-detach userspace for main-client compatibility")
			if inbound != nil && inbound.Conn != nil {
				wakeVisionResponseLoop(ctx, inbound.Conn, "uplink-complete")
			}
		} else {
			errors.LogDebug(ctx, "[kind=vision.uplink_complete_handoff] request uplink completed without direct-copy signal; explicit protocol state already resolved")
		}
	}
	return pending
}

func markVisionCommandContinueEvidence(ctx context.Context, conn gonet.Conn, ob *session.Outbound) bool {
	changed := false
	if inbound := session.InboundFromContext(ctx); inbound != nil && inbound.GetCanSpliceCopy() == session.CopyGatePendingDetach && inbound.CopyGateReason() == session.CopyGateReasonUnspecified {
		inbound.SetCopyGateReason(session.CopyGateReasonVisionCommandContinue)
		changed = true
	}
	if ob != nil && ob.GetCanSpliceCopy() == session.CopyGatePendingDetach && ob.CopyGateReason() == session.CopyGateReasonUnspecified {
		ob.SetCopyGateReason(session.CopyGateReasonVisionCommandContinue)
		changed = true
	}
	if changed {
		errors.LogDebug(ctx, "[kind=vision.command_continue_evidence] repeated command=0 observed; recording telemetry only")
	}
	return changed
}

func (w *VisionReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	buffer, err := w.Reader.ReadMultiBuffer()
	if buffer.IsEmpty() {
		return buffer, err
	}

	ts := w.trafficState
	ts.Lock()
	locked := true
	unlock := func() {
		if locked {
			ts.Unlock()
			locked = false
		}
	}
	defer unlock()

	var withinPaddingBuffers *bool
	var remainingContent *int32
	var remainingPadding *int32
	var currentCommand *int
	var continueCommandsSeen *int32
	var switchToDirectCopy *bool
	if w.isUplink {
		withinPaddingBuffers = &ts.Inbound.WithinPaddingBuffers
		remainingContent = &ts.Inbound.RemainingContent
		remainingPadding = &ts.Inbound.RemainingPadding
		currentCommand = &ts.Inbound.CurrentCommand
		continueCommandsSeen = &ts.Inbound.ContinueCommandsSeen
		switchToDirectCopy = &ts.Inbound.UplinkReaderDirectCopy
	} else {
		withinPaddingBuffers = &ts.Outbound.WithinPaddingBuffers
		remainingContent = &ts.Outbound.RemainingContent
		remainingPadding = &ts.Outbound.RemainingPadding
		currentCommand = &ts.Outbound.CurrentCommand
		continueCommandsSeen = &ts.Outbound.ContinueCommandsSeen
		switchToDirectCopy = &ts.Outbound.DownlinkReaderDirectCopy
	}

	if *switchToDirectCopy {
		if w.isUplink {
			storeVisionUplinkTimestamp(w.source.Conn(), time.Now().UnixNano())
		}
		if w.directReadCounter != nil {
			w.directReadCounter.Add(int64(buffer.Len()))
		}
		return buffer, err
	}

	if shouldObserveVisionPayloadBypass(ts, w.isUplink, w.ctx, buffer) {
		if w.isUplink {
			storeVisionUplinkTimestamp(w.source.Conn(), time.Now().UnixNano())
		}
		markVisionPayloadBypassObserved(w.ctx, ts, w.ob)
		return buffer, err
	}
	if ts.VisionPayloadBypassObserved {
		if w.isUplink {
			storeVisionUplinkTimestamp(w.source.Conn(), time.Now().UnixNano())
		}
		return buffer, err
	}

	if *withinPaddingBuffers || ts.NumberOfPacketToFilter > 0 {
		mb2 := buf.GetMultiBuffer()
		for _, b := range buffer {
			newbuffer := XtlsUnpadding(b, ts, w.isUplink, w.ctx)
			if newbuffer.Len() > 0 {
				mb2 = append(mb2, newbuffer)
			} else {
				newbuffer.Release()
			}
		}
		buffer = mb2
		if *remainingContent > 0 || *remainingPadding > 0 || *currentCommand == 0 {
			*withinPaddingBuffers = true
			if *currentCommand == int(CommandPaddingContinue) && *remainingContent <= 0 && *remainingPadding <= 0 && continueCommandsSeen != nil {
				*continueCommandsSeen = *continueCommandsSeen + 1
				if w.isUplink && *continueCommandsSeen >= 2 {
					markVisionCommandContinueEvidence(w.ctx, w.source.Conn(), w.ob)
				}
			}
		} else if *currentCommand == 1 {
			*withinPaddingBuffers = false
			if continueCommandsSeen != nil {
				*continueCommandsSeen = 0
			}
			markVisionNoDetachObserved(w.ctx, w.ob)
			if w.isUplink {
				wakeVisionResponseLoop(w.ctx, w.source.Conn(), "command=1")
			}
		} else if *currentCommand == 2 {
			*withinPaddingBuffers = false
			if continueCommandsSeen != nil {
				*continueCommandsSeen = 0
			}
			*switchToDirectCopy = true
		} else {
			if continueCommandsSeen != nil {
				*continueCommandsSeen = 0
			}
			errors.LogDebug(w.ctx, "XtlsRead unknown command ", *currentCommand, buffer.Len())
		}
	}
	if ts.NumberOfPacketToFilter > 0 {
		XtlsFilterTls(buffer, ts, w.ctx)
	}
	if w.isUplink && !buffer.IsEmpty() {
		storeVisionUplinkTimestamp(w.source.Conn(), time.Now().UnixNano())
	}

	if *switchToDirectCopy {
		if isDNSPortOutbound(w.ctx) {
			w.ctx = session.ContextWithDNSPlane(w.ctx, session.DNSPlaneVisionGuard)
			errors.LogInfo(w.ctx, "Vision: DNS control-plane flow; keeping rustls (no detach/zero-copy)")
			*switchToDirectCopy = false
			return buffer, err
		}
		if dc := unwrapVisionDeferredConn(w.source.Conn()); dc != nil {
			fut := startVisionDetach(dc)
			wait := visionDetachWaitBudget()
			if !fut.startedAt.IsZero() {
				if elapsed := time.Since(fut.startedAt); elapsed < wait {
					wait -= elapsed
				} else {
					wait = 0
				}
			}
			unlock()
			detachCompleted := false
			select {
			case <-fut.done:
				detachCompleted = true
			case <-time.After(wait):
				select {
				case <-fut.done:
					detachCompleted = true
				default:
				}
				if detachCompleted {
					break
				}
				ts.Lock()
				locked = true
				pipelineMarkerVisionDetachTimeout.Add(1)
				maybeLogPipelineRuntimeSummary(w.ctx)
				errors.LogWarning(w.ctx, "[kind=vision.drain_detach_timeout] DeferredRustConn drain still pending; staying on rustls path")
				*switchToDirectCopy = false
				fut.state.Store(visionDetachTimedOut)
				if inbound := session.InboundFromContext(w.ctx); inbound != nil {
					inbound.SetCopyGate(session.CopyGateForcedUserspace, session.CopyGateReasonDetachTimeout)
				}
				if w.ob != nil {
					w.ob.SetCopyGate(session.CopyGateForcedUserspace, session.CopyGateReasonDetachTimeout)
				}
				// Keep future cached so a later completion can be observed (and ignored) or retried deterministically.
				return buffer, err
			}
			ts.Lock()
			locked = true
			detachDoneUnix := time.Now().UnixNano()
			if fut.result.duration > 0 {
				pipelineMarkerVisionDetachPhaseNanos.Add(uint64(fut.result.duration.Nanoseconds()))
				pipelineMarkerVisionDetachPhaseCount.Add(1)
			}
			if fut.result.err != nil {
				maybeLogPipelineRuntimeSummary(w.ctx)
				// Cannot safely strip outer TLS. Keep rustls active for correctness.
				errors.LogWarning(w.ctx, "[kind=vision.drain_detach_failed] DeferredRustConn drain failed, keeping rustls active: ", fut.result.err)
				*switchToDirectCopy = false
				pipelineVisionDetachFutureByConn.Delete(dc)
				return buffer, err
			}
			// If this future had timed out earlier, treat completion as informational and
			// keep rustls path (no late state flip).
			if fut.state.Load() == visionDetachTimedOut {
				pipelineVisionDetachFutureByConn.Delete(dc)
				errors.LogWarning(w.ctx, "[kind=vision.drain_detach_late] DeferredRustConn detach completed after timeout; keeping rustls path")
				return buffer, err
			}
			if ts != nil && ts.CreatedAtUnixNano > 0 && detachDoneUnix > ts.CreatedAtUnixNano {
				pipelineMarkerVisionPaddingPhaseNanos.Add(uint64(detachDoneUnix - ts.CreatedAtUnixNano))
				pipelineMarkerVisionPaddingPhaseCount.Add(1)
			}
			if rawUnwrapUnix, ok := consumeVisionRawUnwrapWarningTimestamp(w.source.Conn()); ok && detachDoneUnix > rawUnwrapUnix {
				unwrapToDetachNs := uint64(detachDoneUnix - rawUnwrapUnix)
				pipelineMarkerRawUnwrapToDetachNanosTotal.Add(unwrapToDetachNs)
				pipelineMarkerRawUnwrapToDetachSamples.Add(1)
				recordRawUnwrapToDetachHistogram(unwrapToDetachNs)
			}
			storeVisionDetachTimestamp(w.source.Conn(), detachDoneUnix)
			errors.LogDebug(w.ctx, "Vision: DeferredRustConn drained and detached; switching reader to raw socket")
			if len(fut.result.plaintext) > 0 {
				buffer = append(buffer, buf.FromBytes(fut.result.plaintext))
			}
			if len(fut.result.rawAhead) > 0 {
				buffer = append(buffer, buf.FromBytes(fut.result.rawAhead))
			}
			pipelineVisionDetachFutureByConn.Delete(dc)
		} else {
			plaintext, rawAhead := w.source.DrainBufferedState()
			if len(plaintext) > 0 {
				buffer = append(buffer, buf.FromBytes(plaintext))
			}
			if len(rawAhead) > 0 {
				buffer = append(buffer, buf.FromBytes(rawAhead))
			}
		}

		if inbound := session.InboundFromContext(w.ctx); inbound != nil && inbound.Conn != nil {
			// Vision command=2 reached and reader switched to raw path. At this
			// point TLS decryption is no longer required on this leg, so the
			// response copy loop can safely transition to splice/readv-raw path.
			switch inbound.GetCanSpliceCopy() {
			case session.CopyGatePendingDetach:
				inbound.SetCanSpliceCopy(session.CopyGateEligible)
			case session.CopyGateForcedUserspace:
				if inbound.CopyGateReason() == session.CopyGateReasonVisionCommandContinue ||
					inbound.CopyGateReason() == session.CopyGateReasonVisionUplinkComplete {
					inbound.SetCanSpliceCopy(session.CopyGateEligible)
				}
			}
		}

		if inbound := session.InboundFromContext(w.ctx); inbound != nil && inbound.Conn != nil {
			// if w.isUplink && inbound.CanSpliceCopy == 2 { // TODO: enable uplink splice
			// 	inbound.CanSpliceCopy = 1
			// }
			if !w.isUplink && w.ob != nil { // ob need to be passed in due to context can have more than one ob
				switch w.ob.GetCanSpliceCopy() {
				case session.CopyGatePendingDetach:
					w.ob.SetCanSpliceCopy(session.CopyGateEligible)
				case session.CopyGateForcedUserspace:
					if w.ob.CopyGateReason() == session.CopyGateReasonVisionCommandContinue ||
						w.ob.CopyGateReason() == session.CopyGateReasonVisionUplinkComplete {
						w.ob.SetCanSpliceCopy(session.CopyGateEligible)
					}
				}
			}
		}
		if w.isUplink {
			wakeVisionResponseLoop(w.ctx, w.source.Conn(), "command=2")
		}
		readerConn, readCounter, _, readerHandler := UnwrapRawConn(w.source.Conn())
		w.directReadCounter = readCounter
		if readerHandler != nil {
			w.Reader = buf.NewReader(&ktlsReader{Conn: readerConn, handler: readerHandler})
		} else {
			w.Reader = buf.NewReader(readerConn)
		}
	}
	return buffer, err
}

// VisionWriter is used to write xtls vision protocol
// Note Vision probably only make sense as the inner most layer of writer, since it need assess traffic state from origin proxy traffic
type VisionWriter struct {
	buf.Writer
	trafficState *TrafficState
	ctx          context.Context
	isUplink     bool
	conn         net.Conn
	ob           *session.Outbound

	// internal
	writeOnceUserUUID  []byte
	directWriteCounter stats.Counter

	testseed []uint32
}

func NewVisionWriter(writer buf.Writer, trafficState *TrafficState, isUplink bool, ctx context.Context, conn net.Conn, ob *session.Outbound, testseed []uint32) *VisionWriter {
	w := make([]byte, len(trafficState.UserUUID))
	copy(w, trafficState.UserUUID)
	if len(testseed) < 4 {
		testseed = []uint32{900, 500, 900, 256}
	}
	return &VisionWriter{
		Writer:            writer,
		trafficState:      trafficState,
		ctx:               ctx,
		writeOnceUserUUID: w,
		isUplink:          isUplink,
		conn:              conn,
		ob:                ob,
		testseed:          testseed,
	}
}

func (w *VisionWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	ts := w.trafficState
	ts.Lock()
	locked := true
	unlock := func() {
		if locked {
			ts.Unlock()
			locked = false
		}
	}
	defer unlock()

	if ts.VisionPayloadBypassObserved {
		if !mb.IsEmpty() && w.directWriteCounter != nil {
			w.directWriteCounter.Add(int64(mb.Len()))
		}
		return w.Writer.WriteMultiBuffer(mb)
	}

	var isPadding *bool
	var switchToDirectCopy *bool
	if w.isUplink {
		isPadding = &ts.Outbound.IsPadding
		switchToDirectCopy = &ts.Outbound.UplinkWriterDirectCopy
	} else {
		isPadding = &ts.Inbound.IsPadding
		switchToDirectCopy = &ts.Inbound.DownlinkWriterDirectCopy
	}

	switchNow := *switchToDirectCopy
	if switchNow {
		if isDNSPortOutbound(w.ctx) {
			w.ctx = session.ContextWithDNSPlane(w.ctx, session.DNSPlaneVisionGuard)
			errors.LogInfo(w.ctx, "Vision: DNS control-plane flow (writer); keeping rustls (no detach/zero-copy)")
			switchNow = false
			*switchToDirectCopy = false
		}
		dc := unwrapVisionDeferredConn(w.conn)
		deferredReady := true
		if dc != nil && !dc.IsDetached() && !dc.KTLSEnabled().Enabled {
			deferredReady = false
			switchNow = false
		}

		if inbound := session.InboundFromContext(w.ctx); inbound != nil {
			if !w.isUplink && inbound.GetCanSpliceCopy() == session.CopyGatePendingDetach && deferredReady {
				inbound.SetCanSpliceCopy(session.CopyGateEligible)
			}
		}
		if switchNow {
			rawConn, _, writerCounter, _ := UnwrapRawConn(w.conn)
			w.Writer = buf.NewWriter(rawConn)
			w.directWriteCounter = writerCounter
			*switchToDirectCopy = false
		}
	}

	if !mb.IsEmpty() && w.directWriteCounter != nil {
		w.directWriteCounter.Add(int64(mb.Len()))
	}

	if ts.NumberOfPacketToFilter > 0 {
		XtlsFilterTls(mb, ts, w.ctx)
	}

	if *isPadding {
		if len(mb) == 1 && mb[0] == nil {
			mb[0] = XtlsPadding(nil, CommandPaddingContinue, &w.writeOnceUserUUID, true, w.ctx, w.testseed)
			unlock()
			return w.Writer.WriteMultiBuffer(mb)
		}
		isComplete := IsCompleteRecord(mb)
		mb = ReshapeMultiBuffer(w.ctx, mb)
		longPadding := ts.IsTLS
		for i, b := range mb {
			allowDirectOnFragmentedTLS13 := ts.EnableXtls
			if ts.IsTLS &&
				b.Len() >= 6 &&
				bytes.Equal(TlsApplicationDataStart, b.BytesTo(3)) &&
				(isComplete || allowDirectOnFragmentedTLS13) {
				if ts.EnableXtls {
					*switchToDirectCopy = true
				}
				var command byte = CommandPaddingContinue
				if i == len(mb)-1 {
					command = CommandPaddingEnd
					if ts.EnableXtls {
						command = CommandPaddingDirect
					}
				}
				mb[i] = XtlsPadding(b, command, &w.writeOnceUserUUID, true, w.ctx, w.testseed)
				*isPadding = false
				longPadding = false
				continue
			} else if !ts.IsTLS12orAbove && ts.NumberOfPacketToFilter <= 1 {
				*isPadding = false
				mb[i] = XtlsPadding(b, CommandPaddingEnd, &w.writeOnceUserUUID, longPadding, w.ctx, w.testseed)
				break
			}
			var command byte = CommandPaddingContinue
			if i == len(mb)-1 && !*isPadding {
				command = CommandPaddingEnd
				if ts.EnableXtls {
					command = CommandPaddingDirect
				}
			}
			mb[i] = XtlsPadding(b, command, &w.writeOnceUserUUID, longPadding, w.ctx, w.testseed)
		}
	}

	unlock()
	return w.Writer.WriteMultiBuffer(mb)
}

// IsCompleteRecord checks if the MultiBuffer contains complete TLS application
// data records. Scans across buffer segments in-place without copying.
func IsCompleteRecord(buffer buf.MultiBuffer) bool {
	s := newMultiBufferScanner(buffer)
	headerLen := 5
	recordLen := 0

	for s.remaining() > 0 {
		if headerLen > 0 {
			data := s.readByte()
			switch headerLen {
			case 5:
				if data != 0x17 {
					return false
				}
			case 4:
				if data != 0x03 {
					return false
				}
			case 3:
				if data != 0x03 {
					return false
				}
			case 2:
				recordLen = int(data) << 8
			case 1:
				recordLen = recordLen | int(data)
			}
			headerLen--
		} else if recordLen > 0 {
			if s.remaining() < recordLen {
				return false
			}
			s.skip(recordLen)
			recordLen = 0
			headerLen = 5
		} else {
			return false
		}
	}
	return headerLen == 5 && recordLen == 0
}

// multiBufferScanner walks a MultiBuffer's segments without copying.
type multiBufferScanner struct {
	mb     buf.MultiBuffer
	bufIdx int   // current buffer index
	offset int32 // offset within current buffer
	total  int   // total remaining bytes
}

func newMultiBufferScanner(mb buf.MultiBuffer) multiBufferScanner {
	total := 0
	for _, b := range mb {
		if b != nil {
			total += int(b.Len())
		}
	}
	s := multiBufferScanner{mb: mb, total: total}
	s.advance() // skip nil/empty leading buffers
	return s
}

// advance moves past nil/empty buffers.
func (s *multiBufferScanner) advance() {
	for s.bufIdx < len(s.mb) {
		b := s.mb[s.bufIdx]
		if b != nil && s.offset < b.Len() {
			return
		}
		s.bufIdx++
		s.offset = 0
	}
}

func (s *multiBufferScanner) remaining() int {
	return s.total
}

func (s *multiBufferScanner) readByte() byte {
	if s.bufIdx >= len(s.mb) {
		return 0
	}
	b := s.mb[s.bufIdx]
	val := b.Byte(s.offset)
	s.offset++
	s.total--
	if s.offset >= b.Len() {
		s.bufIdx++
		s.offset = 0
		s.advance()
	}
	return val
}

func (s *multiBufferScanner) skip(n int) {
	s.total -= n
	for n > 0 && s.bufIdx < len(s.mb) {
		b := s.mb[s.bufIdx]
		avail := int(b.Len() - s.offset)
		if avail > n {
			s.offset += int32(n)
			return
		}
		n -= avail
		s.bufIdx++
		s.offset = 0
		s.advance()
	}
}

// ReshapeMultiBuffer prepare multi buffer for padding structure (max 21 bytes)
func ReshapeMultiBuffer(ctx context.Context, buffer buf.MultiBuffer) buf.MultiBuffer {
	needReshape := 0
	for _, b := range buffer {
		if b.Len() >= buf.Size-21 {
			needReshape += 1
		}
	}
	if needReshape == 0 {
		return buffer
	}
	mb2 := buf.GetMultiBuffer()
	for i, buffer1 := range buffer {
		if buffer1.Len() >= buf.Size-21 {
			index := int32(bytes.LastIndex(buffer1.Bytes(), TlsApplicationDataStart))
			if index < 21 || index > buf.Size-21 {
				index = buf.Size / 2
			}
			buffer2 := buf.New()
			buffer2.Write(buffer1.BytesFrom(index))
			buffer1.Resize(0, index)
			mb2 = append(mb2, buffer1, buffer2)
		} else {
			mb2 = append(mb2, buffer1)
		}
		buffer[i] = nil
	}
	buffer = buffer[:0]
	errors.LogDebug(ctx, "ReshapeMultiBuffer: reshaped ", needReshape, " oversized buffer(s)")
	return mb2
}

// XtlsPadding add padding to eliminate length signature during tls handshake
func XtlsPadding(b *buf.Buffer, command byte, userUUID *[]byte, longPadding bool, ctx context.Context, testseed []uint32) *buf.Buffer {
	// Delegate to Rust when the native library is linked.
	if native.Available() {
		return xtlsPaddingRust(b, command, userUUID, longPadding, ctx, testseed)
	}
	return xtlsPaddingGoFallback(b, command, userUUID, longPadding, ctx, testseed)
}

// xtlsPaddingRust delegates Vision padding to the Rust native library.
func xtlsPaddingRust(b *buf.Buffer, command byte, userUUID *[]byte, longPadding bool, ctx context.Context, testseed []uint32) *buf.Buffer {
	var data []byte
	if b != nil {
		data = b.Bytes()
	}
	var uuid []byte
	if userUUID != nil {
		uuid = *userUUID
	}

	// Ensure testseed has 4 elements.
	var seeds [4]uint32
	copy(seeds[:], testseed)

	var outBuf *buf.Buffer
	if arena := buf.ArenaFromContext(ctx); arena != nil {
		outBuf = arena.NewBuffer()
	} else {
		outBuf = buf.New()
	}
	// Extend to full capacity to get a writable slice, then resize after.
	outBytes := outBuf.Extend(buf.Size)

	n, err := native.VisionPad(data, command, uuid, longPadding, seeds, outBytes)
	if err != nil {
		// Fallback to Go implementation on error.
		outBuf.Release()
		errors.LogDebugInner(ctx, err, "native VisionPad failed, falling back to Go")
		return xtlsPaddingGoFallback(b, command, userUUID, longPadding, ctx, testseed)
	}

	// Resize to actual written length.
	outBuf.Resize(0, int32(n))

	// Clean up inputs.
	if userUUID != nil {
		*userUUID = nil
	}
	if b != nil {
		b.Release()
	}

	return outBuf
}

// xtlsPaddingGoFallback is the original Go padding implementation.
func xtlsPaddingGoFallback(b *buf.Buffer, command byte, userUUID *[]byte, longPadding bool, ctx context.Context, testseed []uint32) *buf.Buffer {
	var contentLen int32 = 0
	var paddingLen int32 = 0
	if b != nil {
		contentLen = b.Len()
	}
	if contentLen < int32(testseed[0]) && longPadding {
		paddingLen = int32(cryptoRandIntn(testseed[1])) + int32(testseed[2]) - contentLen
	} else {
		paddingLen = int32(cryptoRandIntn(testseed[3]))
	}
	if paddingLen > buf.Size-21-contentLen {
		paddingLen = buf.Size - 21 - contentLen
	}
	var newbuffer *buf.Buffer
	if arena := buf.ArenaFromContext(ctx); arena != nil {
		newbuffer = arena.NewBuffer()
	} else {
		newbuffer = buf.New()
	}
	if userUUID != nil {
		newbuffer.Write(*userUUID)
		*userUUID = nil
	}
	hdr := [5]byte{command, byte(contentLen >> 8), byte(contentLen), byte(paddingLen >> 8), byte(paddingLen)}
	newbuffer.Write(hdr[:])
	if b != nil {
		newbuffer.Write(b.Bytes())
		b.Release()
		b = nil
	}
	newbuffer.Extend(paddingLen)
	errors.LogDebug(ctx, "XtlsPadding ", contentLen, " ", paddingLen, " ", command)
	return newbuffer
}

// cryptoRandIntn returns a cryptographically random int64 in [0, n).
// On RNG failure, falls back to a time-derived value rather than returning 0.
//
// Trade-off: time-based padding is statistically distinguishable from CSPRNG
// output by a DPI adversary with sub-microsecond timing. However, crypto/rand
// failure means /dev/urandom is broken — the system is already unable to
// perform TLS handshakes, so this is a degraded mode for a degraded system.
// This is strictly better than the previous behavior (nil pointer panic).
func cryptoRandIntn(n uint32) int64 {
	if n == 0 {
		return 0
	}
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return int64(uint32(time.Now().UnixNano()) % n)
	}
	return int64(binary.BigEndian.Uint32(buf[:]) % n)
}

// XtlsUnpadding remove padding and parse command
func XtlsUnpadding(b *buf.Buffer, s *TrafficState, isUplink bool, ctx context.Context) *buf.Buffer {
	var remainingCommand *int32
	var remainingContent *int32
	var remainingPadding *int32
	var currentCommand *int
	if isUplink {
		remainingCommand = &s.Inbound.RemainingCommand
		remainingContent = &s.Inbound.RemainingContent
		remainingPadding = &s.Inbound.RemainingPadding
		currentCommand = &s.Inbound.CurrentCommand
	} else {
		remainingCommand = &s.Outbound.RemainingCommand
		remainingContent = &s.Outbound.RemainingContent
		remainingPadding = &s.Outbound.RemainingPadding
		currentCommand = &s.Outbound.CurrentCommand
	}
	if *remainingCommand == -1 && *remainingContent == -1 && *remainingPadding == -1 { // initial state
		if b.Len() >= 21 && bytes.Equal(s.UserUUID, b.BytesTo(16)) {
			b.Advance(16)
			*remainingCommand = 5
		} else {
			return b
		}
	}
	var newbuffer *buf.Buffer
	if arena := buf.ArenaFromContext(ctx); arena != nil {
		newbuffer = arena.NewBuffer()
	} else {
		newbuffer = buf.New()
	}
	for b.Len() > 0 {
		if *remainingCommand > 0 {
			data, err := b.ReadByte()
			if err != nil {
				return newbuffer
			}
			switch *remainingCommand {
			case 5:
				*currentCommand = int(data)
			case 4:
				*remainingContent = int32(data) << 8
			case 3:
				*remainingContent = *remainingContent | int32(data)
			case 2:
				*remainingPadding = int32(data) << 8
			case 1:
				*remainingPadding = *remainingPadding | int32(data)
				errors.LogDebug(ctx, "Xtls Unpadding new block, content ", *remainingContent, " padding ", *remainingPadding, " command ", *currentCommand)
			}
			*remainingCommand--
		} else if *remainingContent > 0 {
			len := *remainingContent
			if b.Len() < len {
				len = b.Len()
			}
			data, err := b.ReadBytes(len)
			if err != nil {
				return newbuffer
			}
			newbuffer.Write(data)
			*remainingContent -= len
		} else { // remainingPadding > 0
			len := *remainingPadding
			if b.Len() < len {
				len = b.Len()
			}
			b.Advance(len)
			*remainingPadding -= len
		}
		if *remainingCommand <= 0 && *remainingContent <= 0 && *remainingPadding <= 0 { // this block done
			if *currentCommand == 0 {
				*remainingCommand = 5
			} else {
				*remainingCommand = -1 // set to initial state
				*remainingContent = -1
				*remainingPadding = -1
				if b.Len() > 0 { // shouldn't happen
					newbuffer.Write(b.Bytes())
				}
				break
			}
		}
	}
	b.Release()
	b = nil
	return newbuffer
}

// XtlsFilterTls filter and recognize tls 1.3 and other info
func XtlsFilterTls(buffer buf.MultiBuffer, trafficState *TrafficState, ctx context.Context) {
	for _, b := range buffer {
		if b == nil {
			continue
		}
		trafficState.NumberOfPacketToFilter--
		if b.Len() >= 6 {
			startsBytes := b.BytesTo(6)
			if bytes.Equal(TlsServerHandShakeStart, startsBytes[:3]) && startsBytes[5] == TlsHandshakeTypeServerHello {
				trafficState.RemainingServerHello = (int32(startsBytes[3])<<8 | int32(startsBytes[4])) + 5
				trafficState.IsTLS12orAbove = true
				trafficState.IsTLS = true
				if b.Len() >= 79 && trafficState.RemainingServerHello >= 79 {
					sessionIdLen := min(int32(b.Byte(43)), 32) // TLS session IDs are at most 32 bytes
					if 43+sessionIdLen+3 > b.Len() {
						errors.LogDebug(ctx, "XtlsFilterTls sessionIdLen exceeds buffer, skipping cipher suite parse")
					} else {
						cipherSuite := b.BytesRange(43+sessionIdLen+1, 43+sessionIdLen+3)
						trafficState.Cipher = uint16(cipherSuite[0])<<8 | uint16(cipherSuite[1])
					}
				} else {
					errors.LogDebug(ctx, "XtlsFilterTls short server hello, tls 1.2 or older? ", b.Len(), " ", trafficState.RemainingServerHello)
				}
			} else if bytes.Equal(TlsClientHandShakeStart, startsBytes[:2]) && startsBytes[5] == TlsHandshakeTypeClientHello {
				trafficState.IsTLS = true
				errors.LogDebug(ctx, "XtlsFilterTls found tls client hello! ", buffer.Len())
			}
		}
		if trafficState.RemainingServerHello > 0 {
			end := trafficState.RemainingServerHello
			if end > b.Len() {
				end = b.Len()
			}
			trafficState.RemainingServerHello -= b.Len()
			if bytes.Contains(b.BytesTo(end), Tls13SupportedVersions) {
				v, ok := Tls13CipherSuiteDic[trafficState.Cipher]
				if !ok {
					v = "Old cipher: " + strconv.FormatUint(uint64(trafficState.Cipher), 16)
				} else if v != "TLS_AES_128_CCM_8_SHA256" {
					trafficState.EnableXtls = true
				}
				errors.LogDebug(ctx, "XtlsFilterTls found tls 1.3! ", b.Len(), " ", v)
				trafficState.NumberOfPacketToFilter = 0
				return
			} else if trafficState.RemainingServerHello <= 0 {
				errors.LogDebug(ctx, "XtlsFilterTls found tls 1.2! ", b.Len())
				trafficState.NumberOfPacketToFilter = 0
				return
			}
			errors.LogDebug(ctx, "XtlsFilterTls inconclusive server hello ", b.Len(), " ", trafficState.RemainingServerHello)
		}
		if trafficState.NumberOfPacketToFilter <= 0 {
			errors.LogDebug(ctx, "XtlsFilterTls stop filtering", buffer.Len())
		}
	}
}

// ktlsReader wraps a raw connection to handle EKEYEXPIRED errors from kTLS
// when the peer sends a TLS 1.3 KeyUpdate message.
type ktlsReader struct {
	net.Conn
	handler *tls.KTLSKeyUpdateHandler
}

func (r *ktlsReader) Read(b []byte) (int, error) {
	n, err := r.Conn.Read(b)
	if err != nil && tls.IsKeyExpired(err) && r.handler != nil {
		if herr := r.handler.Handle(); herr != nil {
			return 0, herr
		}
		return r.Conn.Read(b)
	}
	return n, err
}

// UnwrapRawConn support unwrap encryption, stats, tls, utls, reality, proxyproto, uds-wrapper conn and get raw tcp/uds conn from it
func UnwrapRawConn(conn net.Conn) (net.Conn, stats.Counter, stats.Counter, *tls.KTLSKeyUpdateHandler) {
	var readCounter, writerCounter stats.Counter
	var handler *tls.KTLSKeyUpdateHandler
	if conn != nil {
		isEncryption := false
		if commonConn, ok := conn.(*encryption.CommonConn); ok {
			conn = commonConn.Conn
			isEncryption = true
		}
		if xorConn, ok := conn.(*encryption.XorConn); ok {
			return xorConn, nil, nil, nil // full-random xorConn should not be penetrated
		}
		if statConn, ok := conn.(*stat.CounterConnection); ok {
			conn = statConn.Connection
			readCounter = statConn.ReadCounter
			writerCounter = statConn.WriteCounter
		}
		if !isEncryption { // avoids double penetration
			if xc, ok := conn.(*tls.Conn); ok {
				handler = xc.KTLSKeyUpdateHandler()
				conn = xc.NetConn()
			} else if rc, ok := conn.(*tls.RustConn); ok {
				handler = rc.KTLSKeyUpdateHandler()
				conn = rc.NetConn()
			} else if dc, ok := conn.(*tls.DeferredRustConn); ok {
				if !dc.IsDetached() && !dc.KTLSEnabled().Enabled {
					storeVisionRawUnwrapWarningTimestamp(dc, time.Now().UnixNano())
					pipelineMarkerDeferredRawUnwrapWarning.Add(1)
					maybeLogPipelineRuntimeSummary(context.Background())
					// Deny raw unwrap: keep the deferred connection intact and return
					// the wrapper so callers don't crash on nil.
					return dc, readCounter, writerCounter, handler
				}
				handler = dc.KTLSKeyUpdateHandler()
				conn = dc.NetConn()
			} else if utlsConn, ok := conn.(*tls.UConn); ok {
				conn = utlsConn.NetConn()
			} else if realityConn, ok := conn.(*reality.Conn); ok {
				conn = realityConn.NetConn()
			} else if realityUConn, ok := conn.(*reality.UConn); ok {
				conn = realityUConn.NetConn()
			}
		}
		if pc, ok := conn.(*proxyproto.Conn); ok {
			conn = pc.Raw()
			// 8192 > 4096, there is no need to process pc's bufReader
		}
		if uc, ok := conn.(*internet.UnixConnWrapper); ok {
			conn = uc.UnixConn
		}
	}
	return conn, readCounter, writerCounter, handler
}

// startKeyUpdateMonitor creates and starts a KeyUpdateMonitor for a raw
// connection with the given handler. Returns nil (safe to Stop()) on any
// failure. Used by zero-copy paths (SOCKMAP, splice) that bypass Write()
// and thus skip the per-record write counter for TX key rotation.
func startKeyUpdateMonitor(rawConn net.Conn, handler *tls.KTLSKeyUpdateHandler) *tls.KeyUpdateMonitor {
	if handler == nil {
		return nil
	}
	fd, err := tls.ExtractFd(rawConn)
	if err != nil {
		return nil
	}
	m := tls.NewKeyUpdateMonitor(fd, handler)
	m.Start()
	return m
}

// DetermineSocketCryptoHint peels off connection wrappers and returns the
// underlying raw connection plus a CryptoHint describing the TLS state.
// This must be called BEFORE UnwrapRawConn because it inspects TLS wrappers.
func DetermineSocketCryptoHint(conn net.Conn) (net.Conn, ebpf.CryptoHint) {
	raw, hint, _ := determineSocketCryptoHintWithSource(conn)
	return raw, hint
}

const maxCryptoHintDepth = 8

func determineSocketCryptoHintWithSource(conn net.Conn) (net.Conn, ebpf.CryptoHint, string) {
	return determineSocketCryptoHintRecurse(conn, 0)
}

func determineSocketCryptoHintRecurse(conn net.Conn, depth int) (net.Conn, ebpf.CryptoHint, string) {
	if conn == nil {
		return nil, ebpf.CryptoNone, "nil"
	}
	if depth > maxCryptoHintDepth {
		// Conservative default: assume userspace TLS to prevent sockmap
		// from forwarding data under incorrect crypto assumptions.
		return nil, ebpf.CryptoUserspaceTLS, "depth-exceeded"
	}
	source := connTypeName(conn)

	// Peel encryption wrappers
	if commonConn, ok := conn.(*encryption.CommonConn); ok {
		source = appendCryptoHintSource(source, "*encryption.CommonConn")
		conn = commonConn.Conn
	}
	if _, ok := conn.(*encryption.XorConn); ok {
		return nil, ebpf.CryptoUserspaceTLS, appendCryptoHintSource(source, "*encryption.XorConn")
	}

	// Peel stats and proxyproto wrappers before TLS inspection.
	// NOTE: peel order here differs from UnwrapRawConn (which peels proxyproto
	// after TLS). Both orderings are correct because the type assertions are
	// independent — if proxyproto wraps TLS, we peel it first and see TLS next;
	// if TLS wraps proxyproto, the TLS branch fires first.
	if statConn, ok := conn.(*stat.CounterConnection); ok {
		source = appendCryptoHintSource(source, "*stat.CounterConnection")
		conn = statConn.Connection
	}
	if pc, ok := conn.(*proxyproto.Conn); ok {
		source = appendCryptoHintSource(source, "*proxyproto.Conn")
		conn = pc.Raw()
	}

	// Check TLS type
	if xc, ok := conn.(*tls.Conn); ok {
		ktls := xc.KTLSEnabled()
		raw := xc.NetConn()
		if ktls.TxReady && ktls.RxReady {
			return raw, ebpf.CryptoKTLSBoth, appendCryptoHintSource(source, "*tls.Conn("+ktlsStateName(ktls.TxReady, ktls.RxReady)+")")
		}
		if ktls.TxReady {
			return raw, ebpf.CryptoKTLSTxOnly, appendCryptoHintSource(source, "*tls.Conn("+ktlsStateName(ktls.TxReady, ktls.RxReady)+")")
		}
		if ktls.RxReady {
			return raw, ebpf.CryptoKTLSRxOnly, appendCryptoHintSource(source, "*tls.Conn("+ktlsStateName(ktls.TxReady, ktls.RxReady)+")")
		}
		return raw, ebpf.CryptoUserspaceTLS, appendCryptoHintSource(source, "*tls.Conn("+ktlsStateName(ktls.TxReady, ktls.RxReady)+")")
	}

	if rc, ok := conn.(*tls.RustConn); ok {
		ktls := rc.KTLSEnabled()
		raw := rc.NetConn()
		if ktls.TxReady && ktls.RxReady {
			return raw, ebpf.CryptoKTLSBoth, appendCryptoHintSource(source, "*tls.RustConn("+ktlsStateName(ktls.TxReady, ktls.RxReady)+")")
		}
		if ktls.TxReady {
			return raw, ebpf.CryptoKTLSTxOnly, appendCryptoHintSource(source, "*tls.RustConn("+ktlsStateName(ktls.TxReady, ktls.RxReady)+")")
		}
		if ktls.RxReady {
			return raw, ebpf.CryptoKTLSRxOnly, appendCryptoHintSource(source, "*tls.RustConn("+ktlsStateName(ktls.TxReady, ktls.RxReady)+")")
		}
		return raw, ebpf.CryptoUserspaceTLS, appendCryptoHintSource(source, "*tls.RustConn("+ktlsStateName(ktls.TxReady, ktls.RxReady)+")")
	}

	if dc, ok := conn.(*tls.DeferredRustConn); ok {
		ktls := dc.KTLSEnabled()
		raw := dc.NetConn()
		if ktls.TxReady && ktls.RxReady {
			return raw, ebpf.CryptoKTLSBoth, appendCryptoHintSource(source, "*tls.DeferredRustConn("+ktlsStateName(ktls.TxReady, ktls.RxReady)+")")
		}
		if ktls.TxReady {
			return raw, ebpf.CryptoKTLSTxOnly, appendCryptoHintSource(source, "*tls.DeferredRustConn("+ktlsStateName(ktls.TxReady, ktls.RxReady)+")")
		}
		if ktls.RxReady {
			return raw, ebpf.CryptoKTLSRxOnly, appendCryptoHintSource(source, "*tls.DeferredRustConn("+ktlsStateName(ktls.TxReady, ktls.RxReady)+")")
		}
		if dc.IsDetached() {
			// After Vision command=2 drain+detach, outer rustls is removed and
			// bytes flow on the raw socket. Classify as raw TCP for sockmap policy.
			return raw, ebpf.CryptoNone, appendCryptoHintSource(source, "*tls.DeferredRustConn(detached)")
		}
		return raw, ebpf.CryptoUserspaceTLS, appendCryptoHintSource(source, "*tls.DeferredRustConn("+ktlsStateName(ktls.TxReady, ktls.RxReady)+")")
	}

	if utlsConn, ok := conn.(*tls.UConn); ok {
		if utlsConn == nil || utlsConn.UConn == nil {
			return nil, ebpf.CryptoUserspaceTLS, appendCryptoHintSource(source, "*tls.UConn(nil)")
		}
		inner := utlsConn.NetConn()
		innerRaw, _, innerSource := determineSocketCryptoHintRecurse(inner, depth+1)
		return innerRaw, ebpf.CryptoUserspaceTLS, appendCryptoHintSource(source, "*tls.UConn(userspace inner="+innerSource+")")
	}
	if realityConn, ok := conn.(*reality.Conn); ok {
		if realityConn == nil || realityConn.Conn == nil {
			return nil, ebpf.CryptoUserspaceTLS, appendCryptoHintSource(source, "*reality.Conn(nil)")
		}
		inner := realityConn.NetConn()
		innerRaw, _, innerSource := determineSocketCryptoHintRecurse(inner, depth+1)
		return innerRaw, ebpf.CryptoUserspaceTLS, appendCryptoHintSource(source, "*reality.Conn(userspace inner="+innerSource+")")
	}
	if realityUConn, ok := conn.(*reality.UConn); ok {
		if realityUConn == nil || realityUConn.UConn == nil {
			return nil, ebpf.CryptoUserspaceTLS, appendCryptoHintSource(source, "*reality.UConn(nil)")
		}
		inner := realityUConn.NetConn()
		innerRaw, _, innerSource := determineSocketCryptoHintRecurse(inner, depth+1)
		return innerRaw, ebpf.CryptoUserspaceTLS, appendCryptoHintSource(source, "*reality.UConn(userspace inner="+innerSource+")")
	}

	if _, ok := conn.(*net.TCPConn); ok {
		return conn, ebpf.CryptoNone, appendCryptoHintSource(source, "*net.TCPConn(raw)")
	}

	return nil, ebpf.CryptoNone, appendCryptoHintSource(source, connTypeName(conn))
}

func isLoopbackConnPair(a, b gonet.Conn) bool {
	if a == nil || b == nil {
		return false
	}
	la, lok := a.LocalAddr().(*net.TCPAddr)
	ra, rok := a.RemoteAddr().(*net.TCPAddr)
	lb, lbok := b.LocalAddr().(*net.TCPAddr)
	rb, rbok := b.RemoteAddr().(*net.TCPAddr)
	if !(lok && rok && lbok && rbok) {
		return false
	}
	return la.IP.IsLoopback() && ra.IP.IsLoopback() && lb.IP.IsLoopback() && rb.IP.IsLoopback()
}

func buildVisionDecisionInput(readerConn gonet.Conn, writerConn gonet.Conn, caps pipeline.CapabilitySummary, deferredTLSActive bool) (pipeline.DecisionInput, ebpf.CryptoHint, ebpf.CryptoHint, string, string) {
	rawReaderConn, readerCrypto, readerCryptoSource := determineSocketCryptoHintWithSource(readerConn)
	rawWriterConn, writerCrypto, writerCryptoSource := determineSocketCryptoHintWithSource(writerConn)
	input := pipeline.DecisionInput{
		DeferredTLSActive: deferredTLSActive,
		LoopbackPair:      isLoopbackConnPair(rawReaderConn, rawWriterConn),
		Caps:              caps,
		ReaderCrypto:      cryptoHintName(readerCrypto),
		WriterCrypto:      cryptoHintName(writerCrypto),
	}
	return input, readerCrypto, writerCrypto, readerCryptoSource, writerCryptoSource
}

// After Vision explicitly promotes a flow to direct-copy eligibility, the raw
// sockets become the correct acceleration decision surface even if the outer
// conn object still reports userspace TLS wrappers.
func buildVisionDecisionInputForCopyGate(
	readerConn gonet.Conn,
	writerConn gonet.Conn,
	rawReaderConn gonet.Conn,
	rawWriterConn gonet.Conn,
	caps pipeline.CapabilitySummary,
	deferredTLSActive bool,
	inboundGate session.CopyGateState,
) (pipeline.DecisionInput, ebpf.CryptoHint, ebpf.CryptoHint, string, string) {
	if inboundGate == session.CopyGateEligible && !deferredTLSActive && rawReaderConn != nil && rawWriterConn != nil {
		return buildVisionDecisionInput(rawReaderConn, rawWriterConn, caps, deferredTLSActive)
	}
	return buildVisionDecisionInput(readerConn, writerConn, caps, deferredTLSActive)
}

func isLoopbackConn(conn gonet.Conn) bool {
	if conn == nil {
		return false
	}
	if la := conn.LocalAddr(); la != nil {
		if ip := extractAddrIP(la); ip != nil && ip.IsLoopback() {
			return true
		}
	}
	if ra := conn.RemoteAddr(); ra != nil {
		if ip := extractAddrIP(ra); ip != nil && ip.IsLoopback() {
			return true
		}
	}
	return false
}

func extractAddrIP(addr gonet.Addr) net.IP {
	switch a := addr.(type) {
	case *gonet.TCPAddr:
		return a.IP
	case *gonet.UDPAddr:
		return a.IP
	}
	host, _, err := gonet.SplitHostPort(addr.String())
	if err != nil {
		return nil
	}
	return net.ParseAddress(host).IP()
}

func mapCopyGateState(state session.CopyGateState) pipeline.CopyGateState {
	switch state {
	case session.CopyGateEligible:
		return pipeline.CopyGateEligible
	case session.CopyGatePendingDetach:
		return pipeline.CopyGatePendingDetach
	case session.CopyGateForcedUserspace:
		return pipeline.CopyGateForcedUserspace
	case session.CopyGateNotApplicable:
		return pipeline.CopyGateNotApplicable
	default:
		return pipeline.CopyGateUnset
	}
}

func mapCopyGateReason(reason session.CopyGateReason) pipeline.CopyGateReason {
	switch reason {
	case session.CopyGateReasonFlowNonVisionPolicy:
		return pipeline.CopyGateReasonFlowNonVisionPolicy
	case session.CopyGateReasonTransportNonRawSplitConn:
		return pipeline.CopyGateReasonTransportNonRawSplitConn
	case session.CopyGateReasonTransportUserspace:
		return pipeline.CopyGateReasonTransportUserspace
	case session.CopyGateReasonVisionBypass:
		return pipeline.CopyGateReasonVisionBypass
	case session.CopyGateReasonVisionNoDetach:
		return pipeline.CopyGateReasonVisionNoDetach
	case session.CopyGateReasonVisionUplinkComplete:
		return pipeline.CopyGateReasonVisionUplinkComplete
	case session.CopyGateReasonVisionCommandContinue:
		return pipeline.CopyGateReasonVisionCommandContinue
	case session.CopyGateReasonDetachTimeout:
		return pipeline.CopyGateReasonDetachTimeout
	case session.CopyGateReasonSecurityGuard:
		return pipeline.CopyGateReasonSecurityGuard
	case session.CopyGateReasonMetadataMissing:
		return pipeline.CopyGateReasonMetadataMissing
	default:
		return pipeline.CopyGateReasonUnspecified
	}
}

// CopyRawConnIfExist use the most efficient copy method.
// - If caller don't want to turn on splice, do not pass in both reader conn and writer conn
// - writer are from *transport.Link
func CopyRawConnIfExist(ctx context.Context, readerConn net.Conn, writerConn net.Conn, writer buf.Writer, timer *signal.ActivityTimer, inTimer *signal.ActivityTimer) error {
	disableAccel := os.Getenv("XRAY_DEBUG_DISABLE_ACCEL") == "1"
	disableIdle := os.Getenv("XRAY_DEBUG_IDLE_INFINITE") == "1"
	userspaceReader := buf.NewReader(readerConn)

	decisionCaps := pipelineCapabilities()
	dnsFlowClass := session.ResolveDNSFlowClass(ctx)
	dnsPlane := session.DNSPlaneFromContext(ctx)
	decision := pipeline.DecisionSnapshot{
		Path:           pipeline.PathUserspace,
		Reason:         pipeline.ReasonDefault,
		Caps:           decisionCaps,
		Kind:           "proxy",
		CopyPath:       pipeline.CopyPathUserspace,
		TLSOffloadPath: pipeline.TLSOffloadUserspace,
		CopyGateState:  pipeline.CopyGateUnset,
		CopyGateReason: pipeline.CopyGateReasonUnspecified,
		DNSFlowClass:   dnsFlowClass.String(),
		DNSPlane:       string(dnsPlane),
	}
	postDetachRetrySeen := false
	finalizeDecision := func() {
		if decision.CopyPath != pipeline.CopyPathNotApplicable {
			switch decision.Path {
			case pipeline.PathSplice:
				decision.CopyPath = pipeline.CopyPathSplice
			case pipeline.PathSockmap:
				decision.CopyPath = pipeline.CopyPathSockmap
			case pipeline.PathUserspace:
				if decision.CopyPath == pipeline.CopyPathUnknown {
					decision.CopyPath = pipeline.CopyPathUserspace
				}
			}
		}
		if decision.TLSOffloadPath == pipeline.TLSOffloadUnknown {
			if decision.Path == pipeline.PathKTLS {
				decision.TLSOffloadPath = pipeline.TLSOffloadKTLS
			} else {
				decision.TLSOffloadPath = pipeline.TLSOffloadUserspace
			}
		}
		if decision.CopyGateState == "" {
			decision.CopyGateState = pipeline.CopyGateUnset
		}
		if decision.CopyGateReason == "" {
			decision.CopyGateReason = pipeline.CopyGateReasonUnspecified
		}
		if decision.UserspaceExit == "" && postDetachRetrySeen && decision.Path != pipeline.PathUserspace {
			decision.UserspaceExit = pipeline.UserspaceExitPostDetachRetrySuccess
		}
		if decision.UserspaceExit == "" {
			decision.UserspaceExit = pipeline.UserspaceExitNone
		}
	}
	defer func() {
		finalizeDecision()
		logPipelineDecision(ctx, string(decision.Path), decision.Reason, decisionCaps)
		logPipelineSummary(ctx, decision)
	}()
	defer clearVisionTelemetryTimestamps(readerConn, writerConn)
	registerVisionResponseWakeTarget(writerConn, readerConn)
	defer unregisterVisionResponseWakeTarget(writerConn)

	var (
		rawReady                     bool
		rawReaderConn, rawWriterConn net.Conn
		readCounter, writeCounter    stats.Counter
		readerHandler, writerHandler *tls.KTLSKeyUpdateHandler
		rawWriterTCP                 *net.TCPConn
		rawUserspaceReader           buf.Reader
		readerCrypto                 ebpf.CryptoHint
		writerCrypto                 ebpf.CryptoHint
		readerCryptoSource           string
		writerCryptoSource           string
	)
	ensureRaw := func() bool {
		if rawReady {
			return true
		}
		candidateReaderConn, candidateReadCounter, _, candidateReaderHandler := UnwrapRawConn(readerConn)
		candidateWriterConn, _, candidateWriteCounter, candidateWriterHandler := UnwrapRawConn(writerConn)

		if runtime.GOOS != "linux" && runtime.GOOS != "android" {
			pipelineMarkerEnsureRawFailOS.Add(1)
			errors.LogDebug(ctx, "CopyRawConn fallback to readv: unsupported OS ", runtime.GOOS)
			return false
		}
		if candidateReaderConn == nil || candidateWriterConn == nil {
			pipelineMarkerEnsureRawFailNilConn.Add(1)
			errors.LogDebug(ctx, "CopyRawConn fallback to readv: nil raw conn(s) readerType=", connTypeName(candidateReaderConn), " writerType=", connTypeName(candidateWriterConn))
			return false
		}
		tc, ok := candidateWriterConn.(*net.TCPConn)
		if !ok {
			pipelineMarkerEnsureRawFailWriterType.Add(1)
			errors.LogDebug(ctx, "CopyRawConn fallback to readv: writer is not *net.TCPConn (writerType=", connTypeName(candidateWriterConn), ")")
			return false
		}

		readerForUserspace := candidateReaderConn
		if candidateReaderHandler != nil {
			readerForUserspace = &ktlsReader{Conn: candidateReaderConn, handler: candidateReaderHandler}
		}

		rawReaderConn = candidateReaderConn
		rawWriterConn = candidateWriterConn
		readCounter = candidateReadCounter
		writeCounter = candidateWriteCounter
		readerHandler = candidateReaderHandler
		writerHandler = candidateWriterHandler
		rawWriterTCP = tc
		rawUserspaceReader = buf.NewReader(readerForUserspace)
		rawReady = true
		return true
	}

	inbound := session.InboundFromContext(ctx)
	if inbound == nil {
		errors.LogDebug(ctx, "CopyRawConn fallback to readv: missing inbound metadata")
		decision.Reason = pipeline.ReasonMissingInboundMetadata
		decision.CopyGateReason = pipeline.CopyGateReasonMetadataMissing
		decision.CopyGateState = pipeline.CopyGateUnset
		sc := &buf.SizeCounter{}
		start := time.Now()
		err := readV(ctx, userspaceReader, writer, timer, nil, sc)
		decision.UserspaceBytes = sc.Size
		decision.UserspaceDurationNs = time.Since(start).Nanoseconds()
		decision.Path = pipeline.PathUserspace
		applyUserspaceExit(&decision, err, false)
		return err
	}
	decision.CopyGateState = mapCopyGateState(inbound.CopyGateState())
	decision.CopyGateReason = mapCopyGateReason(inbound.CopyGateReason())
	outbounds := session.OutboundsFromContext(ctx)
	if len(outbounds) == 0 {
		errors.LogDebug(ctx, "CopyRawConn fallback to readv: no outbound metadata")
		decision.Reason = pipeline.ReasonMissingOutboundMetadata
		decision.CopyGateReason = pipeline.CopyGateReasonMetadataMissing
		sc := &buf.SizeCounter{}
		start := time.Now()
		err := readV(ctx, userspaceReader, writer, timer, nil, sc)
		decision.UserspaceBytes = sc.Size
		decision.UserspaceDurationNs = time.Since(start).Nanoseconds()
		decision.Path = pipeline.PathUserspace
		applyUserspaceExit(&decision, err, false)
		return err
	}
	var outGateStates []pipeline.CopyGateState
	var outGateReasons []pipeline.CopyGateReason
	for _, ob := range outbounds {
		outGateStates = append(outGateStates, mapCopyGateState(ob.CopyGateState()))
		outGateReasons = append(outGateReasons, mapCopyGateReason(ob.CopyGateReason()))
	}
	if decision.CopyGateState == pipeline.CopyGateUnset && len(outGateStates) > 0 {
		decision.CopyGateState = outGateStates[0]
		if r := outGateReasons[0]; r != pipeline.CopyGateReasonUnspecified {
			decision.CopyGateReason = r
		}
	}
	if reason, gate, gateReason, copyPath, stop := pipeline.EvaluateCopyGate(pipeline.CopyGateInput{
		InboundGate:    decision.CopyGateState,
		InboundReason:  decision.CopyGateReason,
		OutboundGates:  outGateStates,
		OutboundReason: outGateReasons,
	}); stop {
		dnsControlPlaneFlow := session.ShouldBypassVisionDetach(ctx)
		if dnsControlPlaneFlow && gateReason == pipeline.CopyGateReasonVisionBypass {
			reason = pipeline.ReasonControlPlaneDNSGuard
			if decision.DNSPlane == string(session.DNSPlaneUnknown) || decision.DNSPlane == "" {
				decision.DNSPlane = string(session.DNSPlaneVisionGuard)
			}
		}
		decision.Reason = reason
		decision.CopyGateState = gate
		decision.CopyGateReason = gateReason
		if copyPath != pipeline.CopyPathUnknown {
			decision.CopyPath = copyPath
		}
		prepareVisionStableUserspaceRead(readerConn, writerConn)
		sc := &buf.SizeCounter{}
		start := time.Now()
		err := readV(ctx, userspaceReader, writer, timer, nil, sc)
		decision.UserspaceBytes = sc.Size
		decision.UserspaceDurationNs = time.Since(start).Nanoseconds()
		decision.Path = pipeline.PathUserspace
		applyUserspaceExit(&decision, err, isStableUserspaceReason(reason))
		return err
	}

	dnsControlPlaneFlow := session.ShouldBypassVisionDetach(ctx)
	if dnsControlPlaneFlow {
		decision.Path = pipeline.PathUserspace
		switch dnsFlowClass {
		case session.DNSFlowClassTCPControl, session.DNSFlowClassUDPControl:
			decision.Reason = pipeline.ReasonControlPlaneDNSGuard
		default:
			decision.Reason = pipeline.ReasonLoopbackDNSGuard
		}
		decision.DNSPlane = string(session.DNSPlaneVisionGuard)
	}

	loggedUserspaceLoop := false
	loggedFirstByteGrace := false
	userspaceStart := time.Now()
	forceUserspaceAfterSockmap := false
	dnsGuardFirstResponseSeen := false
	var dnsGuardResponseTracker *dnsTCPResponseTracker
	if dnsControlPlaneFlow && dnsFlowClass == session.DNSFlowClassTCPControl {
		dnsGuardResponseTracker = &dnsTCPResponseTracker{}
	}

	// Phase-aware idle policy:
	// - preDetach: while deferred TLS still active; keep tight to surface jam early.
	// - noDetach: deferred TLS continues without detach; enforce tighter timeout.
	// - inferredNoDetach: request uplink completed without explicit command=1;
	//   keep userspace but with a shorter bounded response budget than real
	//   long-lived no-detach sessions.
	// - postDetach: after detach/promotion; give a bit more headroom.
	// - streaming: once payload flows, grow gently up to a cap.
	const (
		userspacePhasePreDetach        = "pre_detach"
		userspacePhaseNoDetach         = "no_detach"
		userspacePhaseInferredNoDetach = "inferred_no_detach"
		userspacePhaseControlCompat    = "control_compat"
		userspacePhasePostDetach       = "post_detach"
		userspacePhaseStreaming        = "streaming"
	)
	var (
		// Keep pre-detach bounded for ambiguous command-0 flows, but let the
		// shared inactivity timer own that budget. Individual reads only poll
		// for explicit Vision progress instead of turning each poll into a hard
		// timeout decision.
		idlePreDetach        = 3 * time.Second
		idleNoDetach         = 10 * time.Second
		idleInferredNoDetach = 3 * time.Second
		idleControlCompat    = 3 * time.Second
		idlePostDetach       = 20 * time.Second
		idleStreamingMax     = 60 * time.Second
		noDetachMinAge       = 5 * time.Second
		noDetachMaxWallDur   = 60 * time.Second
		spliceProbeTimeout   = 3 * time.Second
		spliceProbeMinByte   = int64(32)
	)
	if disableIdle {
		// For debugging correctness: practically disable idle timeouts.
		idlePreDetach = 10 * time.Minute
		idleNoDetach = 10 * time.Minute
		idleInferredNoDetach = 10 * time.Minute
		idleControlCompat = 10 * time.Minute
		idlePostDetach = 10 * time.Minute
		idleStreamingMax = 2 * time.Hour
		noDetachMinAge = 10 * time.Minute
		noDetachMaxWallDur = 2 * time.Hour
	}
	idleTimeout := idlePreDetach
	phase := userspacePhasePreDetach
	deferredPayloadSeen := false
	noDetachSince := time.Time{}
	postDetachPhaseMarked := false
	lastUserspaceTimerTimeout := time.Duration(0)
	setUserspaceTimerTimeout := func(timeout time.Duration) {
		if timer == nil || timeout <= 0 || timeout == lastUserspaceTimerTimeout {
			return
		}
		timer.SetTimeout(timeout)
		lastUserspaceTimerTimeout = timeout
	}
	markPostDetachPhase := func(path string) {
		if postDetachPhaseMarked {
			return
		}
		detachUnix, ok := consumeVisionDetachTimestamp(writerConn)
		if !ok {
			detachUnix, ok = consumeVisionDetachTimestamp(readerConn)
			if !ok {
				return
			}
		}
		nowUnix := time.Now().UnixNano()
		if nowUnix > detachUnix {
			pipelineMarkerVisionPostDetachNanos.Add(uint64(nowUnix - detachUnix))
		}
		pipelineMarkerVisionPostDetachCount.Add(1)
		switch path {
		case "splice":
			pipelineMarkerVisionPostDetachSplice.Add(1)
		case "sockmap":
			pipelineMarkerVisionPostDetachSockmap.Add(1)
		default:
			pipelineMarkerVisionPostDetachUserspace.Add(1)
		}
		postDetachPhaseMarked = true
	}
	for {
		inboundGate := inbound.GetCanSpliceCopy()
		var splice = !disableAccel && !forceUserspaceAfterSockmap &&
			inboundGate != session.CopyGateUnset &&
			inboundGate != session.CopyGateForcedUserspace &&
			inboundGate != session.CopyGateNotApplicable
		firstNonSpliceOutbound := -1
		firstNonSpliceValue := session.CopyGateState(0)
		for i, ob := range outbounds {
			obSplice := ob.GetCanSpliceCopy()
			if obSplice == session.CopyGateUnset || obSplice == session.CopyGateForcedUserspace || obSplice == session.CopyGateNotApplicable {
				splice = false
				if firstNonSpliceOutbound == -1 {
					firstNonSpliceOutbound = i
					firstNonSpliceValue = obSplice
				}
			}
		}
		if dnsControlPlaneFlow {
			// Control-plane DNS stays on guarded userspace path by design.
			splice = false
		}
		noDetachGuardEnabled := visionNoDetachGuardEnabled(inbound, outbounds)
		readerStillUsesDeferredTLS := deferredConnRequiresTLS(readerConn)
		writerStillUsesDeferredTLS := deferredConnRequiresTLS(writerConn)
		deferredTLSActive := readerStillUsesDeferredTLS || writerStillUsesDeferredTLS
		if deferredTLSActive {
			if phase == userspacePhasePreDetach && deferredPayloadSeen && time.Since(userspaceStart) >= noDetachMinAge && noDetachGuardEnabled {
				phase = userspacePhaseNoDetach
				idleTimeout = idleNoDetach
				if noDetachSince.IsZero() {
					noDetachSince = time.Now()
				}
			}
		} else if phase == userspacePhasePreDetach || phase == userspacePhaseNoDetach || phase == userspacePhaseControlCompat {
			phase = userspacePhasePostDetach
			idleTimeout = idlePostDetach
		}
		if phase == userspacePhaseNoDetach {
			decision.Path = pipeline.PathUserspace
			if decision.Reason == pipeline.ReasonDefault || decision.Reason == pipeline.ReasonDeferredTLSGuard {
				decision.Reason = pipeline.ReasonVisionNoDetachUserspace
			}
		} else if phase == userspacePhaseInferredNoDetach {
			decision.Path = pipeline.PathUserspace
			if decision.Reason == pipeline.ReasonDefault || decision.Reason == pipeline.ReasonDeferredTLSGuard {
				decision.Reason = pipeline.ReasonVisionUplinkCompleteUserspace
			}
		} else if phase == userspacePhaseControlCompat {
			decision.Path = pipeline.PathUserspace
			if decision.Reason == pipeline.ReasonDefault || decision.Reason == pipeline.ReasonDeferredTLSGuard {
				decision.Reason = pipeline.ReasonVisionControlUserspace
			}
		}
		if phase == userspacePhaseNoDetach && noDetachGuardEnabled && !noDetachSince.IsZero() && time.Since(noDetachSince) >= noDetachMaxWallDur {
			decision.Path = pipeline.PathUserspace
			decision.Reason = pipeline.ReasonUserspaceNoDetachIdleTimeout
			decision.UserspaceDurationNs = time.Since(userspaceStart).Nanoseconds()
			errors.LogWarning(ctx, "[kind=vision.no_detach_timeout] deferred userspace phase exceeded guard window")
			return io.EOF
		}
		setUserspaceTimerTimeout(idleTimeout)
		if splice {
			if inboundGate == session.CopyGateEligible && !deferredTLSActive {
				_ = ensureRaw()
			}
			input, currentReaderCrypto, currentWriterCrypto, currentReaderCryptoSource, currentWriterCryptoSource := buildVisionDecisionInputForCopyGate(
				readerConn,
				writerConn,
				rawReaderConn,
				rawWriterConn,
				decisionCaps,
				deferredTLSActive,
				inboundGate,
			)
			readerCrypto = currentReaderCrypto
			writerCrypto = currentWriterCrypto
			readerCryptoSource = currentReaderCryptoSource
			writerCryptoSource = currentWriterCryptoSource
			decision = pipeline.DecideVisionPath(input)
			if decision.Path == pipeline.PathSplice && input.LoopbackPair {
				if session.ShouldBypassVisionDetach(ctx) {
					decision.Path = pipeline.PathUserspace
					decision.Reason = pipeline.ReasonLoopbackDNSGuard
					decision.DNSPlane = string(session.DNSPlaneVisionGuard)
				} else {
					// Keep explicit loopback marker for non-control traffic.
					decision.Reason = pipeline.ReasonLoopbackPairGuard
				}
			}
			if decision.Path != pipeline.PathSplice {
				splice = false
				pipelineMarkerDeferredSpliceGuardHit.Add(1)
				maybeLogPipelineRuntimeSummary(ctx)
			}
		}
		var caps pipeline.CapabilitySummary
		if splice {
			caps = pipelineCapabilities()
			decisionCaps = caps
			decision.Path = pipeline.PathSplice
			if decision.Reason == pipeline.ReasonDefault {
				decision.Reason = pipeline.ReasonSplicePrimary
			}
			if !ensureRaw() {
				decision.Path = pipeline.PathUserspace
				decision.Reason = pipeline.ReasonEnsureRawFailed
				sc := &buf.SizeCounter{}
				start := time.Now()
				err := readV(ctx, userspaceReader, writer, timer, nil, sc)
				decision.UserspaceBytes = sc.Size
				decision.UserspaceDurationNs = time.Since(start).Nanoseconds()
				return err
			}
			// Re-evaluate crypto hints right before gating sockmap/splice so
			// deferred detach or kTLS promotion transitions are reflected.
			deferredTLSActive = deferredConnRequiresTLS(readerConn) || deferredConnRequiresTLS(writerConn)
			_, currentReaderCrypto, currentWriterCrypto, currentReaderCryptoSource, currentWriterCryptoSource := buildVisionDecisionInputForCopyGate(
				readerConn,
				writerConn,
				rawReaderConn,
				rawWriterConn,
				decisionCaps,
				deferredTLSActive,
				inbound.GetCanSpliceCopy(),
			)
			readerCrypto = currentReaderCrypto
			writerCrypto = currentWriterCrypto
			readerCryptoSource = currentReaderCryptoSource
			writerCryptoSource = currentWriterCryptoSource

			// Try eBPF sockmap first — kernel-level forwarding without pipe buffers.
			if !caps.SockmapSupported {
				pipelineMarkerSockmapSkipOther.Add(1)
				decision.Path = pipeline.PathSplice
				decision.Reason = pipeline.ReasonSockmapCapabilityUnsupported
			} else if mgr := ebpf.GlobalSockmapManager(); mgr == nil {
				pipelineMarkerSockmapSkipMgr.Add(1)
				errors.LogDebug(ctx, "CopyRawConn sockmap skipped: manager unavailable")
				decision.Path = pipeline.PathSplice
				decision.Reason = pipeline.ReasonSockmapManagerUnavailable
			} else if mgr.ShouldFallbackToSplice() {
				pipelineMarkerSockmapSkipContention.Add(1)
				errors.LogDebug(ctx, "CopyRawConn sockmap skipped: contention fallback active")
				decision.Path = pipeline.PathSplice
				decision.Reason = pipeline.ReasonSockmapContention
			} else if !ebpf.CanUseZeroCopyWithCrypto(rawReaderConn, rawWriterConn, readerCrypto, writerCrypto) {
				errors.LogDebug(ctx, "CopyRawConn crypto hint: reader=", int(readerCrypto), "[", cryptoHintName(readerCrypto), "] source=", readerCryptoSource, " writer=", int(writerCrypto), "[", cryptoHintName(writerCrypto), "] source=", writerCryptoSource)
				switch {
				case !ebpf.KTLSSockhashCompatible() && (readerCrypto == ebpf.CryptoKTLSBoth || writerCrypto == ebpf.CryptoKTLSBoth):
					pipelineMarkerSockmapSkipKTLSSockhash.Add(1)
					errors.LogDebug(ctx, "CopyRawConn sockmap skipped: kTLS+SOCKHASH not supported on this kernel, using splice")
					mgr.IncrementKTLSSpliceFallback()
					decision.Path = pipeline.PathSplice
					decision.Reason = pipeline.ReasonSockmapKTLSSockhashIncompatible
				case readerCrypto == ebpf.CryptoUserspaceTLS || writerCrypto == ebpf.CryptoUserspaceTLS:
					pipelineMarkerSockmapSkipUserspaceTLS.Add(1)
					errors.LogDebug(ctx, "CopyRawConn sockmap skipped: userspace TLS not eligible (readerCrypto=", int(readerCrypto), "[", cryptoHintName(readerCrypto), "] writerCrypto=", int(writerCrypto), "[", cryptoHintName(writerCrypto), "] readerType=", connTypeName(rawReaderConn), " writerType=", connTypeName(rawWriterConn), ")")
					decision.Path = pipeline.PathSplice
					decision.Reason = pipeline.ReasonSockmapUserspaceTLS
				case (readerCrypto == ebpf.CryptoKTLSBoth) != (writerCrypto == ebpf.CryptoKTLSBoth):
					pipelineMarkerSockmapSkipAsymmetric.Add(1)
					errors.LogDebug(ctx, "CopyRawConn sockmap skipped: asymmetric kTLS state (readerCrypto=", int(readerCrypto), "[", cryptoHintName(readerCrypto), "] writerCrypto=", int(writerCrypto), "[", cryptoHintName(writerCrypto), "] readerType=", connTypeName(rawReaderConn), " writerType=", connTypeName(rawWriterConn), ")")
					decision.Path = pipeline.PathSplice
					decision.Reason = pipeline.ReasonSockmapAsymmetricKTLS
				default:
					pipelineMarkerSockmapSkipOther.Add(1)
					errors.LogDebug(ctx, "CopyRawConn sockmap skipped: policy/type mismatch (readerCrypto=", int(readerCrypto), "[", cryptoHintName(readerCrypto), "] writerCrypto=", int(writerCrypto), "[", cryptoHintName(writerCrypto), "] readerType=", connTypeName(rawReaderConn), " writerType=", connTypeName(rawWriterConn), ")")
					decision.Path = pipeline.PathSplice
					decision.Reason = pipeline.ReasonSockmapOtherPolicy
				}
			} else {
				if pair, ok := mgr.GetStats(rawReaderConn, rawWriterConn); ok && (pair.InboundCrypto != readerCrypto || pair.OutboundCrypto != writerCrypto) {
					pipelineMarkerSockmapPolicyRefresh.Add(1)
					if err := mgr.UnregisterPair(rawReaderConn, rawWriterConn); err != nil {
						pipelineMarkerSockmapPolicyRefreshFail.Add(1)
						decision.Path = pipeline.PathSplice
						decision.Reason = pipeline.ReasonSockmapRegisterFail
						errors.LogDebugInner(ctx, err, "CopyRawConn sockmap policy refresh (unregister) failed, falling back to splice")
						maybeLogPipelineRuntimeSummary(ctx)
						continue
					}
				}

				pipelineMarkerSockmapRegisterAttempt.Add(1)
				if err := mgr.RegisterPairWithCrypto(rawReaderConn, rawWriterConn, readerCrypto, writerCrypto); err == nil {
					pipelineMarkerSockmapRegisterSuccess.Add(1)
					markPostDetachPhase("sockmap")
					decision.Path = pipeline.PathSockmap
					decision.Reason = pipeline.ReasonSockmapActive
					lr, rr := connAddrs(rawReaderConn)
					lw, rw := connAddrs(rawWriterConn)
					errors.LogInfo(ctx, "CopyRawConn sockmap start: crypto reader=", int(readerCrypto), " writer=", int(writerCrypto), " reader_addrs=", lr, "->", rr, " writer_addrs=", lw, "->", rw, " loopback=", isLoopbackConnPair(rawReaderConn, rawWriterConn))
					writerMonitor := startKeyUpdateMonitor(rawWriterConn, writerHandler)
					timer.SetTimeout(24 * time.Hour)
					if inTimer != nil {
						inTimer.SetTimeout(24 * time.Hour)
					}
					fallbackToSplice, waitErr := waitForSockmapForwarding(rawReaderConn, rawWriterConn)
					writerMonitor.Stop()
					if err := mgr.UnregisterPair(rawReaderConn, rawWriterConn); err != nil {
						errors.LogDebugInner(ctx, err, "CopyRawConn sockmap unregister failed")
					}
					// Prevent GC from finalizing connections while BPF ops used their FDs.
					runtime.KeepAlive(rawReaderConn)
					runtime.KeepAlive(rawWriterConn)
					if waitErr != nil {
						pipelineMarkerSockmapWaitError.Add(1)
						errors.LogWarningInner(ctx, waitErr, "CopyRawConn sockmap wait failed, switching to guarded userspace fallback; reader_addrs=", lr, "->", rr, " writer_addrs=", lw, "->", rw)
						decision.Path = pipeline.PathUserspace
						decision.Reason = pipeline.ReasonSockmapWaitErrorUserspaceGuard
						forceUserspaceAfterSockmap = true
						continue
					} else if !fallbackToSplice {
						pipelineMarkerSockmapWaitSuccess.Add(1)
						decision.Path = pipeline.PathSockmap
						decision.Reason = pipeline.ReasonForwardSuccess
						errors.LogInfo(ctx, "CopyRawConn sockmap forward success: reader_addrs=", lr, "->", rr, " writer_addrs=", lw, "->", rw)
						decision.SockmapSuccess = true
						return nil
					} else {
						pipelineMarkerSockmapWaitFallback.Add(1)
						errors.LogWarning(ctx, "CopyRawConn sockmap inactive, switching to guarded userspace fallback; reader_addrs=", lr, "->", rr, " writer_addrs=", lw, "->", rw)
						decision.Path = pipeline.PathUserspace
						decision.Reason = pipeline.ReasonSockmapWaitFallbackUserspaceGuard
						forceUserspaceAfterSockmap = true
						continue
					}
				} else {
					pipelineMarkerSockmapRegisterFail.Add(1)
					errors.LogDebugInner(ctx, err, "CopyRawConn sockmap register failed, falling back to splice")
					decision.Path = pipeline.PathSplice
					decision.Reason = pipeline.ReasonSockmapRegisterFail
				}
			}
			// Fall through to splice on sockmap failure

			decision.Path = pipeline.PathSplice
			if decision.Reason == pipeline.ReasonDefault || decision.Reason == pipeline.ReasonSockmapActive {
				decision.Reason = pipeline.ReasonSplicePrimary
			}
			postSockmapSpliceProbe := decision.Reason == pipeline.ReasonSockmapRegisterFail
			errors.LogDebug(ctx, "CopyRawConn splice")
			statWriter, _ := writer.(*dispatcher.SizeStatWriter)
			//runtime.Gosched() // necessary
			time.Sleep(time.Millisecond)     // without this, there will be a rare ssl error for freedom splice
			timer.SetTimeout(24 * time.Hour) // prevent leak, just in case
			if inTimer != nil {
				inTimer.SetTimeout(24 * time.Hour)
			}
			writerMonitor := startKeyUpdateMonitor(rawWriterConn, writerHandler)
			pipelineMarkerSpliceAttempts.Add(1)
			maybeLogPipelineRuntimeSummary(ctx)
			spliceStart := time.Now()
			markPostDetachPhase("splice")
			if postSockmapSpliceProbe {
				_ = rawReaderConn.SetReadDeadline(time.Now().Add(spliceProbeTimeout))
			}
			w, err := rawWriterTCP.ReadFrom(rawReaderConn)
			if postSockmapSpliceProbe {
				_ = rawReaderConn.SetReadDeadline(time.Time{})
			}
			decision.SpliceBytes = w
			writerMonitor.Stop()
			spliceDuration := time.Since(spliceStart)
			decision.SpliceDurationNs = spliceDuration.Nanoseconds()
			pipelineMarkerSpliceBytesTotal.Add(uint64(w))
			pipelineMarkerSpliceDurationNanosTotal.Add(uint64(spliceDuration.Nanoseconds()))
			recordSpliceHistogram(uint64(w), uint64(spliceDuration.Nanoseconds()))
			if readCounter != nil {
				readCounter.Add(w) // outbound stats
			}
			if writeCounter != nil {
				writeCounter.Add(w) // inbound stats
			}
			if statWriter != nil {
				statWriter.Counter.Add(w) // user stats
			}
			if postSockmapSpliceProbe && isNetTimeout(err) && w <= spliceProbeMinByte {
				pipelineMarkerSpliceCompleted.Add(1)
				decision.Reason = pipeline.ReasonSplicePostSockmapStall
				maybeLogPipelineRuntimeSummary(ctx)
				errors.LogWarning(ctx, "[kind=vision.splice_post_sockmap_stall] splice made no progress after sockmap fallback: bytes=", w, " timeout=", spliceProbeTimeout)
				return io.EOF
			}
			if err != nil && readerHandler != nil && tls.IsKeyExpired(err) {
				if herr := readerHandler.Handle(); herr != nil {
					return herr
				}
				continue // retry splice after key update
			}
			if err == nil || errors.Cause(err) == io.EOF {
				pipelineMarkerSpliceCompleted.Add(1)
				maybeLogPipelineRuntimeSummary(ctx)
				return nil
			}
			if isExpectedSpliceReadFromError(err) {
				pipelineMarkerSpliceExpectedTeardown.Add(1)
				recordSpliceExpectedTeardownClass(err)
				pipelineMarkerSpliceCompleted.Add(1)
				maybeLogPipelineRuntimeSummary(ctx)
				errors.LogWarning(ctx, "[kind=vision.splice_expected_teardown] splice/readfrom closed by peer or stream teardown: ", err)
				return nil
			}
			// Unexpected splice error: record and also flag as acceleration fault for learning.
			recordSpliceUnexpectedReset(err)
			pipelineMarkerSpliceUnexpectedError.Add(1)
			maybeLogPipelineRuntimeSummary(ctx)
			errors.LogWarning(ctx, "[kind=vision.splice_unexpected_error] splice/readfrom failed: ", err)
			return err
		}
		if !loggedUserspaceLoop {
			inboundSplice := inbound.GetCanSpliceCopy()
			if inboundSplice != session.CopyGateEligible {
				errors.LogDebug(ctx, "CopyRawConn userspace copy loop: inbound.CopyGate=", inboundSplice.String())
			} else if readerStillUsesDeferredTLS || writerStillUsesDeferredTLS {
				errors.LogDebug(ctx,
					"CopyRawConn userspace copy loop: deferred rustls still active",
					" reader=", readerStillUsesDeferredTLS,
					" writer=", writerStillUsesDeferredTLS,
				)
			} else {
				errors.LogDebug(ctx, "CopyRawConn userspace copy loop: outbounds[", firstNonSpliceOutbound, "].CopyGate=", firstNonSpliceValue.String())
			}
			loggedUserspaceLoop = true
		}
		currentReader := userspaceReader
		usingRawUserspaceReader := false
		// After Vision command=2, inbound switches to raw direct-copy mode.
		// If splice is disabled by peer metadata, userspace fallback must read
		// from the same unwrapped/raw layer to avoid waiting for TLS framing.
		if inbound.GetCanSpliceCopy() == session.CopyGateEligible && !readerStillUsesDeferredTLS && ensureRaw() && rawUserspaceReader != nil {
			currentReader = rawUserspaceReader
			usingRawUserspaceReader = true
		}
		deferredPhaseActive := phase == userspacePhasePreDetach || phase == userspacePhaseNoDetach
		preDetachHeuristicActive := phase == userspacePhasePreDetach
		preDetachCompatibilityWait := preDetachHeuristicActive && !dnsControlPlaneFlow && decision.UserspaceBytes == 0
		if shouldRetryVisionPostDetachTransition(readerConn, writerConn, decision.UserspaceBytes, dnsControlPlaneFlow, deferredTLSActive, deferredPhaseActive) {
			phase = userspacePhasePostDetach
			idleTimeout = idlePostDetach
			setUserspaceTimerTimeout(idleTimeout)
			decision.Reason = pipeline.ReasonDefault
			errors.LogDebug(ctx, "[kind=vision.post_detach_recheck] deferred TLS cleared before fallback read; retrying post-detach path")
			continue
		}
		if gate, gateReason, ok := visionStableUserspaceGateActive(inbound, outbounds); ok {
			if gateReason == pipeline.CopyGateReasonVisionUplinkComplete && phase != userspacePhasePreDetach {
				goto userspaceReadLoop
			}
			phase = userspacePhaseNoDetach
			idleTimeout = idleNoDetach
			if gateReason == pipeline.CopyGateReasonVisionUplinkComplete {
				phase = userspacePhaseInferredNoDetach
				idleTimeout = idleInferredNoDetach
			}
			setUserspaceTimerTimeout(idleTimeout)
			decision.Path = pipeline.PathUserspace
			decision.Reason = visionUserspaceReasonForGate(gateReason)
			decision.CopyGateState = gate
			decision.CopyGateReason = gateReason
			prepareVisionStableUserspaceRead(readerConn, writerConn)
			if gateReason == pipeline.CopyGateReasonVisionUplinkComplete {
				errors.LogDebug(ctx, "[kind=vision.stable_userspace_handoff] inferred no-detach flow will stay on local response loop until first response byte")
				continue
			}
			sc := &buf.SizeCounter{}
			err := readV(ctx, currentReader, writer, timer, nil, sc)
			decision.UserspaceBytes += sc.Size
			decision.UserspaceDurationNs = time.Since(userspaceStart).Nanoseconds()
			applyUserspaceExit(&decision, err, isStableUserspaceReason(decision.Reason))
			return err
		}

	userspaceReadLoop:
		readTimeout := idleTimeout
		if preDetachCompatibilityWait {
			readTimeout = visionPreDetachPollTick
		}

		_ = readerConn.SetReadDeadline(time.Now().Add(readTimeout))
		buffer, err := currentReader.ReadMultiBuffer()
		_ = readerConn.SetReadDeadline(time.Time{})
		if !buffer.IsEmpty() {
			dnsGuardResponseComplete := dnsGuardResponseTracker != nil && dnsGuardResponseTracker.Observe(buffer)
			pipelineMarkerUserspaceCopyReads.Add(1)
			pipelineMarkerUserspaceCopyBytesTotal.Add(uint64(buffer.Len()))
			decision.UserspaceBytes += int64(buffer.Len())
			if phase == userspacePhaseInferredNoDetach {
				phase = userspacePhaseNoDetach
				idleTimeout = idleNoDetach
				if noDetachSince.IsZero() {
					noDetachSince = time.Now()
				}
				setUserspaceTimerTimeout(idleTimeout)
			} else if phase == userspacePhaseControlCompat {
				phase = userspacePhaseNoDetach
				idleTimeout = idleNoDetach
				if noDetachSince.IsZero() {
					noDetachSince = time.Now()
				}
				setUserspaceTimerTimeout(idleTimeout)
			}
			if dnsControlPlaneFlow && !dnsGuardFirstResponseSeen {
				firstResponseNs := uint64(time.Since(userspaceStart).Nanoseconds())
				pipelineMarkerDNSGuardFirstResponseNanos.Add(firstResponseNs)
				pipelineMarkerDNSGuardFirstResponseCount.Add(1)
				recordDNSGuardFirstResponseHistogram(firstResponseNs)
				decision.DNSGuardFirstResponseNs = int64(firstResponseNs)
				dnsGuardFirstResponseSeen = true
			}
			if deferredTLSActive {
				deferredPayloadSeen = true
				if phase == userspacePhasePreDetach && time.Since(userspaceStart) >= noDetachMinAge {
					phase = userspacePhaseNoDetach
					idleTimeout = idleNoDetach
					if noDetachSince.IsZero() {
						noDetachSince = time.Now()
					}
				}
				if phase == userspacePhaseNoDetach && idleTimeout > idleNoDetach {
					idleTimeout = idleNoDetach
				}
			} else {
				if phase != userspacePhaseStreaming {
					phase = userspacePhaseStreaming
					if idleTimeout < idlePostDetach {
						idleTimeout = idlePostDetach
					}
				}
				if idleTimeout < idleStreamingMax {
					idleTimeout += 5 * time.Second
					if idleTimeout > idleStreamingMax {
						idleTimeout = idleStreamingMax
					}
				}
			}
			if usingRawUserspaceReader {
				pipelineMarkerUserspaceRawReaderHits.Add(1)
			} else {
				pipelineMarkerUserspaceTLSReaderHits.Add(1)
			}
			timer.Update()
			if werr := writer.WriteMultiBuffer(buffer); werr != nil {
				return werr
			}
			if dnsGuardResponseComplete {
				decision.Path = pipeline.PathUserspace
				switch dnsFlowClass {
				case session.DNSFlowClassTCPControl, session.DNSFlowClassUDPControl:
					decision.Reason = pipeline.ReasonControlPlaneDNSGuard
				default:
					decision.Reason = pipeline.ReasonLoopbackDNSGuard
				}
				decision.UserspaceDurationNs = time.Since(userspaceStart).Nanoseconds()
				decision.UserspaceExit = pipeline.UserspaceExitComplete
				errors.LogDebug(ctx, "[kind=dns.guard_response_complete] forwarded one full DNS-over-TCP response frame; retiring guarded control-plane flow promptly")
				return nil
			}
		}
		if err != nil {
			decision.UserspaceDurationNs = time.Since(userspaceStart).Nanoseconds()
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if shouldRetryVisionPostDetachTransition(readerConn, writerConn, decision.UserspaceBytes, dnsControlPlaneFlow, deferredTLSActive, deferredPhaseActive) {
					phase = userspacePhasePostDetach
					idleTimeout = idlePostDetach
					setUserspaceTimerTimeout(idleTimeout)
					decision.Reason = pipeline.ReasonDefault
					postDetachRetrySeen = true
					errors.LogDebug(ctx, "[kind=vision.post_detach_retry] deferred TLS cleared during response wait; retrying with post-detach budget")
					continue
				}
				if phase == userspacePhasePreDetach && applyVisionStableUserspaceGateDecision(&decision, inbound, outbounds) {
					if decision.CopyGateReason == pipeline.CopyGateReasonVisionUplinkComplete {
						phase = userspacePhaseInferredNoDetach
						idleTimeout = idleInferredNoDetach
					} else {
						phase = userspacePhaseNoDetach
						idleTimeout = idleNoDetach
					}
					setUserspaceTimerTimeout(idleTimeout)
					errors.LogDebug(ctx, "[kind=vision.stable_userspace_handoff] Vision flow confirmed for stable userspace path during response wait")
					continue
				}
				if preDetachCompatibilityWait && time.Since(userspaceStart) < idleTimeout {
					continue
				}
				now := time.Now()
				if remaining, ok := shouldDeferVisionFirstByteTimeout(writerConn, decision.UserspaceBytes, dnsControlPlaneFlow, deferredTLSActive, preDetachHeuristicActive, userspaceStart, now); ok {
					if !loggedFirstByteGrace {
						loggedFirstByteGrace = true
						errors.LogDebug(ctx, "[kind=vision.userspace_first_byte_grace] deferring zero-byte response timeout while uplink remains active")
					}
					idleTimeout = remaining
					setUserspaceTimerTimeout(idleTimeout)
					continue
				}
				if shouldPromoteVisionNoDetachResponsePhase(writerConn, decision.UserspaceBytes, dnsControlPlaneFlow, deferredTLSActive, preDetachHeuristicActive, now) {
					errors.LogDebug(ctx, "[kind=vision.uplink_quiesce_handoff] uplink has gone quiet without direct-copy signal; telemetry only for main-client compatibility")
				}
				if phase == userspacePhasePreDetach &&
					decision.UserspaceBytes == 0 &&
					!dnsControlPlaneFlow &&
					!debugVisionExplicitOnly() &&
					visionControlUserspaceCompatible(outbounds) {
					phase = userspacePhaseControlCompat
					idleTimeout = idleControlCompat
					setUserspaceTimerTimeout(idleTimeout)
					decision.Path = pipeline.PathUserspace
					decision.Reason = pipeline.ReasonVisionControlUserspace
					errors.LogDebug(ctx, "[kind=vision.control_userspace_handoff] control-compatible flow stayed command=0; granting bounded local response window before final timeout")
					continue
				}
				if dnsControlPlaneFlow && decision.UserspaceBytes == 0 {
					pipelineMarkerDNSGuardZeroByteTimeout.Add(1)
					decision.DNSGuardZeroByteTimeout = true
				}
				if !dnsControlPlaneFlow {
					if phase == userspacePhaseNoDetach {
						decision.Reason = pipeline.ReasonUserspaceNoDetachIdleTimeout
					} else if phase == userspacePhaseControlCompat {
						decision.Reason = pipeline.ReasonVisionControlUserspace
					} else if phase == userspacePhaseInferredNoDetach {
						decision.Reason = pipeline.ReasonVisionUplinkCompleteUserspace
					} else {
						decision.Reason = pipeline.ReasonUserspaceIdleTimeout
					}
				} else {
					switch dnsFlowClass {
					case session.DNSFlowClassTCPControl, session.DNSFlowClassUDPControl:
						decision.Reason = pipeline.ReasonControlPlaneDNSGuard
					default:
						decision.Reason = pipeline.ReasonLoopbackDNSGuard
					}
				}
				decision.Path = pipeline.PathUserspace
				applyUserspaceExit(&decision, err, phase == userspacePhaseNoDetach || phase == userspacePhaseInferredNoDetach || isStableUserspaceReason(decision.Reason))
				// Treat idle timeout as clean close to avoid marking failures upstream.
				return io.EOF
			}
			if errors.Cause(err) == io.EOF {
				if shouldRetryVisionPostDetachTransition(readerConn, writerConn, decision.UserspaceBytes, dnsControlPlaneFlow, deferredTLSActive, deferredPhaseActive) {
					phase = userspacePhasePostDetach
					idleTimeout = idlePostDetach
					setUserspaceTimerTimeout(idleTimeout)
					decision.Reason = pipeline.ReasonDefault
					postDetachRetrySeen = true
					errors.LogDebug(ctx, "[kind=vision.post_detach_eof_retry] deferred TLS cleared on EOF; retrying with post-detach budget")
					continue
				}
				if phase == userspacePhasePreDetach && applyVisionStableUserspaceGateDecision(&decision, inbound, outbounds) {
					if decision.CopyGateReason == pipeline.CopyGateReasonVisionUplinkComplete {
						phase = userspacePhaseInferredNoDetach
						idleTimeout = idleInferredNoDetach
					} else {
						phase = userspacePhaseNoDetach
						idleTimeout = idleNoDetach
					}
					setUserspaceTimerTimeout(idleTimeout)
				}
				if (phase == userspacePhaseNoDetach || phase == userspacePhaseInferredNoDetach || phase == userspacePhaseControlCompat) &&
					(decision.Reason == pipeline.ReasonDefault || decision.Reason == pipeline.ReasonDeferredTLSGuard) {
					decision.Reason = pipeline.ReasonVisionNoDetachUserspace
					if phase == userspacePhaseInferredNoDetach {
						decision.Reason = pipeline.ReasonVisionUplinkCompleteUserspace
					} else if phase == userspacePhaseControlCompat {
						decision.Reason = pipeline.ReasonVisionControlUserspace
					}
					decision.Path = pipeline.PathUserspace
				}
				if decision.Reason == pipeline.ReasonDefault {
					decision.Reason = pipeline.ReasonUserspaceComplete
					decision.Path = pipeline.PathUserspace
				}
				applyUserspaceExit(&decision, err, phase == userspacePhaseNoDetach || phase == userspacePhaseInferredNoDetach || phase == userspacePhaseControlCompat || isStableUserspaceReason(decision.Reason))
				return nil
			}
			if phase == userspacePhasePreDetach && applyVisionStableUserspaceGateDecision(&decision, inbound, outbounds) {
				if decision.CopyGateReason == pipeline.CopyGateReasonVisionUplinkComplete {
					phase = userspacePhaseInferredNoDetach
					idleTimeout = idleInferredNoDetach
				} else {
					phase = userspacePhaseNoDetach
					idleTimeout = idleNoDetach
				}
				setUserspaceTimerTimeout(idleTimeout)
			}
			if (phase == userspacePhaseNoDetach || phase == userspacePhaseInferredNoDetach || phase == userspacePhaseControlCompat) &&
				(decision.Reason == pipeline.ReasonDefault || decision.Reason == pipeline.ReasonDeferredTLSGuard) {
				decision.Reason = pipeline.ReasonVisionNoDetachUserspace
				if phase == userspacePhaseInferredNoDetach {
					decision.Reason = pipeline.ReasonVisionUplinkCompleteUserspace
				} else if phase == userspacePhaseControlCompat {
					decision.Reason = pipeline.ReasonVisionControlUserspace
				}
				decision.Path = pipeline.PathUserspace
			}
			applyUserspaceExit(&decision, err, phase == userspacePhaseNoDetach || phase == userspacePhaseInferredNoDetach || phase == userspacePhaseControlCompat || isStableUserspaceReason(decision.Reason))
			return err
		}
		decision.UserspaceDurationNs = time.Since(userspaceStart).Nanoseconds()
	}
}

func connTypeName(conn net.Conn) string {
	if conn == nil {
		return "<nil>"
	}
	return reflect.TypeOf(conn).String()
}

func connAddrs(conn net.Conn) (l, r string) {
	if conn == nil {
		return "<nil>", "<nil>"
	}
	if la := conn.LocalAddr(); la != nil {
		l = la.String()
	}
	if ra := conn.RemoteAddr(); ra != nil {
		r = ra.String()
	}
	return
}

// isDNSPortOutbound returns true when current flow should keep Vision userspace
// path for deterministic control-plane behavior.
func isDNSPortOutbound(ctx context.Context) bool {
	return session.ShouldBypassVisionDetach(ctx)
}

type dnsTCPResponseTracker struct {
	header        [2]byte
	headerSeen    int
	totalSeen     int
	expectedTotal int
}

func (t *dnsTCPResponseTracker) Observe(buffer buf.MultiBuffer) bool {
	if t == nil || t.expectedTotal > 0 && t.totalSeen >= t.expectedTotal {
		return t != nil && t.expectedTotal > 0 && t.totalSeen >= t.expectedTotal
	}
	for _, b := range buffer {
		if b == nil || b.Len() == 0 {
			continue
		}
		payload := b.Bytes()
		t.totalSeen += len(payload)
		if t.headerSeen < len(t.header) {
			t.headerSeen += copy(t.header[t.headerSeen:], payload)
			if t.headerSeen == len(t.header) && t.expectedTotal == 0 {
				t.expectedTotal = len(t.header) + int(binary.BigEndian.Uint16(t.header[:]))
			}
		}
		if t.expectedTotal > 0 && t.totalSeen >= t.expectedTotal {
			return true
		}
	}
	return false
}

func isNetTimeout(err error) bool {
	if err == nil {
		return false
	}
	var ne interface{ Timeout() bool }
	return goerrors.As(err, &ne) && ne.Timeout()
}

func appendCryptoHintSource(source, step string) string {
	if source == "" {
		return step
	}
	if step == "" {
		return source
	}
	return source + " -> " + step
}

func RecordPipelineFlowMix(ctx context.Context, destNet net.Network, allowedNet net.Network) {
	switch {
	case destNet == net.Network_TCP && allowedNet == net.Network_UDP:
		pipelineMarkerFlowMuxUDP.Add(1)
	case destNet == net.Network_TCP && allowedNet == net.Network_Unknown:
		pipelineMarkerFlowPureTCP.Add(1)
	case destNet == net.Network_TCP && allowedNet == net.Network_TCP:
		pipelineMarkerFlowMuxTCP.Add(1)
	default:
		pipelineMarkerFlowOther.Add(1)
	}
}

func maybeLogPipelineRuntimeSummary(ctx context.Context) {
	if pipelineTelemetryV2Enabled() {
		return
	}
	// Legacy runtime summary logging has been replaced by v2 telemetry markers.
}

func logStartupHealth() {
	ctx := context.Background()
	bpffsMounted := false
	if fi, err := os.Stat("/sys/fs/bpf"); err == nil && fi.IsDir() {
		bpffsMounted = true
	}
	pinDir := ebpf.DefaultSockmapConfig().PinPath
	pinsReady := false
	if pinDir != "" {
		if fi, err := os.Stat(pinDir); err == nil && fi.IsDir() {
			_, errHash := os.Stat(filepath.Join(pinDir, "sockhash"))
			_, errPolicy := os.Stat(filepath.Join(pinDir, "policy"))
			pinsReady = errHash == nil && errPolicy == nil
		}
	}
	sockmapEnabled := false
	if mgr := ebpf.GlobalSockmapManager(); mgr != nil && mgr.IsEnabled() {
		sockmapEnabled = true
	}
	ktlsSockhash := ebpf.KTLSSockhashCompatible()

	errors.LogInfo(ctx,
		"startup health: bpffs_mounted=", bpffsMounted,
		" pin_dir=", pinDir,
		" pins_ready=", pinsReady,
		" sockmap_enabled=", sockmapEnabled,
		" ktls_sockhash_compatible=", ktlsSockhash,
		" vision_detach_mode=async budget=", visionDetachWaitBudget(),
	)
}

func markerSnapshot(total *atomic.Uint64, last *atomic.Uint64) (current uint64, delta uint64) {
	current = total.Load()
	prev := last.Swap(current)
	if current >= prev {
		delta = current - prev
	}
	return current, delta
}

func fmtMarkerWithDelta(current, delta uint64) string {
	if delta == 0 {
		return strconv.FormatUint(current, 10)
	}
	return strconv.FormatUint(current, 10) + "(+" + strconv.FormatUint(delta, 10) + ")"
}

func fmtAverageNanos(total uint64, count uint64) string {
	if count == 0 {
		return "0"
	}
	return strconv.FormatUint(total/count, 10)
}

func recordSpliceHistogram(bytes uint64, durationNs uint64) {
	switch {
	case bytes < 4*1024:
		pipelineMarkerSpliceBytesLt4K.Add(1)
	case bytes < 64*1024:
		pipelineMarkerSpliceBytes4KTo64K.Add(1)
	case bytes < 1024*1024:
		pipelineMarkerSpliceBytes64KTo1M.Add(1)
	default:
		pipelineMarkerSpliceBytesGe1M.Add(1)
	}
	switch {
	case durationNs < uint64(time.Millisecond):
		pipelineMarkerSpliceDurLt1ms.Add(1)
	case durationNs < uint64(5*time.Millisecond):
		pipelineMarkerSpliceDur1To5ms.Add(1)
	case durationNs < uint64(20*time.Millisecond):
		pipelineMarkerSpliceDur5To20ms.Add(1)
	case durationNs < uint64(100*time.Millisecond):
		pipelineMarkerSpliceDur20To100ms.Add(1)
	default:
		pipelineMarkerSpliceDurGe100ms.Add(1)
	}
}

func recordRawUnwrapToDetachHistogram(durationNs uint64) {
	switch {
	case durationNs < uint64(5*time.Millisecond):
		pipelineMarkerRawUnwrapToDetachLt5ms.Add(1)
	case durationNs < uint64(20*time.Millisecond):
		pipelineMarkerRawUnwrapToDetach5To20ms.Add(1)
	case durationNs < uint64(100*time.Millisecond):
		pipelineMarkerRawUnwrapToDetach20To100ms.Add(1)
	default:
		pipelineMarkerRawUnwrapToDetachGe100ms.Add(1)
	}
}

func recordDNSGuardFirstResponseHistogram(durationNs uint64) {
	switch {
	case durationNs < uint64(20*time.Millisecond):
		pipelineMarkerDNSGuardFirstRespLt20ms.Add(1)
	case durationNs < uint64(100*time.Millisecond):
		pipelineMarkerDNSGuardFirstResp20To100ms.Add(1)
	case durationNs < uint64(time.Second):
		pipelineMarkerDNSGuardFirstResp100msTo1s.Add(1)
	default:
		pipelineMarkerDNSGuardFirstRespGe1s.Add(1)
	}
}

// visionNoDetachGuardEnabled determines whether the no-detach watchdog should
// run for the current splice decision, based on inbound/outbound splice hints.
func visionNoDetachGuardEnabled(inbound *session.Inbound, outbounds []*session.Outbound) bool {
	if inbound == nil {
		return false
	}
	if inbound.GetCanSpliceCopy() == session.CopyGateForcedUserspace || inbound.GetCanSpliceCopy() == session.CopyGateNotApplicable {
		return false
	}
	for _, ob := range outbounds {
		if ob != nil && (ob.GetCanSpliceCopy() == session.CopyGateForcedUserspace || ob.GetCanSpliceCopy() == session.CopyGateNotApplicable) {
			return false
		}
	}
	return true
}

func clearVisionTelemetryTimestamps(conns ...gonet.Conn) {
	for _, conn := range conns {
		dc := unwrapVisionDeferredConn(conn)
		if dc == nil {
			continue
		}
		pipelineVisionRawUnwrapUnixByConn.Delete(dc)
		pipelineVisionDetachUnixByConn.Delete(dc)
		pipelineVisionUplinkUnixByConn.Delete(dc)
		pipelineVisionDetachFutureByConn.Delete(dc)
		pipelineVisionResponseWakeByConn.Delete(dc)
	}
}

func storeVisionRawUnwrapWarningTimestamp(conn gonet.Conn, unixNano int64) {
	if unixNano <= 0 {
		return
	}
	dc := unwrapVisionDeferredConn(conn)
	if dc == nil {
		return
	}
	if _, loaded := pipelineVisionRawUnwrapUnixByConn.LoadOrStore(dc, unixNano); loaded {
		return
	}
}

func consumeVisionRawUnwrapWarningTimestamp(conn gonet.Conn) (int64, bool) {
	dc := unwrapVisionDeferredConn(conn)
	if dc == nil {
		return 0, false
	}
	value, ok := pipelineVisionRawUnwrapUnixByConn.LoadAndDelete(dc)
	if !ok {
		return 0, false
	}
	unixNano, ok := value.(int64)
	if !ok || unixNano <= 0 {
		return 0, false
	}
	return unixNano, true
}

func storeVisionUplinkTimestamp(conn gonet.Conn, unixNano int64) {
	if unixNano <= 0 {
		return
	}
	dc := unwrapVisionDeferredConn(conn)
	if dc == nil {
		return
	}
	pipelineVisionUplinkUnixByConn.Store(dc, unixNano)
}

func loadVisionUplinkTimestamp(conn gonet.Conn) (int64, bool) {
	dc := unwrapVisionDeferredConn(conn)
	if dc == nil {
		return 0, false
	}
	value, ok := pipelineVisionUplinkUnixByConn.Load(dc)
	if !ok {
		return 0, false
	}
	unixNano, ok := value.(int64)
	if !ok || unixNano <= 0 {
		return 0, false
	}
	return unixNano, true
}

func remainingVisionUplinkGraceAt(conn gonet.Conn, grace time.Duration, now time.Time) time.Duration {
	if grace <= 0 || now.IsZero() {
		return 0
	}
	unixNano, ok := loadVisionUplinkTimestamp(conn)
	if !ok {
		return 0
	}
	age := now.Sub(time.Unix(0, unixNano))
	if age < 0 {
		age = 0
	}
	if age >= grace {
		return 0
	}
	return grace - age
}

func shouldDeferVisionFirstByteTimeout(conn gonet.Conn, userspaceBytes int64, dnsControlPlaneFlow bool, deferredTLSActive bool, deferredPhaseActive bool, userspaceStart time.Time, now time.Time) (time.Duration, bool) {
	if conn == nil || userspaceBytes != 0 || dnsControlPlaneFlow || !deferredTLSActive || !deferredPhaseActive || userspaceStart.IsZero() || now.IsZero() {
		return 0, false
	}
	elapsed := now.Sub(userspaceStart)
	if elapsed < 0 || elapsed >= visionFirstResponseMax {
		return 0, false
	}
	remaining := remainingVisionUplinkGraceAt(conn, visionFirstResponseGrace, now)
	if remaining <= 0 {
		return 0, false
	}
	if maxRemaining := visionFirstResponseMax - elapsed; remaining > maxRemaining {
		remaining = maxRemaining
	}
	if remaining <= 0 {
		return 0, false
	}
	if remaining < 100*time.Millisecond {
		remaining = 100 * time.Millisecond
	}
	return remaining, true
}

func shouldPromoteVisionNoDetachResponsePhase(conn gonet.Conn, userspaceBytes int64, dnsControlPlaneFlow bool, deferredTLSActive bool, deferredPhaseActive bool, now time.Time) bool {
	if conn == nil || userspaceBytes != 0 || dnsControlPlaneFlow || !deferredTLSActive || !deferredPhaseActive || now.IsZero() {
		return false
	}
	unixNano, ok := loadVisionUplinkTimestamp(conn)
	if !ok {
		return false
	}
	age := now.Sub(time.Unix(0, unixNano))
	if age < 0 {
		age = 0
	}
	return age >= visionUplinkQuietWindow
}

var visionDeferredTLSRequiredFn = deferredConnRequiresTLS

func shouldRetryVisionPostDetachTransition(readerConn, writerConn gonet.Conn, userspaceBytes int64, dnsControlPlaneFlow bool, deferredTLSActive bool, deferredPhaseActive bool) bool {
	if userspaceBytes != 0 || dnsControlPlaneFlow || !deferredTLSActive || !deferredPhaseActive {
		return false
	}
	return !visionDeferredTLSRequiredFn(readerConn) && !visionDeferredTLSRequiredFn(writerConn)
}

func visionUserspaceReasonForGate(gateReason pipeline.CopyGateReason) string {
	switch gateReason {
	case pipeline.CopyGateReasonVisionUplinkComplete:
		return pipeline.ReasonVisionUplinkCompleteUserspace
	case pipeline.CopyGateReasonVisionNoDetach:
		return pipeline.ReasonVisionNoDetachUserspace
	default:
		return pipeline.ReasonVisionNoDetachUserspace
	}
}

func isStableUserspaceReason(reason string) bool {
	switch reason {
	case pipeline.ReasonVisionNoDetachUserspace,
		pipeline.ReasonVisionControlUserspace,
		pipeline.ReasonVisionUplinkCompleteUserspace,
		pipeline.ReasonVisionCommandContinueUserspace:
		return true
	default:
		return false
	}
}

func visionControlUserspaceCompatible(outbounds []*session.Outbound) bool {
	for i := len(outbounds) - 1; i >= 0; i-- {
		ob := outbounds[i]
		if ob == nil {
			continue
		}
		dest := ob.Target
		if !dest.IsValid() {
			dest = ob.RouteTarget
		}
		if !dest.IsValid() {
			dest = ob.OriginalTarget
		}
		if !dest.IsValid() {
			continue
		}
		return dest.Network == net.Network_TCP && dest.Port == net.Port(5222)
	}
	return false
}

func visionStableUserspaceGateActive(inbound *session.Inbound, outbounds []*session.Outbound) (pipeline.CopyGateState, pipeline.CopyGateReason, bool) {
	if inbound != nil && inbound.GetCanSpliceCopy() == session.CopyGateForcedUserspace {
		if inbound.CopyGateReason() == session.CopyGateReasonVisionNoDetach {
			return pipeline.CopyGateForcedUserspace, pipeline.CopyGateReasonVisionNoDetach, true
		}
	}
	for _, ob := range outbounds {
		if ob == nil || ob.GetCanSpliceCopy() != session.CopyGateForcedUserspace {
			continue
		}
		if ob.CopyGateReason() == session.CopyGateReasonVisionNoDetach {
			return pipeline.CopyGateForcedUserspace, pipeline.CopyGateReasonVisionNoDetach, true
		}
	}
	if inbound != nil && inbound.GetCanSpliceCopy() == session.CopyGateForcedUserspace {
		if inbound.CopyGateReason() == session.CopyGateReasonVisionUplinkComplete {
			return pipeline.CopyGateForcedUserspace, pipeline.CopyGateReasonVisionUplinkComplete, true
		}
	}
	for _, ob := range outbounds {
		if ob == nil || ob.GetCanSpliceCopy() != session.CopyGateForcedUserspace {
			continue
		}
		if ob.CopyGateReason() == session.CopyGateReasonVisionUplinkComplete {
			return pipeline.CopyGateForcedUserspace, pipeline.CopyGateReasonVisionUplinkComplete, true
		}
	}
	return pipeline.CopyGateUnset, pipeline.CopyGateReasonUnspecified, false
}

func applyVisionStableUserspaceGateDecision(decision *pipeline.DecisionSnapshot, inbound *session.Inbound, outbounds []*session.Outbound) bool {
	gate, gateReason, ok := visionStableUserspaceGateActive(inbound, outbounds)
	if !ok {
		return false
	}
	decision.Path = pipeline.PathUserspace
	decision.Reason = visionUserspaceReasonForGate(gateReason)
	decision.CopyGateState = gate
	decision.CopyGateReason = gateReason
	return true
}

func isLocalUserspaceClose(err error) bool {
	cause := errors.Cause(err)
	if cause == nil {
		cause = err
	}
	return goerrors.Is(cause, gonet.ErrClosed) ||
		goerrors.Is(cause, context.Canceled) ||
		goerrors.Is(cause, syscall.ENOTCONN) ||
		goerrors.Is(cause, syscall.ESHUTDOWN)
}

func classifyUserspaceExit(err error, userspaceBytes int64, stableUserspace bool) pipeline.UserspaceExit {
	if err == nil {
		return pipeline.UserspaceExitNone
	}
	cause := errors.Cause(err)
	if cause == nil {
		cause = err
	}
	switch {
	case isNetTimeout(err):
		return pipeline.UserspaceExitTimeout
	case goerrors.Is(cause, syscall.ECONNRESET) || goerrors.Is(cause, syscall.EPIPE) || goerrors.Is(cause, io.ErrClosedPipe):
		return pipeline.UserspaceExitRemoteReset
	case isLocalUserspaceClose(cause):
		if userspaceBytes == 0 {
			return pipeline.UserspaceExitLocalCloseNoResponse
		}
		if stableUserspace {
			return pipeline.UserspaceExitStableUserspaceClose
		}
		return pipeline.UserspaceExitComplete
	case goerrors.Is(cause, io.EOF):
		if stableUserspace {
			return pipeline.UserspaceExitStableUserspaceClose
		}
		if userspaceBytes == 0 {
			return pipeline.UserspaceExitRemoteEOFNoResponse
		}
		return pipeline.UserspaceExitComplete
	default:
		if stableUserspace && userspaceBytes == 0 {
			return pipeline.UserspaceExitStableUserspaceClose
		}
		return pipeline.UserspaceExitNone
	}
}

func applyUserspaceExit(decision *pipeline.DecisionSnapshot, err error, stableUserspace bool) {
	if decision == nil {
		return
	}
	if exit := classifyUserspaceExit(err, decision.UserspaceBytes, stableUserspace); exit != pipeline.UserspaceExitNone {
		decision.UserspaceExit = exit
	}
}

func storeVisionDetachTimestamp(conn gonet.Conn, unixNano int64) {
	if unixNano <= 0 {
		return
	}
	dc := unwrapVisionDeferredConn(conn)
	if dc == nil {
		return
	}
	pipelineVisionDetachUnixByConn.Store(dc, unixNano)
}

func consumeVisionDetachTimestamp(conn gonet.Conn) (int64, bool) {
	dc := unwrapVisionDeferredConn(conn)
	if dc == nil {
		return 0, false
	}
	value, ok := pipelineVisionDetachUnixByConn.LoadAndDelete(dc)
	if !ok {
		return 0, false
	}
	unixNano, ok := value.(int64)
	if !ok || unixNano <= 0 {
		return 0, false
	}
	return unixNano, true
}

func deferredConnRequiresTLS(conn gonet.Conn) bool {
	dc := unwrapVisionDeferredConn(conn)
	if dc == nil {
		return false
	}
	if dc.IsDetached() {
		return false
	}
	return !dc.KTLSEnabled().Enabled
}

func isExpectedSpliceReadFromError(err error) bool {
	cause := errors.Cause(err)
	if cause == nil {
		cause = err
	}
	return goerrors.Is(cause, io.ErrClosedPipe) ||
		goerrors.Is(cause, gonet.ErrClosed) ||
		goerrors.Is(cause, context.Canceled) ||
		goerrors.Is(cause, syscall.EPIPE) ||
		goerrors.Is(cause, syscall.ECONNRESET) ||
		goerrors.Is(cause, syscall.ENOTCONN) ||
		goerrors.Is(cause, syscall.ESHUTDOWN)
}

func recordSpliceExpectedTeardownClass(err error) {
	cause := errors.Cause(err)
	if cause == nil {
		cause = err
	}
	switch {
	case goerrors.Is(cause, io.ErrClosedPipe) || goerrors.Is(cause, syscall.EPIPE):
		pipelineMarkerSpliceExpectedBrokenPipe.Add(1)
	case goerrors.Is(cause, syscall.ECONNRESET):
		pipelineMarkerSpliceExpectedConnReset.Add(1)
	case goerrors.Is(cause, gonet.ErrClosed):
		pipelineMarkerSpliceExpectedClosedConn.Add(1)
	case goerrors.Is(cause, context.Canceled):
		pipelineMarkerSpliceExpectedCanceled.Add(1)
	case goerrors.Is(cause, syscall.ENOTCONN):
		pipelineMarkerSpliceExpectedNotConn.Add(1)
	case goerrors.Is(cause, syscall.ESHUTDOWN):
		pipelineMarkerSpliceExpectedShutdown.Add(1)
	default:
		pipelineMarkerSpliceExpectedOther.Add(1)
	}
}

func recordSpliceUnexpectedReset(err error) {
	cause := errors.Cause(err)
	if cause == nil {
		cause = err
	}
	if goerrors.Is(cause, syscall.EPIPE) || goerrors.Is(cause, syscall.ECONNRESET) {
		pipelineMarkerSpliceExpectedBrokenPipe.Add(1) // reuse existing counter for visibility
	}
}

func ktlsStateName(txReady, rxReady bool) string {
	switch {
	case txReady && rxReady:
		return "ktls-both"
	case txReady:
		return "ktls-tx-only"
	case rxReady:
		return "ktls-rx-only"
	default:
		return "userspace"
	}
}

func cryptoHintName(h ebpf.CryptoHint) string {
	switch h {
	case ebpf.CryptoNone:
		return "none"
	case ebpf.CryptoKTLSBoth:
		return "ktls-both"
	case ebpf.CryptoKTLSTxOnly:
		return "ktls-tx-only"
	case ebpf.CryptoKTLSRxOnly:
		return "ktls-rx-only"
	case ebpf.CryptoUserspaceTLS:
		return "userspace-tls"
	default:
		return "unknown"
	}
}

func readV(ctx context.Context, reader buf.Reader, writer buf.Writer, timer signal.ActivityUpdater, readCounter stats.Counter, sizeCounter *buf.SizeCounter) error {
	errors.LogDebug(ctx, "CopyRawConn (maybe) readv")
	opts := []buf.CopyOption{buf.UpdateActivity(timer), buf.AddToStatCounter(readCounter)}
	if sizeCounter != nil {
		opts = append(opts, buf.CountSize(sizeCounter))
	}
	if err := buf.Copy(reader, writer, opts...); err != nil {
		return errors.New("failed to process response").Base(err)
	}
	return nil
}

func IsRAWTransportWithoutSecurity(conn stat.Connection) bool {
	iConn := stat.TryUnwrapStatsConn(conn)
	_, ok1 := iConn.(*proxyproto.Conn)
	_, ok2 := iConn.(*net.TCPConn)
	_, ok3 := iConn.(*internet.UnixConnWrapper)
	return ok1 || ok2 || ok3
}
