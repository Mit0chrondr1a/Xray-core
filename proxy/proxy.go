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
	pipelineMarkerSockmapSkipLoopback         atomic.Uint64
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
	pipelineMarkerLastSockmapSkipLoopback         atomic.Uint64
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
	pipelineVisionDetachFutureByConn  sync.Map
	startupHealthOnce                 sync.Once
)

const visionDetachTimeout = 500 * time.Millisecond
const loopbackDetachGuardPort = 2036

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
}

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
	UserUUID               []byte
	NumberOfPacketToFilter int
	CreatedAtUnixNano      int64
	EnableXtls             bool
	IsTLS12orAbove         bool
	IsTLS                  bool
	Cipher                 uint16
	RemainingServerHello   int32
	Inbound                InboundState
	Outbound               OutboundState
}

type InboundState struct {
	// reader link state
	WithinPaddingBuffers   bool
	UplinkReaderDirectCopy bool
	RemainingCommand       int32
	RemainingContent       int32
	RemainingPadding       int32
	CurrentCommand         int
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
		NumberOfPacketToFilter: visionPacketsToFilterDefault,
		CreatedAtUnixNano:      time.Now().UnixNano(),
		EnableXtls:             false,
		IsTLS12orAbove:         false,
		IsTLS:                  false,
		Cipher:                 0,
		RemainingServerHello:   -1,
		Inbound: InboundState{
			WithinPaddingBuffers:     true,
			UplinkReaderDirectCopy:   false,
			RemainingCommand:         -1,
			RemainingContent:         -1,
			RemainingPadding:         -1,
			CurrentCommand:           0,
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
			IsPadding:                true,
			UplinkWriterDirectCopy:   false,
		},
	}
}

func unwrapVisionDeferredConn(conn net.Conn) *tls.DeferredRustConn {
	if conn == nil {
		return nil
	}
	if dc, ok := conn.(*tls.DeferredRustConn); ok {
		return dc
	}
	if sc := stat.TryUnwrapStatsConn(conn); sc != nil && sc != conn {
		if dc, ok := sc.(*tls.DeferredRustConn); ok {
			return dc
		}
	}
	if cc, ok := conn.(*encryption.CommonConn); ok && cc != nil {
		if dc, ok := cc.Conn.(*tls.DeferredRustConn); ok {
			return dc
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
		fut.startedAt = time.Now()
		pipelineMarkerVisionDrainDetachAttempt.Add(1)
		go func() {
			plaintext, rawAhead, err := dc.DrainAndDetach()
			duration := time.Since(fut.startedAt)
			if err != nil {
				pipelineMarkerVisionDrainDetachFail.Add(1)
			} else {
				pipelineMarkerVisionDrainDetachSuccess.Add(1)
			}
			fut.result = visionDetachResult{
				plaintext: plaintext,
				rawAhead:  rawAhead,
				err:       err,
				duration:  duration,
			}
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
	conn         net.Conn
	input        *bytes.Reader
	rawInput     *bytes.Buffer
	ob           *session.Outbound

	// internal
	directReadCounter stats.Counter
}

func NewVisionReader(reader buf.Reader, trafficState *TrafficState, isUplink bool, ctx context.Context, conn net.Conn, input *bytes.Reader, rawInput *bytes.Buffer, ob *session.Outbound) *VisionReader {
	return &VisionReader{
		Reader:       reader,
		trafficState: trafficState,
		ctx:          ctx,
		isUplink:     isUplink,
		conn:         conn,
		input:        input,
		rawInput:     rawInput,
		ob:           ob,
	}
}

func (w *VisionReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	buffer, err := w.Reader.ReadMultiBuffer()
	if buffer.IsEmpty() {
		return buffer, err
	}

	var withinPaddingBuffers *bool
	var remainingContent *int32
	var remainingPadding *int32
	var currentCommand *int
	var switchToDirectCopy *bool
	if w.isUplink {
		withinPaddingBuffers = &w.trafficState.Inbound.WithinPaddingBuffers
		remainingContent = &w.trafficState.Inbound.RemainingContent
		remainingPadding = &w.trafficState.Inbound.RemainingPadding
		currentCommand = &w.trafficState.Inbound.CurrentCommand
		switchToDirectCopy = &w.trafficState.Inbound.UplinkReaderDirectCopy
	} else {
		withinPaddingBuffers = &w.trafficState.Outbound.WithinPaddingBuffers
		remainingContent = &w.trafficState.Outbound.RemainingContent
		remainingPadding = &w.trafficState.Outbound.RemainingPadding
		currentCommand = &w.trafficState.Outbound.CurrentCommand
		switchToDirectCopy = &w.trafficState.Outbound.DownlinkReaderDirectCopy
	}

	if *switchToDirectCopy {
		if w.directReadCounter != nil {
			w.directReadCounter.Add(int64(buffer.Len()))
		}
		return buffer, err
	}

	if *withinPaddingBuffers || w.trafficState.NumberOfPacketToFilter > 0 {
		mb2 := buf.GetMultiBuffer()
		for _, b := range buffer {
			newbuffer := XtlsUnpadding(b, w.trafficState, w.isUplink, w.ctx)
			if newbuffer.Len() > 0 {
				mb2 = append(mb2, newbuffer)
			} else {
				newbuffer.Release()
			}
		}
		buffer = mb2
		if *remainingContent > 0 || *remainingPadding > 0 || *currentCommand == 0 {
			*withinPaddingBuffers = true
		} else if *currentCommand == 1 {
			*withinPaddingBuffers = false
		} else if *currentCommand == 2 {
			*withinPaddingBuffers = false
			*switchToDirectCopy = true
		} else {
			errors.LogDebug(w.ctx, "XtlsRead unknown command ", *currentCommand, buffer.Len())
		}
	}
	if w.trafficState.NumberOfPacketToFilter > 0 {
		XtlsFilterTls(buffer, w.trafficState, w.ctx)
	}

	if *switchToDirectCopy {
		loopbackGuard := isLoopbackDetachGuardedConn(w.conn)
		if loopbackGuard && isDNSPortOutbound(w.ctx) {
			errors.LogInfo(w.ctx, "Vision: loopback DNS flow; keeping rustls (no detach/zero-copy)")
			*switchToDirectCopy = false
			return buffer, err
		}
		if loopbackGuard {
			errors.LogInfo(w.ctx, "Vision: loopback guarded flow; detaching but pinning to userspace copy (no zero-copy)")
		}
		if dc := unwrapVisionDeferredConn(w.conn); dc != nil {
			fut := startVisionDetach(dc)
			wait := visionDetachTimeout
			if !fut.startedAt.IsZero() {
				if elapsed := time.Since(fut.startedAt); elapsed < visionDetachTimeout {
					wait = visionDetachTimeout - elapsed
				} else {
					wait = 0
				}
			}
			select {
			case <-fut.done:
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
				if w.trafficState != nil && w.trafficState.CreatedAtUnixNano > 0 && detachDoneUnix > w.trafficState.CreatedAtUnixNano {
					pipelineMarkerVisionPaddingPhaseNanos.Add(uint64(detachDoneUnix - w.trafficState.CreatedAtUnixNano))
					pipelineMarkerVisionPaddingPhaseCount.Add(1)
				}
				if rawUnwrapUnix, ok := consumeVisionRawUnwrapWarningTimestamp(w.conn); ok && detachDoneUnix > rawUnwrapUnix {
					unwrapToDetachNs := uint64(detachDoneUnix - rawUnwrapUnix)
					pipelineMarkerRawUnwrapToDetachNanosTotal.Add(unwrapToDetachNs)
					pipelineMarkerRawUnwrapToDetachSamples.Add(1)
					recordRawUnwrapToDetachHistogram(unwrapToDetachNs)
				}
				storeVisionDetachTimestamp(w.conn, detachDoneUnix)
				errors.LogDebug(w.ctx, "Vision: DeferredRustConn drained and detached; switching reader to raw socket")
				if len(fut.result.plaintext) > 0 {
					buffer = append(buffer, buf.FromBytes(fut.result.plaintext))
				}
				if len(fut.result.rawAhead) > 0 {
					buffer = append(buffer, buf.FromBytes(fut.result.rawAhead))
				}
				pipelineVisionDetachFutureByConn.Delete(dc)
			case <-time.After(wait):
				pipelineMarkerVisionDetachTimeout.Add(1)
				maybeLogPipelineRuntimeSummary(w.ctx)
				errors.LogWarning(w.ctx, "[kind=vision.drain_detach_timeout] DeferredRustConn drain still pending; staying on rustls path")
				*switchToDirectCopy = false
				return buffer, err
			}
		} else {
			// XTLS Vision processes TLS-like conn's input and rawInput
			if w.input != nil {
				if inputBuffer, err := buf.ReadFrom(w.input); err == nil && !inputBuffer.IsEmpty() {
					buffer, _ = buf.MergeMulti(buffer, inputBuffer)
				}
				*w.input = bytes.Reader{} // release memory
				w.input = nil
			}
			if w.rawInput != nil {
				if rawInputBuffer, err := buf.ReadFrom(w.rawInput); err == nil && !rawInputBuffer.IsEmpty() {
					buffer, _ = buf.MergeMulti(buffer, rawInputBuffer)
				}
				*w.rawInput = bytes.Buffer{} // release memory
				w.rawInput = nil
			}
		}

		if inbound := session.InboundFromContext(w.ctx); inbound != nil && inbound.Conn != nil && inbound.GetCanSpliceCopy() == 2 {
			// Vision command=2 reached and reader switched to raw path. At this
			// point TLS decryption is no longer required on this leg, so the
			// response copy loop can safely transition to splice/readv-raw path.
			inbound.SetCanSpliceCopy(1)
		}

		if inbound := session.InboundFromContext(w.ctx); inbound != nil && inbound.Conn != nil {
			// if w.isUplink && inbound.CanSpliceCopy == 2 { // TODO: enable uplink splice
			// 	inbound.CanSpliceCopy = 1
			// }
			if !w.isUplink && w.ob != nil && w.ob.GetCanSpliceCopy() == 2 { // ob need to be passed in due to context can have more than one ob
				w.ob.SetCanSpliceCopy(1)
			}
		}
		readerConn, readCounter, _, readerHandler := UnwrapRawConn(w.conn)
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
	var isPadding *bool
	var switchToDirectCopy *bool
	loopbackGuard := isLoopbackDetachGuardedConn(w.conn)
	if w.isUplink {
		isPadding = &w.trafficState.Outbound.IsPadding
		switchToDirectCopy = &w.trafficState.Outbound.UplinkWriterDirectCopy
	} else {
		isPadding = &w.trafficState.Inbound.IsPadding
		switchToDirectCopy = &w.trafficState.Inbound.DownlinkWriterDirectCopy
	}
	switchNow := *switchToDirectCopy
	if switchNow {
		if loopbackGuard {
			if isDNSPortOutbound(w.ctx) {
				errors.LogInfo(w.ctx, "Vision: loopback DNS flow (writer); keeping rustls (no detach/zero-copy)")
				switchNow = false
				*switchToDirectCopy = false
			} else {
				errors.LogInfo(w.ctx, "Vision: loopback guarded flow (writer); detaching but disabling zero-copy")
			}
		}
		dc := unwrapVisionDeferredConn(w.conn)
		deferredReady := true
		// Avoid raw unwrap while DeferredRustConn still owns unread rustls state.
		// Wait until detach (or kTLS promotion) completes, then switch.
		if dc != nil && !dc.IsDetached() && !dc.KTLSEnabled().Enabled {
			deferredReady = false
			switchNow = false
		}

		if inbound := session.InboundFromContext(w.ctx); inbound != nil {
			// NOTE: CanSpliceCopy stays at 2 while DeferredRustConn is active
			// because CopyRawConn uses CanSpliceCopy==1 to gate rawUserspaceReader,
			// which bypasses TLS decryption on the outbound — wrong for HTTPS targets.
			if !w.isUplink && inbound.GetCanSpliceCopy() == 2 && deferredReady {
				inbound.SetCanSpliceCopy(1)
			}
			// if w.isUplink && w.ob != nil && w.ob.CanSpliceCopy == 2 { // TODO: enable uplink splice
			// 	w.ob.CanSpliceCopy = 1
			// }
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

	if w.trafficState.NumberOfPacketToFilter > 0 {
		XtlsFilterTls(mb, w.trafficState, w.ctx)
	}

	if *isPadding {
		if len(mb) == 1 && mb[0] == nil {
			mb[0] = XtlsPadding(nil, CommandPaddingContinue, &w.writeOnceUserUUID, true, w.ctx, w.testseed) // we do a long padding to hide vless header
			return w.Writer.WriteMultiBuffer(mb)
		}
		isComplete := IsCompleteRecord(mb)
		mb = ReshapeMultiBuffer(w.ctx, mb)
		longPadding := w.trafficState.IsTLS
		for i, b := range mb {
			allowDirectOnFragmentedTLS13 := w.trafficState.EnableXtls
			if w.trafficState.IsTLS &&
				b.Len() >= 6 &&
				bytes.Equal(TlsApplicationDataStart, b.BytesTo(3)) &&
				(isComplete || allowDirectOnFragmentedTLS13) {
				if w.trafficState.EnableXtls {
					*switchToDirectCopy = true
				}
				var command byte = CommandPaddingContinue
				if i == len(mb)-1 {
					command = CommandPaddingEnd
					if w.trafficState.EnableXtls {
						command = CommandPaddingDirect
					}
				}
				mb[i] = XtlsPadding(b, command, &w.writeOnceUserUUID, true, w.ctx, w.testseed)
				*isPadding = false // padding going to end
				longPadding = false
				continue
			} else if !w.trafficState.IsTLS12orAbove && w.trafficState.NumberOfPacketToFilter <= 1 { // For compatibility with earlier vision receiver, we finish padding 1 packet early
				*isPadding = false
				mb[i] = XtlsPadding(b, CommandPaddingEnd, &w.writeOnceUserUUID, longPadding, w.ctx, w.testseed)
				break
			}
			var command byte = CommandPaddingContinue
			if i == len(mb)-1 && !*isPadding {
				command = CommandPaddingEnd
				if w.trafficState.EnableXtls {
					command = CommandPaddingDirect
				}
			}
			mb[i] = XtlsPadding(b, command, &w.writeOnceUserUUID, longPadding, w.ctx, w.testseed)
		}
	}
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
					errors.LogWarning(context.Background(),
						"[kind=vision.deferred_raw_unwrap] UnwrapRawConn: DeferredRustConn is neither detached nor kTLS-active; unwrapping to raw socket may lose rustls-buffered data")
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

// CopyRawConnIfExist use the most efficient copy method.
// - If caller don't want to turn on splice, do not pass in both reader conn and writer conn
// - writer are from *transport.Link
func CopyRawConnIfExist(ctx context.Context, readerConn net.Conn, writerConn net.Conn, writer buf.Writer, timer *signal.ActivityTimer, inTimer *signal.ActivityTimer) error {
	disableAccel := os.Getenv("XRAY_DEBUG_DISABLE_ACCEL") == "1"
	disableIdle := os.Getenv("XRAY_DEBUG_IDLE_INFINITE") == "1"
	userspaceReader := buf.NewReader(readerConn)

	decisionCaps := pipelineCapabilities()
	decision := pipeline.DecisionSnapshot{
		Path:   pipeline.PathUserspace,
		Reason: pipeline.ReasonDefault,
		Caps:   decisionCaps,
		Kind:   "proxy",
	}
	defer func() {
		logPipelineDecision(ctx, string(decision.Path), decision.Reason, decisionCaps)
		logPipelineSummary(ctx, decision)
	}()
	defer clearVisionTelemetryTimestamps(readerConn, writerConn)

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
		sc := &buf.SizeCounter{}
		start := time.Now()
		err := readV(ctx, userspaceReader, writer, timer, nil, sc)
		decision.UserspaceBytes = sc.Size
		decision.UserspaceDurationNs = time.Since(start).Nanoseconds()
		decision.Path = pipeline.PathUserspace
		return err
	}
	if inbound.GetCanSpliceCopy() == 3 {
		errors.LogDebug(ctx, "CopyRawConn fallback to readv: inbound.CanSpliceCopy=3")
		decision.Reason = pipeline.ReasonInboundForcedUserspace
		sc := &buf.SizeCounter{}
		start := time.Now()
		err := readV(ctx, userspaceReader, writer, timer, nil, sc)
		decision.UserspaceBytes = sc.Size
		decision.UserspaceDurationNs = time.Since(start).Nanoseconds()
		decision.Path = pipeline.PathUserspace
		return err
	}
	outbounds := session.OutboundsFromContext(ctx)
	if len(outbounds) == 0 {
		errors.LogDebug(ctx, "CopyRawConn fallback to readv: no outbound metadata")
		decision.Reason = pipeline.ReasonMissingOutboundMetadata
		sc := &buf.SizeCounter{}
		start := time.Now()
		err := readV(ctx, userspaceReader, writer, timer, nil, sc)
		decision.UserspaceBytes = sc.Size
		decision.UserspaceDurationNs = time.Since(start).Nanoseconds()
		decision.Path = pipeline.PathUserspace
		return err
	}
	for i, ob := range outbounds {
		if ob.GetCanSpliceCopy() == 3 {
			errors.LogDebug(ctx, "CopyRawConn fallback to readv: outbounds[", i, "].CanSpliceCopy=3")
			sc := &buf.SizeCounter{}
			start := time.Now()
			err := readV(ctx, userspaceReader, writer, timer, nil, sc)
			decision.UserspaceBytes = sc.Size
			decision.UserspaceDurationNs = time.Since(start).Nanoseconds()
			decision.Path = pipeline.PathUserspace
			decision.Reason = pipeline.ReasonOutboundForcedUserspace
			return err
		}
	}

	loopbackDetachGuard := isLoopbackDetachGuardedConn(readerConn) || isLoopbackDetachGuardedConn(writerConn) || isLoopbackDetachGuardedConn(inbound.Conn)

	if loopbackDetachGuard {
		lr, rr := connAddrs(readerConn)
		lw, rw := connAddrs(writerConn)
		errors.LogInfo(ctx, "CopyRawConn loopback guard active: disabling splice/sockmap; reader_addrs=", lr, "->", rr, " writer_addrs=", lw, "->", rw)
		// For DNS (DoT) on the loopback ingress, align with main-branch behavior:
		// bypass all acceleration (sockmap/splice/ktls) and stick to userspace
		// copy to avoid startup cork/pop.
		if dest := outbounds[len(outbounds)-1].Target; dest.Network == net.Network_TCP && (dest.Port == net.Port(53) || dest.Port == net.Port(853)) {
			decision.Path = pipeline.PathUserspace
			decision.Reason = pipeline.ReasonLoopbackDNSGuard
			sc := &buf.SizeCounter{}
			start := time.Now()
			err := readV(ctx, userspaceReader, writer, timer, nil, sc)
			decision.UserspaceBytes = sc.Size
			decision.UserspaceDurationNs = time.Since(start).Nanoseconds()
			return err
		}
	}

	loggedUserspaceLoop := false
	userspaceStart := time.Now()
	forceUserspaceAfterSockmap := false

	// Phase-aware idle policy:
	// - preDetach: while deferred TLS still active; keep tight to surface jam early.
	// - noDetach: deferred TLS continues without detach; enforce tighter timeout.
	// - postDetach: after detach/promotion; give a bit more headroom.
	// - streaming: once payload flows, grow gently up to a cap.
	const (
		userspacePhasePreDetach  = "pre_detach"
		userspacePhaseNoDetach   = "no_detach"
		userspacePhasePostDetach = "post_detach"
		userspacePhaseStreaming  = "streaming"
	)
	var (
		// Defaults tuned for fast stall surfacing.
		idlePreDetach      = 2 * time.Second
		idleNoDetach       = 10 * time.Second
		idlePostDetach     = 20 * time.Second
		idleStreamingMax   = 60 * time.Second
		noDetachMinAge     = 5 * time.Second
		noDetachMaxWallDur = 60 * time.Second
		spliceProbeTimeout = 3 * time.Second
		spliceProbeMinByte = int64(32)
	)
	if disableIdle {
		// For debugging correctness: practically disable idle timeouts.
		idlePreDetach = 10 * time.Minute
		idleNoDetach = 10 * time.Minute
		idlePostDetach = 10 * time.Minute
		idleStreamingMax = 2 * time.Hour
		noDetachMinAge = 10 * time.Minute
		noDetachMaxWallDur = 2 * time.Hour
	}
	if loopbackDetachGuard && len(outbounds) > 0 {
		dest := outbounds[len(outbounds)-1].Target
		if dest.Network == net.Network_TCP && (dest.Port == net.Port(53) || dest.Port == net.Port(853)) {
			// DNS on loopback ingress: disable userspace idle watchdog to avoid
			// late DNS replies being cut off (matches baseline behavior).
			disableIdle = true
			idlePreDetach = 30 * time.Minute
			idleNoDetach = 30 * time.Minute
			idlePostDetach = 30 * time.Minute
			idleStreamingMax = 30 * time.Minute
			noDetachMinAge = 30 * time.Minute
			noDetachMaxWallDur = 30 * time.Minute
		}
	}
	idleTimeout := idlePreDetach
	phase := userspacePhasePreDetach
	deferredPayloadSeen := false
	noDetachSince := time.Time{}
	postDetachPhaseMarked := false
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
		var splice = !disableAccel && !forceUserspaceAfterSockmap && !loopbackDetachGuard && inbound.GetCanSpliceCopy() != 0 && inbound.GetCanSpliceCopy() != 3
		firstNonSpliceOutbound := -1
		firstNonSpliceValue := 0
		for i, ob := range outbounds {
			obSplice := ob.GetCanSpliceCopy()
			if obSplice == 0 || obSplice == 3 {
				splice = false
				if firstNonSpliceOutbound == -1 {
					firstNonSpliceOutbound = i
					firstNonSpliceValue = obSplice
				}
			}
		}
		readerStillUsesDeferredTLS := deferredConnRequiresTLS(readerConn)
		writerStillUsesDeferredTLS := deferredConnRequiresTLS(writerConn)
		deferredTLSActive := readerStillUsesDeferredTLS || writerStillUsesDeferredTLS
		if deferredTLSActive {
			if phase == userspacePhasePreDetach && deferredPayloadSeen && time.Since(userspaceStart) >= noDetachMinAge {
				phase = userspacePhaseNoDetach
				idleTimeout = idleNoDetach
				if noDetachSince.IsZero() {
					noDetachSince = time.Now()
				}
			}
		} else if phase == userspacePhasePreDetach || phase == userspacePhaseNoDetach {
			phase = userspacePhasePostDetach
			idleTimeout = idlePostDetach
		}
		if phase == userspacePhaseNoDetach && !noDetachSince.IsZero() && time.Since(noDetachSince) >= noDetachMaxWallDur {
			decision.Path = pipeline.PathUserspace
			decision.Reason = pipeline.ReasonUserspaceNoDetachIdleTimeout
			decision.UserspaceDurationNs = time.Since(userspaceStart).Nanoseconds()
			errors.LogWarning(ctx, "[kind=vision.no_detach_timeout] deferred userspace phase exceeded guard window")
			return io.EOF
		}
		if splice {
			input, currentReaderCrypto, currentWriterCrypto, currentReaderCryptoSource, currentWriterCryptoSource := buildVisionDecisionInput(readerConn, writerConn, decisionCaps, deferredTLSActive)
			readerCrypto = currentReaderCrypto
			writerCrypto = currentWriterCrypto
			readerCryptoSource = currentReaderCryptoSource
			writerCryptoSource = currentWriterCryptoSource
			decision = pipeline.DecideVisionPath(input)
			// Performance-first: keep loopback pairs on zero-copy instead of forcing
			// the slow userspace guard. Retain the marker so telemetry still shows
			// the guard trigger reason.
			if decision.Path == pipeline.PathSplice && input.LoopbackPair {
				decision.Reason = pipeline.ReasonLoopbackPairGuard
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
			input, currentReaderCrypto, currentWriterCrypto, currentReaderCryptoSource, currentWriterCryptoSource := buildVisionDecisionInput(readerConn, writerConn, decisionCaps, deferredTLSActive)
			readerCrypto = currentReaderCrypto
			writerCrypto = currentWriterCrypto
			readerCryptoSource = currentReaderCryptoSource
			writerCryptoSource = currentWriterCryptoSource
			if input.LoopbackPair && deferredTLSActive {
				decision.Path = pipeline.PathUserspace
				decision.Reason = pipeline.ReasonLoopbackTLSGuard
				sc := &buf.SizeCounter{}
				start := time.Now()
				err := readV(ctx, userspaceReader, writer, timer, nil, sc)
				decision.UserspaceBytes = sc.Size
				decision.UserspaceDurationNs = time.Since(start).Nanoseconds()
				return err
			}

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
			} else if isLoopbackConn(rawReaderConn) || isLoopbackConn(rawWriterConn) {
				pipelineMarkerSockmapSkipLoopback.Add(1)
				lr, rr := connAddrs(rawReaderConn)
				lw, rw := connAddrs(rawWriterConn)
				errors.LogInfo(ctx, "CopyRawConn sockmap skipped: loopback endpoint; reader_addrs=", lr, "->", rr, " writer_addrs=", lw, "->", rw)
				decision.Path = pipeline.PathSplice
				decision.Reason = pipeline.ReasonLoopbackPairGuard
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
			if inboundSplice != 1 {
				errors.LogDebug(ctx, "CopyRawConn userspace copy loop: inbound.CanSpliceCopy=", inboundSplice)
			} else if readerStillUsesDeferredTLS || writerStillUsesDeferredTLS {
				errors.LogDebug(ctx,
					"CopyRawConn userspace copy loop: deferred rustls still active",
					" reader=", readerStillUsesDeferredTLS,
					" writer=", writerStillUsesDeferredTLS,
				)
			} else {
				errors.LogDebug(ctx, "CopyRawConn userspace copy loop: outbounds[", firstNonSpliceOutbound, "].CanSpliceCopy=", firstNonSpliceValue)
			}
			loggedUserspaceLoop = true
		}
		currentReader := userspaceReader
		usingRawUserspaceReader := false
		// After Vision command=2, inbound switches to raw direct-copy mode.
		// If splice is disabled by peer metadata, userspace fallback must read
		// from the same unwrapped/raw layer to avoid waiting for TLS framing.
		if inbound.GetCanSpliceCopy() == 1 && !readerStillUsesDeferredTLS && ensureRaw() && rawUserspaceReader != nil {
			currentReader = rawUserspaceReader
			usingRawUserspaceReader = true
		}

		_ = readerConn.SetReadDeadline(time.Now().Add(idleTimeout))
		buffer, err := currentReader.ReadMultiBuffer()
		_ = readerConn.SetReadDeadline(time.Time{})
		if !buffer.IsEmpty() {
			pipelineMarkerUserspaceCopyReads.Add(1)
			pipelineMarkerUserspaceCopyBytesTotal.Add(uint64(buffer.Len()))
			decision.UserspaceBytes += int64(buffer.Len())
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
		}
		if err != nil {
			decision.UserspaceDurationNs = time.Since(userspaceStart).Nanoseconds()
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if phase == userspacePhaseNoDetach {
					decision.Reason = pipeline.ReasonUserspaceNoDetachIdleTimeout
				} else {
					decision.Reason = pipeline.ReasonUserspaceIdleTimeout
				}
				decision.Path = pipeline.PathUserspace
				// Treat idle timeout as clean close to avoid marking failures upstream.
				return io.EOF
			}
			if errors.Cause(err) == io.EOF {
				if decision.Reason == pipeline.ReasonDefault {
					decision.Reason = pipeline.ReasonUserspaceComplete
					decision.Path = pipeline.PathUserspace
				}
				return nil
			}
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

func isNilConnValue(conn net.Conn) bool {
	if conn == nil {
		return true
	}
	v := reflect.ValueOf(conn)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Map, reflect.Ptr, reflect.Slice, reflect.Interface:
		return v.IsNil()
	default:
		return false
	}
}

func isLoopbackDetachGuardedConn(conn net.Conn) bool {
	if isNilConnValue(conn) {
		return false
	}
	if drc, ok := conn.(*tls.DeferredRustConn); ok {
		if drc == nil {
			return false
		}
		if rc := drc.NetConn(); rc != nil {
			conn = rc
		} else {
			return false
		}
	}
	la := conn.LocalAddr()
	ra := conn.RemoteAddr()
	if la == nil || ra == nil {
		return false
	}
	lip := extractAddrIP(la)
	rip := extractAddrIP(ra)
	if lip == nil || rip == nil {
		return false
	}
	if !(lip.IsLoopback() || rip.IsLoopback()) {
		return false
	}
	_, lport, _ := gonet.SplitHostPort(la.String())
	_, rport, _ := gonet.SplitHostPort(ra.String())
	return lport == strconv.Itoa(loopbackDetachGuardPort) || rport == strconv.Itoa(loopbackDetachGuardPort)
}

// isLoopbackDetachGuardedInbound mirrors the detach guard check but only uses
// the inbound connection from context (safe for use in dispatcher).
func isLoopbackDetachGuardedInbound(ctx context.Context) bool {
	inb := session.InboundFromContext(ctx)
	if inb == nil || inb.Conn == nil {
		return false
	}
	return isLoopbackDetachGuardedConn(inb.Conn)
}

// isDNSPortOutbound returns true if the last outbound target is TCP:53 or TCP:853.
func isDNSPortOutbound(ctx context.Context) bool {
	outbounds := session.OutboundsFromContext(ctx)
	if len(outbounds) == 0 {
		return false
	}
	dest := outbounds[len(outbounds)-1].Target
	if dest.Network != net.Network_TCP {
		return false
	}
	return dest.Port == net.Port(53) || dest.Port == net.Port(853)
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
		" vision_detach_mode=async timeout=", visionDetachTimeout,
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

func clearVisionTelemetryTimestamps(conns ...gonet.Conn) {
	for _, conn := range conns {
		dc := unwrapVisionDeferredConn(conn)
		if dc == nil {
			continue
		}
		pipelineVisionRawUnwrapUnixByConn.Delete(dc)
		pipelineVisionDetachUnixByConn.Delete(dc)
		pipelineVisionDetachFutureByConn.Delete(dc)
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
