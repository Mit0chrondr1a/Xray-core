package mux

import (
	"context"
	stderrors "errors"
	"io"
	gonet "net"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/xtls/xray-core/common/errors"
)

const muxMarkerLogInterval = 30 * time.Second

var (
	muxMarkerLastLogUnix atomic.Int64

	muxMarkerSessionEndTotal      atomic.Uint64
	muxMarkerSessionEndClosedPipe atomic.Uint64
	muxMarkerSessionEndEOF        atomic.Uint64
	muxMarkerSessionEndOther      atomic.Uint64

	muxMarkerXUDPNew          atomic.Uint64
	muxMarkerXUDPHit          atomic.Uint64
	muxMarkerXUDPConflict     atomic.Uint64
	muxMarkerXUDPMapFull      atomic.Uint64
	muxMarkerXUDPDispatchFail atomic.Uint64
	muxMarkerXUDPPut          atomic.Uint64
	muxMarkerXUDPEvictExp     atomic.Uint64
	muxMarkerXUDPEvictActive  atomic.Uint64
	muxMarkerXUDPDelExpired   atomic.Uint64

	muxMarkerLastSessionEndTotal      atomic.Uint64
	muxMarkerLastSessionEndClosedPipe atomic.Uint64
	muxMarkerLastSessionEndEOF        atomic.Uint64
	muxMarkerLastSessionEndOther      atomic.Uint64
	muxMarkerLastXUDPNew              atomic.Uint64
	muxMarkerLastXUDPHit              atomic.Uint64
	muxMarkerLastXUDPConflict         atomic.Uint64
	muxMarkerLastXUDPMapFull          atomic.Uint64
	muxMarkerLastXUDPDispatchFail     atomic.Uint64
	muxMarkerLastXUDPPut              atomic.Uint64
	muxMarkerLastXUDPEvictExp         atomic.Uint64
	muxMarkerLastXUDPEvictActive      atomic.Uint64
	muxMarkerLastXUDPDelExpired       atomic.Uint64
)

func muxMarkerSnapshot(total *atomic.Uint64, last *atomic.Uint64) (current uint64, delta uint64) {
	current = total.Load()
	previous := last.Swap(current)
	return current, current - previous
}

func maybeLogMuxMarkers(ctx context.Context) {
	now := time.Now().UnixNano()
	last := muxMarkerLastLogUnix.Load()
	if last != 0 && now-last < int64(muxMarkerLogInterval) {
		return
	}
	if !muxMarkerLastLogUnix.CompareAndSwap(last, now) {
		return
	}

	sessionTotal, sessionTotalDelta := muxMarkerSnapshot(&muxMarkerSessionEndTotal, &muxMarkerLastSessionEndTotal)
	sessionClosedPipe, sessionClosedPipeDelta := muxMarkerSnapshot(&muxMarkerSessionEndClosedPipe, &muxMarkerLastSessionEndClosedPipe)
	sessionEOF, sessionEOFDelta := muxMarkerSnapshot(&muxMarkerSessionEndEOF, &muxMarkerLastSessionEndEOF)
	sessionOther, sessionOtherDelta := muxMarkerSnapshot(&muxMarkerSessionEndOther, &muxMarkerLastSessionEndOther)

	xudpNew, xudpNewDelta := muxMarkerSnapshot(&muxMarkerXUDPNew, &muxMarkerLastXUDPNew)
	xudpHit, xudpHitDelta := muxMarkerSnapshot(&muxMarkerXUDPHit, &muxMarkerLastXUDPHit)
	xudpConflict, xudpConflictDelta := muxMarkerSnapshot(&muxMarkerXUDPConflict, &muxMarkerLastXUDPConflict)
	xudpMapFull, xudpMapFullDelta := muxMarkerSnapshot(&muxMarkerXUDPMapFull, &muxMarkerLastXUDPMapFull)
	xudpDispatchFail, xudpDispatchFailDelta := muxMarkerSnapshot(&muxMarkerXUDPDispatchFail, &muxMarkerLastXUDPDispatchFail)
	xudpPut, xudpPutDelta := muxMarkerSnapshot(&muxMarkerXUDPPut, &muxMarkerLastXUDPPut)
	xudpEvictExp, xudpEvictExpDelta := muxMarkerSnapshot(&muxMarkerXUDPEvictExp, &muxMarkerLastXUDPEvictExp)
	xudpEvictActive, xudpEvictActiveDelta := muxMarkerSnapshot(&muxMarkerXUDPEvictActive, &muxMarkerLastXUDPEvictActive)
	xudpDelExpired, xudpDelExpiredDelta := muxMarkerSnapshot(&muxMarkerXUDPDelExpired, &muxMarkerLastXUDPDelExpired)

	errors.LogInfo(ctx, "mux markers[kind=session-end]: ",
		"total=", sessionTotal, "(+", sessionTotalDelta, ") ",
		"closed_pipe=", sessionClosedPipe, "(+", sessionClosedPipeDelta, ") ",
		"eof=", sessionEOF, "(+", sessionEOFDelta, ") ",
		"other=", sessionOther, "(+", sessionOtherDelta, ")",
	)
	errors.LogInfo(ctx, "mux markers[kind=xudp]: ",
		"new=", xudpNew, "(+", xudpNewDelta, ") ",
		"hit=", xudpHit, "(+", xudpHitDelta, ") ",
		"conflict=", xudpConflict, "(+", xudpConflictDelta, ") ",
		"map_full=", xudpMapFull, "(+", xudpMapFullDelta, ") ",
		"dispatch_fail=", xudpDispatchFail, "(+", xudpDispatchFailDelta, ") ",
		"put=", xudpPut, "(+", xudpPutDelta, ") ",
		"evict_expiring=", xudpEvictExp, "(+", xudpEvictExpDelta, ") ",
		"evict_active=", xudpEvictActive, "(+", xudpEvictActiveDelta, ") ",
		"del_expired=", xudpDelExpired, "(+", xudpDelExpiredDelta, ")",
	)
}

func recordMuxSessionEnd(err error) {
	if err == nil {
		return
	}
	muxMarkerSessionEndTotal.Add(1)
	cause := errors.Cause(err)
	if cause == nil {
		cause = err
	}
	switch {
	case stderrors.Is(cause, io.EOF):
		muxMarkerSessionEndEOF.Add(1)
	case stderrors.Is(cause, io.ErrClosedPipe),
		stderrors.Is(cause, gonet.ErrClosed),
		stderrors.Is(cause, syscall.EPIPE),
		stderrors.Is(cause, syscall.ECONNRESET),
		strings.Contains(strings.ToLower(cause.Error()), "closed pipe"):
		muxMarkerSessionEndClosedPipe.Add(1)
	default:
		muxMarkerSessionEndOther.Add(1)
	}
	maybeLogMuxMarkers(context.Background())
}

func recordXUDPNew() {
	muxMarkerXUDPNew.Add(1)
	maybeLogMuxMarkers(context.Background())
}

func recordXUDPHit() {
	muxMarkerXUDPHit.Add(1)
	maybeLogMuxMarkers(context.Background())
}

func recordXUDPConflict() {
	muxMarkerXUDPConflict.Add(1)
	maybeLogMuxMarkers(context.Background())
}

func recordXUDPMapFull() {
	muxMarkerXUDPMapFull.Add(1)
	maybeLogMuxMarkers(context.Background())
}

func recordXUDPDispatchFail() {
	muxMarkerXUDPDispatchFail.Add(1)
	maybeLogMuxMarkers(context.Background())
}

func recordXUDPPut() {
	muxMarkerXUDPPut.Add(1)
	maybeLogMuxMarkers(context.Background())
}

func recordXUDPEvictExpiring() {
	muxMarkerXUDPEvictExp.Add(1)
	maybeLogMuxMarkers(context.Background())
}

func recordXUDPEvictActive() {
	muxMarkerXUDPEvictActive.Add(1)
	maybeLogMuxMarkers(context.Background())
}

func recordXUDPDelExpired() {
	muxMarkerXUDPDelExpired.Add(1)
	maybeLogMuxMarkers(context.Background())
}
