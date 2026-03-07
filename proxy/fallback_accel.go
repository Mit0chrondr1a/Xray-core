package proxy

import (
	"context"
	gonet "net"

	"github.com/pires/go-proxyproto"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/proxy/vless/encryption"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

var copyRawConnIfExistFn = CopyRawConnIfExist
var fallbackRawHandoffEligibleFn = fallbackRawHandoffEligible

func fallbackRawHandoffEligible(conn gonet.Conn) bool {
	conn = stat.TryUnwrapStatsConn(conn)
	switch c := conn.(type) {
	case *gonet.TCPConn, *proxyproto.Conn, *internet.UnixConnWrapper:
		return true
	case *tls.Conn:
		state := c.KTLSEnabled()
		return state.TxReady && state.RxReady
	case *tls.RustConn:
		state := c.KTLSEnabled()
		return state.TxReady && state.RxReady
	case *tls.DeferredRustConn:
		if c.IsDetached() {
			return true
		}
		state := c.KTLSEnabled()
		return state.TxReady && state.RxReady
	case *encryption.CommonConn, *encryption.XorConn:
		return false
	default:
		return false
	}
}

func fallbackRawCopyContext(ctx context.Context, clientConn, backendConn gonet.Conn) (context.Context, bool) {
	inbound := session.InboundFromContext(ctx)
	if inbound == nil {
		return ctx, false
	}
	if inbound.CopyGateState() == session.CopyGateForcedUserspace || inbound.CopyGateState() == session.CopyGateNotApplicable {
		return ctx, false
	}
	if clientConn == nil || backendConn == nil {
		return ctx, false
	}
	if !fallbackRawHandoffEligibleFn(clientConn) || !fallbackRawHandoffEligibleFn(backendConn) {
		return ctx, false
	}

	clonedInbound := *inbound
	clonedInbound.Conn = clientConn
	clonedInbound.SetCopyGate(session.CopyGateEligible, session.CopyGateReasonUnspecified)

	outbound := &session.Outbound{Conn: backendConn}
	outbound.SetCopyGate(session.CopyGateEligible, session.CopyGateReasonUnspecified)

	copyCtx := session.ContextWithInbound(ctx, &clonedInbound)
	copyCtx = session.ContextWithOutbounds(copyCtx, []*session.Outbound{outbound})
	return copyCtx, true
}

func copyFallbackUserspace(reader buf.Reader, writer buf.Writer, timer *signal.ActivityTimer) error {
	if timer == nil {
		return buf.Copy(reader, writer)
	}
	return buf.Copy(reader, writer, buf.UpdateActivity(timer))
}

func flushFallbackBufferedPrelude(reader buf.Reader, writer buf.Writer, timer *signal.ActivityTimer) error {
	buffered, ok := reader.(*buf.BufferedReader)
	if !ok || buffered.BufferedBytes() == 0 {
		return nil
	}
	mb, err := buffered.ReadMultiBuffer()
	if !mb.IsEmpty() {
		if timer != nil {
			timer.Update()
		}
		if werr := writer.WriteMultiBuffer(mb); werr != nil {
			return werr
		}
	}
	return err
}

// CopyFallbackRequest flushes any buffered classification prelude, then upgrades
// the steady-state leg to the raw-copy pipeline when both sides are eligible.
func CopyFallbackRequest(ctx context.Context, clientConn, backendConn gonet.Conn, reader buf.Reader, writer buf.Writer, timer *signal.ActivityTimer) error {
	copyCtx, rawEligible := fallbackRawCopyContext(ctx, clientConn, backendConn)
	if !rawEligible {
		return copyFallbackUserspace(reader, writer, timer)
	}
	if err := flushFallbackBufferedPrelude(reader, writer, timer); err != nil {
		return err
	}
	return copyRawConnIfExistFn(copyCtx, clientConn, backendConn, writer, timer, nil)
}

// CopyFallbackResponse hands the steady-state fallback response leg to the
// shared raw-copy pipeline when the client and backend transports are eligible.
func CopyFallbackResponse(ctx context.Context, backendConn, clientConn gonet.Conn, writer buf.Writer, timer *signal.ActivityTimer) error {
	copyCtx, rawEligible := fallbackRawCopyContext(ctx, clientConn, backendConn)
	if !rawEligible {
		return copyFallbackUserspace(buf.NewReader(backendConn), writer, timer)
	}
	return copyRawConnIfExistFn(copyCtx, backendConn, clientConn, writer, timer, nil)
}
