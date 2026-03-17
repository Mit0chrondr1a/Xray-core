package proxy

import (
	"bytes"
	"context"
	"net"
	"strings"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/pipeline"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
)

func TestCopyFallbackRequestFlushesPreludeBeforeRawHandoff(t *testing.T) {
	oldCopyRaw := copyRawConnIfExistFn
	oldEligible := fallbackRawHandoffEligibleFn
	t.Cleanup(func() {
		copyRawConnIfExistFn = oldCopyRaw
		fallbackRawHandoffEligibleFn = oldEligible
	})

	fallbackRawHandoffEligibleFn = func(net.Conn) bool { return true }

	var written bytes.Buffer
	copyRawConnIfExistFn = func(ctx context.Context, readerConn, writerConn net.Conn, writer buf.Writer, timer *signal.ActivityTimer, inTimer *signal.ActivityTimer) error {
		if got := written.String(); got != "HEAD" {
			t.Fatalf("buffered prelude = %q, want %q before raw handoff", got, "HEAD")
		}
		inbound := session.InboundFromContext(ctx)
		if inbound == nil || inbound.CopyGateState() != session.CopyGateEligible {
			t.Fatalf("inbound copy gate = %v, want %v", inbound.CopyGateState(), session.CopyGateEligible)
		}
		outbounds := session.OutboundsFromContext(ctx)
		if len(outbounds) != 1 || outbounds[0].CopyGateState() != session.CopyGateEligible {
			t.Fatalf("outbound copy gate = %v, want single eligible outbound", outbounds)
		}
		return nil
	}

	reader := &buf.BufferedReader{
		Reader: &buf.SingleReader{Reader: strings.NewReader("tail")},
		Buffer: buf.MultiBuffer{buf.FromBytes([]byte("HEAD"))},
	}
	writer := buf.NewWriter(&written)
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{})

	if err := CopyFallbackRequest(ctx, testEOFConn{}, testEOFConn{}, reader, writer, nil); err != nil {
		t.Fatalf("CopyFallbackRequest() error = %v", err)
	}
	if got := reader.BufferedBytes(); got != 0 {
		t.Fatalf("BufferedBytes = %d, want 0 after prelude flush", got)
	}
}

func TestCopyFallbackResponseForcedUserspacePreservesPayload(t *testing.T) {
	oldCopyRaw := copyRawConnIfExistFn
	oldEligible := fallbackRawHandoffEligibleFn
	t.Cleanup(func() {
		copyRawConnIfExistFn = oldCopyRaw
		fallbackRawHandoffEligibleFn = oldEligible
	})

	copyRawConnIfExistFn = func(context.Context, net.Conn, net.Conn, buf.Writer, *signal.ActivityTimer, *signal.ActivityTimer) error {
		t.Fatal("CopyRawConnIfExist should not be called when inbound forces userspace")
		return nil
	}
	fallbackRawHandoffEligibleFn = func(net.Conn) bool { return true }

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	go func() {
		_, _ = server.Write([]byte("fallback-response"))
		_ = server.Close()
	}()

	var written bytes.Buffer
	writer := buf.NewWriter(&written)
	inbound := &session.Inbound{}
	inbound.SetCopyGate(session.CopyGateForcedUserspace, session.CopyGateReasonSecurityGuard)
	ctx := session.ContextWithInbound(context.Background(), inbound)

	if err := CopyFallbackResponse(ctx, client, testEOFConn{}, writer, nil); err != nil {
		t.Fatalf("CopyFallbackResponse() error = %v", err)
	}
	if got := written.String(); got != "fallback-response" {
		t.Fatalf("response payload = %q, want %q", got, "fallback-response")
	}
}

func TestFallbackRawCopyContextAnnotatesRuntimeRecoveryMeta(t *testing.T) {
	oldEligible := fallbackRawHandoffEligibleFn
	t.Cleanup(func() {
		fallbackRawHandoffEligibleFn = oldEligible
	})

	fallbackRawHandoffEligibleFn = func(net.Conn) bool { return true }

	inbound := &session.Inbound{Tag: "reality-vision-main"}
	ctx := session.ContextWithInbound(context.Background(), inbound)
	copyCtx, ok := fallbackRawCopyContext(ctx, &xtls.Conn{}, testEOFConn{})
	if !ok {
		t.Fatal("fallbackRawCopyContext() rawEligible=false, want true")
	}
	meta, ok := fallbackRuntimeRecoveryMetaFromContext(copyCtx)
	if !ok {
		t.Fatal("fallback runtime recovery meta missing from context")
	}
	if meta.Tag != inbound.Tag {
		t.Fatalf("meta.Tag=%q, want %q", meta.Tag, inbound.Tag)
	}
	if meta.FrontendTransport != "go_tls" {
		t.Fatalf("meta.FrontendTransport=%q, want %q", meta.FrontendTransport, "go_tls")
	}
	if meta.FrontendTLSOffloadPath != pipeline.TLSOffloadUserspace {
		t.Fatalf("meta.FrontendTLSOffloadPath=%q, want %q", meta.FrontendTLSOffloadPath, pipeline.TLSOffloadUserspace)
	}
}

func TestMaybeReportFallbackNativeRuntimeRecoveryOnSplice(t *testing.T) {
	oldReport := reportNativeRuntimeRecoveryByTagFn
	t.Cleanup(func() {
		reportNativeRuntimeRecoveryByTagFn = oldReport
	})

	reportedTag := ""
	reportNativeRuntimeRecoveryByTagFn = func(tag string) bool {
		reportedTag = tag
		return true
	}

	ctx := context.WithValue(context.Background(), fallbackRuntimeRecoveryContextKey{}, fallbackRuntimeRecoveryMeta{
		Tag:                    "reality-vision-main",
		FrontendTransport:      "deferred_rust",
		FrontendTLSOffloadPath: pipeline.TLSOffloadKTLS,
	})
	decision := &pipeline.DecisionSnapshot{
		Path:        pipeline.PathSplice,
		Reason:      pipeline.ReasonForwardSuccess,
		SpliceBytes: 512,
	}
	if !maybeReportFallbackNativeRuntimeRecovery(ctx, decision) {
		t.Fatal("maybeReportFallbackNativeRuntimeRecovery()=false, want true")
	}
	if reportedTag != "reality-vision-main" {
		t.Fatalf("reported tag=%q, want %q", reportedTag, "reality-vision-main")
	}
}

func TestMaybeReportFallbackNativeRuntimeRecoveryRejectsUserspace(t *testing.T) {
	ctx := context.WithValue(context.Background(), fallbackRuntimeRecoveryContextKey{}, fallbackRuntimeRecoveryMeta{
		Tag:                    "reality-vision-main",
		FrontendTransport:      "deferred_rust",
		FrontendTLSOffloadPath: pipeline.TLSOffloadKTLS,
		State:                  &fallbackRuntimeRecoveryState{},
	})
	decision := &pipeline.DecisionSnapshot{
		Path:          pipeline.PathUserspace,
		Reason:        pipeline.ReasonUserspaceIdleTimeout,
		UserspaceExit: pipeline.UserspaceExitTimeout,
	}
	if maybeReportFallbackNativeRuntimeRecovery(ctx, decision) {
		t.Fatal("maybeReportFallbackNativeRuntimeRecovery()=true, want false")
	}
}

func TestWithFallbackRuntimeRecoveryContextPreservesSharedState(t *testing.T) {
	oldEligible := fallbackRawHandoffEligibleFn
	t.Cleanup(func() {
		fallbackRawHandoffEligibleFn = oldEligible
	})

	fallbackRawHandoffEligibleFn = func(net.Conn) bool { return true }

	inbound := &session.Inbound{Tag: "reality-vision-main"}
	ctx := session.ContextWithInbound(context.Background(), inbound)
	ctx = WithFallbackRuntimeRecoveryContext(ctx, &xtls.DeferredRustConn{})

	meta, ok := fallbackRuntimeRecoveryMetaFromContext(ctx)
	if !ok {
		t.Fatal("fallback runtime recovery meta missing after parent annotation")
	}
	if meta.State == nil {
		t.Fatal("fallback runtime recovery shared state missing")
	}

	copyCtx, ok := fallbackRawCopyContext(ctx, &xtls.DeferredRustConn{}, testEOFConn{})
	if !ok {
		t.Fatal("fallbackRawCopyContext() rawEligible=false, want true")
	}
	copyMeta, ok := fallbackRuntimeRecoveryMetaFromContext(copyCtx)
	if !ok {
		t.Fatal("fallback runtime recovery meta missing on copy context")
	}
	if copyMeta.State != meta.State {
		t.Fatal("fallback runtime recovery state should be shared across request/response legs")
	}
}

func TestCopyFallbackRawHandoffReportsRuntimeRecoveryOnceAcrossDirections(t *testing.T) {
	oldCopyRaw := copyRawConnIfExistFn
	oldEligible := fallbackRawHandoffEligibleFn
	oldReport := reportNativeRuntimeRecoveryByTagFn
	t.Cleanup(func() {
		copyRawConnIfExistFn = oldCopyRaw
		fallbackRawHandoffEligibleFn = oldEligible
		reportNativeRuntimeRecoveryByTagFn = oldReport
	})

	fallbackRawHandoffEligibleFn = func(net.Conn) bool { return true }
	copyRawConnIfExistFn = func(context.Context, net.Conn, net.Conn, buf.Writer, *signal.ActivityTimer, *signal.ActivityTimer) error {
		return nil
	}

	var reported []string
	reportNativeRuntimeRecoveryByTagFn = func(tag string) bool {
		reported = append(reported, tag)
		return true
	}

	inbound := &session.Inbound{Tag: "reality-vision-main"}
	ctx := session.ContextWithInbound(context.Background(), inbound)
	ctx = WithFallbackRuntimeRecoveryContext(ctx, &xtls.DeferredRustConn{})

	reader := &buf.BufferedReader{
		Reader: &buf.SingleReader{Reader: strings.NewReader("tail")},
		Buffer: buf.MultiBuffer{buf.FromBytes([]byte("HEAD"))},
	}
	if err := CopyFallbackRequest(ctx, &xtls.DeferredRustConn{}, testEOFConn{}, reader, buf.Discard, nil); err != nil {
		t.Fatalf("CopyFallbackRequest() error = %v", err)
	}
	if err := CopyFallbackResponse(ctx, testEOFConn{}, &xtls.DeferredRustConn{}, buf.Discard, nil); err != nil {
		t.Fatalf("CopyFallbackResponse() error = %v", err)
	}
	if len(reported) != 1 {
		t.Fatalf("runtime recovery reports = %d, want 1", len(reported))
	}
	if reported[0] != inbound.Tag {
		t.Fatalf("reported tag=%q, want %q", reported[0], inbound.Tag)
	}
}
