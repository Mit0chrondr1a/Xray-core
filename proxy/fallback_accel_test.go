package proxy

import (
	"bytes"
	"context"
	"net"
	"strings"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
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
