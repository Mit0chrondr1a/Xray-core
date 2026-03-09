package outbound

import (
	"bytes"
	gonet "net"
	"reflect"
	"testing"
	"unsafe"

	"github.com/xtls/xray-core/common/native"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/vless/encryption"
	"github.com/xtls/xray-core/transport/internet/tls"
)

func TestBuildVisionTransitionSource(t *testing.T) {
	t.Run("common conn supported path drains buffered state", func(t *testing.T) {
		t.Setenv("XRAY_DEBUG_VISION_TRANSITION_TRACE", "1")
		client, server := gonet.Pipe()
		defer client.Close()
		defer server.Close()

		commonConn := encryption.NewCommonConn(client, false)
		setCommonConnBufferedState(t, commonConn, []byte("plain"), []byte("raw"))
		proxy.ObserveVisionTransitionSource(commonConn, proxy.VisionTransitionKindCommonConn, proxy.VisionIngressOriginGoReality)
		proxy.ObserveVisionTransitionScope(commonConn, "go-scope|reality|tcp")

		source, err := proxy.BuildVisionTransitionSource(commonConn, commonConn)
		if err != nil {
			t.Fatalf("BuildVisionTransitionSource() error = %v", err)
		}
		if source == nil {
			t.Fatal("expected transition source for CommonConn")
		}
		snap := source.Snapshot()
		if snap.Kind != proxy.VisionTransitionKindCommonConn {
			t.Fatalf("transition kind = %q, want %q", snap.Kind, proxy.VisionTransitionKindCommonConn)
		}
		if snap.IngressOrigin != proxy.VisionIngressOriginGoReality {
			t.Fatalf("ingress origin = %q, want %q", snap.IngressOrigin, proxy.VisionIngressOriginGoReality)
		}
		if snap.ScopeKey != "go-scope|reality|tcp" {
			t.Fatalf("scope key = %q, want %q", snap.ScopeKey, "go-scope|reality|tcp")
		}
		if !snap.HasBufferedState || snap.BufferedPlaintext != len("plain") || snap.BufferedRawAhead != len("raw") {
			t.Fatalf("unexpected snapshot before drain: %+v", snap)
		}

		plain, rawAhead := source.DrainBufferedState()
		if got := string(plain); got != "plain" {
			t.Fatalf("plaintext = %q, want %q", got, "plain")
		}
		if got := string(rawAhead); got != "raw" {
			t.Fatalf("rawAhead = %q, want %q", got, "raw")
		}
	})

	t.Run("public common conn wins over stale inner conn", func(t *testing.T) {
		t.Setenv("XRAY_DEBUG_VISION_TRANSITION_TRACE", "1")
		client, server := gonet.Pipe()
		defer client.Close()
		defer server.Close()

		commonConn := encryption.NewCommonConn(client, false)
		proxy.ObserveVisionTransitionSource(client, proxy.VisionTransitionKindCommonConn, proxy.VisionIngressOriginGoRealityFallback)

		source, err := proxy.BuildVisionTransitionSource(commonConn, client)
		if err != nil {
			t.Fatalf("BuildVisionTransitionSource() error = %v", err)
		}
		if source == nil {
			t.Fatal("expected transition source for outer CommonConn")
		}
		if got := source.Snapshot().Kind; got != proxy.VisionTransitionKindCommonConn {
			t.Fatalf("transition kind = %q, want %q", got, proxy.VisionTransitionKindCommonConn)
		}
		if got := source.Snapshot().IngressOrigin; got != proxy.VisionIngressOriginGoRealityFallback {
			t.Fatalf("ingress origin = %q, want %q", got, proxy.VisionIngressOriginGoRealityFallback)
		}
		if source.Conn() != commonConn {
			t.Fatal("expected transition source to keep outer CommonConn as public conn")
		}
	})

	t.Run("deferred rust conn snapshot is explicit", func(t *testing.T) {
		t.Setenv("XRAY_DEBUG_VISION_TRANSITION_TRACE", "1")
		deferred := &tls.DeferredRustConn{}
		proxy.ObserveVisionTransitionSource(deferred, proxy.VisionTransitionKindDeferredRust, proxy.VisionIngressOriginNativeRealityDeferred)
		proxy.ObserveVisionTransitionScope(deferred, "native-scope|reality|tcp")
		proxy.ObserveVisionTransitionEvent(deferred, proxy.VisionTransitionKindDeferredRust, proxy.VisionIngressOriginNativeRealityDeferred, "uplink", proxy.VisionTransitionEventCommandObserved, 2)
		proxy.ObserveVisionTransportLifecycle(deferred, proxy.VisionTransitionKindDeferredRust, proxy.VisionIngressOriginNativeRealityDeferred, tls.DeferredRustLifecycleDeferredActive)
		proxy.ObserveVisionTransportLifecycle(deferred, proxy.VisionTransitionKindDeferredRust, proxy.VisionIngressOriginNativeRealityDeferred, tls.DeferredRustLifecycleDetachCompleted)
		proxy.ObserveVisionTransportLifecycle(deferred, proxy.VisionTransitionKindDeferredRust, proxy.VisionIngressOriginNativeRealityDeferred, tls.DeferredRustLifecycleKTLSEnabled)
		proxy.ObserveVisionTransportProgress(deferred, proxy.VisionTransitionKindDeferredRust, proxy.VisionIngressOriginNativeRealityDeferred, tls.DeferredRustProgressEvent{Direction: tls.DeferredRustProgressWrite, Bytes: 19})
		proxy.ObserveVisionTransportProgress(deferred, proxy.VisionTransitionKindDeferredRust, proxy.VisionIngressOriginNativeRealityDeferred, tls.DeferredRustProgressEvent{Direction: tls.DeferredRustProgressRead, Bytes: 7})
		proxy.ObserveVisionTransportDrain(deferred, proxy.VisionTransitionKindDeferredRust, proxy.VisionIngressOriginNativeRealityDeferred, proxy.VisionDrainModeDeferred, 12, 5)
		source, err := proxy.BuildVisionTransitionSource(nil, deferred)
		if err != nil {
			t.Fatalf("BuildVisionTransitionSource() error = %v", err)
		}
		if source == nil {
			t.Fatal("expected transition source for DeferredRustConn")
		}
		snap := source.Snapshot()
		if snap.Kind != proxy.VisionTransitionKindDeferredRust {
			t.Fatalf("transition kind = %q, want %q", snap.Kind, proxy.VisionTransitionKindDeferredRust)
		}
		if snap.IngressOrigin != proxy.VisionIngressOriginNativeRealityDeferred {
			t.Fatalf("ingress origin = %q, want %q", snap.IngressOrigin, proxy.VisionIngressOriginNativeRealityDeferred)
		}
		if snap.ScopeKey != "native-scope|reality|tcp" {
			t.Fatalf("scope key = %q, want %q", snap.ScopeKey, "native-scope|reality|tcp")
		}
		if !snap.UsesDeferredRust {
			t.Fatalf("expected deferred-rust snapshot, got %+v", snap)
		}
		if snap.HasBufferedState {
			t.Fatalf("deferred-rust snapshot should not report buffered state, got %+v", snap)
		}
		if snap.UplinkSemantic != proxy.VisionSemanticExplicitDirect {
			t.Fatalf("uplink semantic = %q, want %q", snap.UplinkSemantic, proxy.VisionSemanticExplicitDirect)
		}
		if snap.NativeProvisionalSemantic != proxy.VisionNativeProvisionalSemanticNone {
			t.Fatalf("native provisional semantic = %q, want %q", snap.NativeProvisionalSemantic, proxy.VisionNativeProvisionalSemanticNone)
		}
		if snap.TransportDrainMode != proxy.VisionDrainModeDeferred || snap.TransportDrainCount != 1 || snap.TransportDrainPlaintext != 12 || snap.TransportDrainRawAhead != 5 {
			t.Fatalf("unexpected transport drain snapshot: %+v", snap)
		}
		if snap.DrainRelation != proxy.VisionDrainRelationTransportOnly {
			t.Fatalf("drain relation = %q, want %q", snap.DrainRelation, proxy.VisionDrainRelationTransportOnly)
		}
		if snap.BridgeAssessment != proxy.VisionBridgeAssessmentNativeDivergent {
			t.Fatalf("bridge assessment = %q, want %q", snap.BridgeAssessment, proxy.VisionBridgeAssessmentNativeDivergent)
		}
		if snap.TransportReadOps != 1 || snap.TransportReadBytes != 7 {
			t.Fatalf("unexpected transport read snapshot: %+v", snap)
		}
		if snap.TransportWriteOps != 1 || snap.TransportWriteBytes != 19 {
			t.Fatalf("unexpected transport write snapshot: %+v", snap)
		}
		if snap.TransportProgress != proxy.VisionTransportProgressBidirectional {
			t.Fatalf("transport progress = %q, want %q", snap.TransportProgress, proxy.VisionTransportProgressBidirectional)
		}
		if snap.TransportLifecycleState != proxy.VisionTransportLifecycleKTLSEnabled {
			t.Fatalf("transport lifecycle state = %q, want %q", snap.TransportLifecycleState, proxy.VisionTransportLifecycleKTLSEnabled)
		}
		if snap.TransportDetachStatus != proxy.VisionTransportDetachStatusCompleted {
			t.Fatalf("transport detach status = %q, want %q", snap.TransportDetachStatus, proxy.VisionTransportDetachStatusCompleted)
		}
		if snap.TransportKTLSPromotion != proxy.VisionTransportKTLSPromotionEnabled {
			t.Fatalf("transport ktls promotion = %q, want %q", snap.TransportKTLSPromotion, proxy.VisionTransportKTLSPromotionEnabled)
		}
	})

	t.Run("deferred rust pending snapshot exposes provisional semantic", func(t *testing.T) {
		deferred := &tls.DeferredRustConn{}
		proxy.ObserveVisionTransitionSource(deferred, proxy.VisionTransitionKindDeferredRust, proxy.VisionIngressOriginNativeRealityDeferred)
		proxy.ObserveVisionTransitionScope(deferred, "native-pending-scope|reality|tcp")
		proxy.ObserveVisionTransportLifecycle(deferred, proxy.VisionTransitionKindDeferredRust, proxy.VisionIngressOriginNativeRealityDeferred, tls.DeferredRustLifecycleDeferredActive)
		proxy.ObserveVisionTransitionEvent(deferred, proxy.VisionTransitionKindDeferredRust, proxy.VisionIngressOriginNativeRealityDeferred, "uplink", proxy.VisionTransitionEventCommandObserved, 0)
		proxy.ObserveVisionTransitionEvent(deferred, proxy.VisionTransitionKindDeferredRust, proxy.VisionIngressOriginNativeRealityDeferred, "uplink", proxy.VisionTransitionEventCommandObserved, 0)
		proxy.ObserveVisionTransportProgress(deferred, proxy.VisionTransitionKindDeferredRust, proxy.VisionIngressOriginNativeRealityDeferred, tls.DeferredRustProgressEvent{Direction: tls.DeferredRustProgressWrite, Bytes: 23})
		proxy.ObserveVisionTransportProgress(deferred, proxy.VisionTransitionKindDeferredRust, proxy.VisionIngressOriginNativeRealityDeferred, tls.DeferredRustProgressEvent{Direction: tls.DeferredRustProgressRead, Bytes: 11})
		proxy.ObserveVisionNativeExplicitProvisionalSemantic(deferred, proxy.VisionTransitionKindDeferredRust, proxy.VisionIngressOriginNativeRealityDeferred, proxy.VisionNativeProvisionalSemanticCommand0Bidirectional)
		proxy.ObserveVisionNativeExplicitProvisionalOutcome(deferred, proxy.VisionTransitionKindDeferredRust, proxy.VisionIngressOriginNativeRealityDeferred, proxy.VisionNativeProvisionalOutcomeActive)

		source, err := proxy.BuildVisionTransitionSource(nil, deferred)
		if err != nil {
			t.Fatalf("BuildVisionTransitionSource() error = %v", err)
		}
		if source == nil {
			t.Fatal("expected transition source for DeferredRustConn")
		}
		snap := source.Snapshot()
		if snap.NativeProvisionalSemantic != proxy.VisionNativeProvisionalSemanticCommand0Bidirectional {
			t.Fatalf("native provisional semantic = %q, want %q", snap.NativeProvisionalSemantic, proxy.VisionNativeProvisionalSemanticCommand0Bidirectional)
		}
		if snap.NativeProvisionalSource != proxy.VisionNativeProvisionalSemanticSourceExplicitProducer {
			t.Fatalf("native provisional semantic source = %q, want %q", snap.NativeProvisionalSource, proxy.VisionNativeProvisionalSemanticSourceExplicitProducer)
		}
		if snap.NativeProvisionalObserved != proxy.VisionNativeProvisionalSemanticCommand0Bidirectional {
			t.Fatalf("native provisional observed = %q, want %q", snap.NativeProvisionalObserved, proxy.VisionNativeProvisionalSemanticCommand0Bidirectional)
		}
		if snap.NativeProvisionalObservedSource != proxy.VisionNativeProvisionalSemanticSourceExplicitProducer {
			t.Fatalf("native provisional observed source = %q, want %q", snap.NativeProvisionalObservedSource, proxy.VisionNativeProvisionalSemanticSourceExplicitProducer)
		}
		if snap.NativeProvisionalOutcome != proxy.VisionNativeProvisionalOutcomeActive {
			t.Fatalf("native provisional outcome = %q, want %q", snap.NativeProvisionalOutcome, proxy.VisionNativeProvisionalOutcomeActive)
		}
		if snap.NativeProvisionalOutcomeSource != proxy.VisionNativeProvisionalOutcomeSourceExplicitProducer {
			t.Fatalf("native provisional outcome source = %q, want %q", snap.NativeProvisionalOutcomeSource, proxy.VisionNativeProvisionalOutcomeSourceExplicitProducer)
		}
		if snap.PendingGap != proxy.VisionPendingGapCommand0BidirectionalNoDet {
			t.Fatalf("pending gap = %q, want %q", snap.PendingGap, proxy.VisionPendingGapCommand0BidirectionalNoDet)
		}
	})

	t.Run("plain net conn rejected", func(t *testing.T) {
		client, server := gonet.Pipe()
		defer client.Close()
		defer server.Close()

		source, err := proxy.BuildVisionTransitionSource(client, client)
		if err == nil {
			t.Fatal("expected plain net.Conn to be rejected")
		}
		if source != nil {
			t.Fatal("expected nil transition source for unsupported conn")
		}
	})

	t.Run("rust conn without full ktls rejected", func(t *testing.T) {
		source, err := proxy.BuildVisionTransitionSource(nil, &tls.RustConn{})
		if err == nil {
			t.Fatal("expected error for RustConn without full kTLS")
		}
		if source != nil {
			t.Fatal("expected nil transition source when RustConn is rejected")
		}
	})

	t.Run("rust conn with full ktls rejected", func(t *testing.T) {
		client, server := gonet.Pipe()
		defer server.Close()

		rc, err := tls.NewRustConnChecked(client, &native.TlsResult{
			KtlsTx:  true,
			KtlsRx:  true,
			Version: 0x0304,
		}, "example.com")
		if err != nil {
			t.Fatalf("failed to create test RustConn: %v", err)
		}
		defer rc.Close()

		source, err := proxy.BuildVisionTransitionSource(client, rc)
		if err == nil {
			t.Fatal("expected Vision to reject RustConn with active kTLS")
		}
		if source != nil {
			t.Fatal("expected nil transition source when Vision rejects RustConn")
		}
	})
}

func setCommonConnBufferedState(t *testing.T, conn *encryption.CommonConn, plain []byte, raw []byte) {
	t.Helper()

	connValue := reflect.ValueOf(conn).Elem()

	inputField := connValue.FieldByName("input")
	inputReader := bytes.NewReader(plain)
	reflect.NewAt(inputField.Type(), unsafe.Pointer(inputField.UnsafeAddr())).Elem().Set(reflect.ValueOf(*inputReader))

	rawField := connValue.FieldByName("rawInput")
	var rawBuffer bytes.Buffer
	rawBuffer.Write(raw)
	reflect.NewAt(rawField.Type(), unsafe.Pointer(rawField.UnsafeAddr())).Elem().Set(reflect.ValueOf(rawBuffer))
}
