package proxy

import (
	"bytes"
	"context"
	goerrors "errors"
	"io"
	gonet "net"
	"reflect"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/pipeline"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/proxy/vless/encryption"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

type visionDeferredWrapConn struct {
	gonet.Conn
	inner gonet.Conn
}

func (c *visionDeferredWrapConn) NetConn() gonet.Conn {
	return c.inner
}

// --- NewTrafficState ---

func TestNewTrafficState(t *testing.T) {
	uuid := []byte("0123456789abcdef")
	ts := NewTrafficState(uuid)

	if ts == nil {
		t.Fatal("NewTrafficState returned nil")
	}
	if string(ts.UserUUID) != string(uuid) {
		t.Fatalf("UserUUID mismatch: got %v", ts.UserUUID)
	}
	if ts.NumberOfPacketToFilter != visionPacketsToFilterDefault {
		t.Fatalf("NumberOfPacketToFilter=%d, want %d", ts.NumberOfPacketToFilter, visionPacketsToFilterDefault)
	}
	if ts.EnableXtls {
		t.Fatal("EnableXtls should be false initially")
	}
	if ts.IsTLS12orAbove {
		t.Fatal("IsTLS12orAbove should be false initially")
	}
	if ts.IsTLS {
		t.Fatal("IsTLS should be false initially")
	}
	if ts.Cipher != 0 {
		t.Fatalf("Cipher=%d, want 0", ts.Cipher)
	}
	if ts.RemainingServerHello != -1 {
		t.Fatalf("RemainingServerHello=%d, want -1", ts.RemainingServerHello)
	}
}

func TestNewTrafficStateInboundDefaults(t *testing.T) {
	ts := NewTrafficState(nil)
	in := ts.Inbound

	if !in.WithinPaddingBuffers {
		t.Fatal("Inbound.WithinPaddingBuffers should be true initially")
	}
	if in.UplinkReaderDirectCopy {
		t.Fatal("Inbound.UplinkReaderDirectCopy should be false initially")
	}
	if in.RemainingCommand != -1 {
		t.Fatalf("Inbound.RemainingCommand=%d, want -1", in.RemainingCommand)
	}
	if in.RemainingContent != -1 {
		t.Fatalf("Inbound.RemainingContent=%d, want -1", in.RemainingContent)
	}
	if in.RemainingPadding != -1 {
		t.Fatalf("Inbound.RemainingPadding=%d, want -1", in.RemainingPadding)
	}
	if in.CurrentCommand != 0 {
		t.Fatalf("Inbound.CurrentCommand=%d, want 0", in.CurrentCommand)
	}
	if !in.IsPadding {
		t.Fatal("Inbound.IsPadding should be true initially")
	}
	if in.DownlinkWriterDirectCopy {
		t.Fatal("Inbound.DownlinkWriterDirectCopy should be false initially")
	}
}

func TestNewTrafficStateOutboundDefaults(t *testing.T) {
	ts := NewTrafficState(nil)
	out := ts.Outbound

	if !out.WithinPaddingBuffers {
		t.Fatal("Outbound.WithinPaddingBuffers should be true initially")
	}
	if out.DownlinkReaderDirectCopy {
		t.Fatal("Outbound.DownlinkReaderDirectCopy should be false initially")
	}
	if out.RemainingCommand != -1 {
		t.Fatalf("Outbound.RemainingCommand=%d, want -1", out.RemainingCommand)
	}
	if out.RemainingContent != -1 {
		t.Fatalf("Outbound.RemainingContent=%d, want -1", out.RemainingContent)
	}
	if out.RemainingPadding != -1 {
		t.Fatalf("Outbound.RemainingPadding=%d, want -1", out.RemainingPadding)
	}
	if out.CurrentCommand != 0 {
		t.Fatalf("Outbound.CurrentCommand=%d, want 0", out.CurrentCommand)
	}
	if !out.IsPadding {
		t.Fatal("Outbound.IsPadding should be true initially")
	}
	if out.UplinkWriterDirectCopy {
		t.Fatal("Outbound.UplinkWriterDirectCopy should be false initially")
	}
}

// --- IsCompleteRecord ---

func TestIsCompleteRecordValid(t *testing.T) {
	// Build a valid TLS application data record: 0x17 0x03 0x03 <len_high> <len_low> <payload>
	payload := make([]byte, 100)
	record := []byte{0x17, 0x03, 0x03, 0x00, byte(len(payload))}
	record = append(record, payload...)

	b := buf.New()
	b.Write(record)
	mb := buf.MultiBuffer{b}

	if !IsCompleteRecord(mb) {
		t.Fatal("expected valid TLS record to be complete")
	}
}

func TestIsCompleteRecordMultipleRecords(t *testing.T) {
	// Two consecutive valid records
	payload1 := make([]byte, 50)
	payload2 := make([]byte, 30)
	record := []byte{0x17, 0x03, 0x03, 0x00, byte(len(payload1))}
	record = append(record, payload1...)
	record = append(record, 0x17, 0x03, 0x03, 0x00, byte(len(payload2)))
	record = append(record, payload2...)

	b := buf.New()
	b.Write(record)
	mb := buf.MultiBuffer{b}

	if !IsCompleteRecord(mb) {
		t.Fatal("expected multiple valid TLS records to be complete")
	}
}

func TestIsCompleteRecordTruncated(t *testing.T) {
	// Record header says 100 bytes but only 50 provided
	payload := make([]byte, 50)
	record := []byte{0x17, 0x03, 0x03, 0x00, 100}
	record = append(record, payload...)

	b := buf.New()
	b.Write(record)
	mb := buf.MultiBuffer{b}

	if IsCompleteRecord(mb) {
		t.Fatal("expected truncated record to be incomplete")
	}
}

func TestIsCompleteRecordWrongHeader(t *testing.T) {
	// Wrong first byte
	record := []byte{0x16, 0x03, 0x03, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05}

	b := buf.New()
	b.Write(record)
	mb := buf.MultiBuffer{b}

	if IsCompleteRecord(mb) {
		t.Fatal("expected non-0x17 record to be rejected")
	}
}

func TestIsCompleteRecordEmpty(t *testing.T) {
	b := buf.New()
	mb := buf.MultiBuffer{b}

	// Empty buffer with 5-byte header expectation should return true (headerLen==5, recordLen==0)
	if !IsCompleteRecord(mb) {
		t.Fatal("expected empty buffer to be 'complete' (0 records)")
	}
}

func TestIsCompleteRecordHeaderOnly(t *testing.T) {
	// Header says 0 bytes of payload. After parsing the header,
	// headerLen=0, recordLen=0, which falls into the else branch
	// returning false. This is the actual behavior.
	record := []byte{0x17, 0x03, 0x03, 0x00, 0x00}
	b := buf.New()
	b.Write(record)
	mb := buf.MultiBuffer{b}

	if IsCompleteRecord(mb) {
		t.Fatal("expected zero-length record to be rejected (headerLen=0, recordLen=0 hits else)")
	}
}

// --- ReshapeMultiBuffer ---

func TestReshapeMultiBufferNoReshapeNeeded(t *testing.T) {
	b := buf.New()
	b.Write(make([]byte, 100))
	mb := buf.MultiBuffer{b}

	result := ReshapeMultiBuffer(context.Background(), mb)
	if len(result) != 1 {
		t.Fatalf("expected 1 buffer after reshape, got %d", len(result))
	}
}

func TestReshapeMultiBufferSplitsLarge(t *testing.T) {
	b := buf.New()
	data := make([]byte, buf.Size-10) // Close to Size, triggers reshape
	b.Write(data)
	mb := buf.MultiBuffer{b}

	result := ReshapeMultiBuffer(context.Background(), mb)
	if len(result) < 2 {
		t.Fatalf("expected at least 2 buffers after reshape, got %d", len(result))
	}

	// Total length should be preserved
	var totalLen int32
	for _, b := range result {
		totalLen += b.Len()
	}
	if totalLen != int32(len(data)) {
		t.Fatalf("total length after reshape: %d, want %d", totalLen, len(data))
	}
}

// --- XtlsPadding / XtlsUnpadding round trip ---

func TestXtlsPaddingUnpaddingRoundTrip(t *testing.T) {
	uuid := []byte("0123456789ABCDEF") // exactly 16 bytes
	uuidCopy := make([]byte, 16)
	copy(uuidCopy, uuid)

	plaintext := []byte("hello world, this is a test payload for vision padding")
	b := buf.New()
	b.Write(plaintext)

	testseed := []uint32{900, 500, 900, 256}
	userUUID := make([]byte, len(uuid))
	copy(userUUID, uuid)

	padded := XtlsPadding(b, CommandPaddingEnd, &userUUID, false, context.Background(), testseed)
	if padded == nil {
		t.Fatal("XtlsPadding returned nil")
	}
	if padded.Len() < int32(len(plaintext)) {
		t.Fatalf("padded length %d < plaintext length %d", padded.Len(), len(plaintext))
	}

	// Unpad
	ts := NewTrafficState(uuidCopy)
	result := XtlsUnpadding(padded, ts, true, context.Background())
	if result == nil {
		t.Fatal("XtlsUnpadding returned nil")
	}
	got := string(result.Bytes())
	if got != string(plaintext) {
		t.Fatalf("unpadded data mismatch:\n  got:  %q\n  want: %q", got, string(plaintext))
	}
	result.Release()
}

func TestXtlsPaddingNilBuffer(t *testing.T) {
	uuid := []byte("0123456789ABCDEF")
	testseed := []uint32{900, 500, 900, 256}
	padded := XtlsPadding(nil, CommandPaddingContinue, &uuid, true, context.Background(), testseed)
	if padded == nil {
		t.Fatal("XtlsPadding(nil) returned nil")
	}
	// Should still produce a valid buffer with just UUID + header + padding
	if padded.Len() < 5 {
		t.Fatalf("padded nil buffer too short: %d", padded.Len())
	}
	padded.Release()
}

func TestXtlsPaddingClearsUserUUID(t *testing.T) {
	uuid := []byte("0123456789ABCDEF")
	testseed := []uint32{900, 500, 900, 256}
	padded := XtlsPadding(buf.New(), CommandPaddingEnd, &uuid, false, context.Background(), testseed)
	padded.Release()

	if uuid != nil {
		t.Fatal("XtlsPadding should set *userUUID to nil after first use")
	}
}

func TestXtlsUnpaddingNoUUIDMatch(t *testing.T) {
	// If the buffer doesn't start with the UUID, XtlsUnpadding returns the buffer as-is.
	ts := NewTrafficState([]byte("0123456789ABCDEF"))
	b := buf.New()
	b.Write([]byte("this doesn't match any UUID"))

	result := XtlsUnpadding(b, ts, true, context.Background())
	if result == nil {
		t.Fatal("XtlsUnpadding returned nil for non-matching buffer")
	}
	got := string(result.Bytes())
	if got != "this doesn't match any UUID" {
		t.Fatalf("non-matching buffer should be returned unchanged, got %q", got)
	}
	result.Release()
}

// --- XtlsFilterTls ---

func TestXtlsFilterTlsClientHello(t *testing.T) {
	// Construct a minimal TLS Client Hello header
	header := []byte{
		0x16, 0x03, 0x01, 0x00, 0x05, // TLS record header (handshake, TLS 1.0)
		0x01,             // HandshakeType: ClientHello
		0x00, 0x00, 0x01, // Length
		0x00, // Data
	}
	b := buf.New()
	b.Write(header)
	mb := buf.MultiBuffer{b}

	ts := NewTrafficState(nil)
	XtlsFilterTls(mb, ts, context.Background())

	if !ts.IsTLS {
		t.Fatal("expected IsTLS=true after seeing Client Hello")
	}
	buf.ReleaseMulti(mb)
}

func TestXtlsFilterTlsServerHello(t *testing.T) {
	// Construct a minimal TLS Server Hello header (80+ bytes)
	data := make([]byte, 80)
	// Record header: 0x16 0x03 0x03 <len:2>
	data[0] = 0x16
	data[1] = 0x03
	data[2] = 0x03
	data[3] = 0x00
	data[4] = byte(len(data) - 5)
	// Handshake type: ServerHello
	data[5] = 0x02
	// Session ID length at offset 43 = 0 (no session ID)
	data[43] = 0
	// Cipher suite at offset 44-45
	data[44] = 0x13
	data[45] = 0x01 // TLS_AES_128_GCM_SHA256

	b := buf.New()
	b.Write(data)
	mb := buf.MultiBuffer{b}

	ts := NewTrafficState(nil)
	XtlsFilterTls(mb, ts, context.Background())

	if !ts.IsTLS12orAbove {
		t.Fatal("expected IsTLS12orAbove=true after Server Hello")
	}
	if !ts.IsTLS {
		t.Fatal("expected IsTLS=true after Server Hello")
	}
	if ts.Cipher != 0x1301 {
		t.Fatalf("Cipher=0x%04x, want 0x1301", ts.Cipher)
	}
	buf.ReleaseMulti(mb)
}

func TestXtlsFilterTlsNonTLS(t *testing.T) {
	data := []byte{0x48, 0x54, 0x54, 0x50, 0x2F, 0x31} // "HTTP/1"
	b := buf.New()
	b.Write(data)
	mb := buf.MultiBuffer{b}

	ts := NewTrafficState(nil)
	XtlsFilterTls(mb, ts, context.Background())

	if ts.IsTLS {
		t.Fatal("expected IsTLS=false for non-TLS traffic")
	}
	buf.ReleaseMulti(mb)
}

func TestXtlsFilterTlsNilBuffer(t *testing.T) {
	// Should handle nil buffers in the MultiBuffer without panicking.
	mb := buf.MultiBuffer{nil}
	ts := NewTrafficState(nil)
	XtlsFilterTls(mb, ts, context.Background())
	// No panic = success.
}

// --- Tls13CipherSuiteDic ---

func TestTls13CipherSuiteDic(t *testing.T) {
	expected := map[uint16]string{
		0x1301: "TLS_AES_128_GCM_SHA256",
		0x1302: "TLS_AES_256_GCM_SHA384",
		0x1303: "TLS_CHACHA20_POLY1305_SHA256",
		0x1304: "TLS_AES_128_CCM_SHA256",
		0x1305: "TLS_AES_128_CCM_8_SHA256",
	}
	for k, v := range expected {
		got, ok := Tls13CipherSuiteDic[k]
		if !ok {
			t.Errorf("missing cipher suite 0x%04x", k)
			continue
		}
		if got != v {
			t.Errorf("Tls13CipherSuiteDic[0x%04x] = %q, want %q", k, got, v)
		}
	}
	if len(Tls13CipherSuiteDic) != len(expected) {
		t.Fatalf("Tls13CipherSuiteDic has %d entries, want %d", len(Tls13CipherSuiteDic), len(expected))
	}
}

// --- TLS byte markers ---

func TestTlsByteMarkers(t *testing.T) {
	if len(TlsClientHandShakeStart) != 2 {
		t.Fatalf("TlsClientHandShakeStart len=%d, want 2", len(TlsClientHandShakeStart))
	}
	if TlsClientHandShakeStart[0] != 0x16 || TlsClientHandShakeStart[1] != 0x03 {
		t.Fatalf("TlsClientHandShakeStart = %x, want [16 03]", TlsClientHandShakeStart)
	}

	if len(TlsServerHandShakeStart) != 3 {
		t.Fatalf("TlsServerHandShakeStart len=%d, want 3", len(TlsServerHandShakeStart))
	}

	if len(TlsApplicationDataStart) != 3 {
		t.Fatalf("TlsApplicationDataStart len=%d, want 3", len(TlsApplicationDataStart))
	}
	if TlsApplicationDataStart[0] != 0x17 {
		t.Fatalf("TlsApplicationDataStart[0] = 0x%02x, want 0x17", TlsApplicationDataStart[0])
	}
}

func TestVisionWriterDefersRawSwitchUntilDeferredConnReady(t *testing.T) {
	// Writer must not unwrap to raw while DeferredRustConn is neither detached
	// nor kTLS-active; otherwise rustls-buffered data can be bypassed/lost.
	ts := NewTrafficState(nil)
	ts.Inbound.IsPadding = false
	ts.Inbound.DownlinkWriterDirectCopy = true

	w := NewVisionWriter(
		buf.Discard,
		ts,
		false,
		context.Background(),
		&tls.DeferredRustConn{},
		nil,
		nil,
	)

	if err := w.WriteMultiBuffer(buf.MultiBuffer{}); err != nil {
		t.Fatalf("WriteMultiBuffer() error = %v", err)
	}

	if !ts.Inbound.DownlinkWriterDirectCopy {
		t.Fatal("DownlinkWriterDirectCopy should remain armed until deferred conn is detached or kTLS-active")
	}
}

func TestVisionWriterCanSpliceCopyTransitions(t *testing.T) {
	// With active DeferredRustConn, writer keeps state at 2 until raw switch is safe.
	ts := NewTrafficState(nil)
	ts.Inbound.IsPadding = false
	ts.Inbound.DownlinkWriterDirectCopy = true

	inbound := &session.Inbound{CanSpliceCopy: int32(session.CopyGatePendingDetach)}
	ctx := session.ContextWithInbound(context.Background(), inbound)

	w := NewVisionWriter(
		buf.Discard,
		ts,
		false, // downlink writer
		ctx,
		&tls.DeferredRustConn{}, // not detached
		nil,
		nil,
	)

	if err := w.WriteMultiBuffer(buf.MultiBuffer{}); err != nil {
		t.Fatalf("WriteMultiBuffer() error = %v", err)
	}

	if inbound.GetCanSpliceCopy() != session.CopyGatePendingDetach {
		t.Fatalf("CopyGateState = %v, want %v", inbound.GetCanSpliceCopy(), session.CopyGatePendingDetach)
	}
}

func TestVisionWriterCanSpliceCopyTransitionsNoDeferredConn(t *testing.T) {
	// Without DeferredRustConn, downlink writer can transition 2 -> 1.
	left, right := mustTCPPair(t)
	defer left.Close()
	defer right.Close()

	ts := NewTrafficState(nil)
	ts.Inbound.IsPadding = false
	ts.Inbound.DownlinkWriterDirectCopy = true

	inbound := &session.Inbound{CanSpliceCopy: int32(session.CopyGatePendingDetach)}
	ctx := session.ContextWithInbound(context.Background(), inbound)

	w := NewVisionWriter(
		buf.Discard,
		ts,
		false,
		ctx,
		left,
		nil,
		nil,
	)

	if err := w.WriteMultiBuffer(buf.MultiBuffer{}); err != nil {
		t.Fatalf("WriteMultiBuffer() error = %v", err)
	}

	if inbound.GetCanSpliceCopy() != session.CopyGateEligible {
		t.Fatalf("CopyGateState = %v, want %v", inbound.GetCanSpliceCopy(), session.CopyGateEligible)
	}
}

func TestVisionReaderDirectCopyPromotesInboundSpliceState(t *testing.T) {
	left, right := mustTCPPair(t)
	defer left.Close()
	defer right.Close()

	ts := NewTrafficState(nil)
	ts.Outbound.WithinPaddingBuffers = true
	ts.Outbound.CurrentCommand = 2

	inbound := &session.Inbound{CanSpliceCopy: int32(session.CopyGatePendingDetach), Conn: left}
	ctx := session.ContextWithInbound(context.Background(), inbound)

	b := buf.New()
	b.Write([]byte("abc"))
	reader := &singleReadReader{
		mb: buf.MultiBuffer{b},
	}
	vr := NewVisionReader(reader, ts, false, ctx, left, nil, nil, nil, nil)
	mb, err := vr.ReadMultiBuffer()
	if err != nil {
		t.Fatalf("ReadMultiBuffer() error = %v", err)
	}
	buf.ReleaseMulti(mb)

	if !ts.Outbound.DownlinkReaderDirectCopy {
		t.Fatal("DownlinkReaderDirectCopy should be true after command=2")
	}
	if inbound.GetCanSpliceCopy() != session.CopyGateEligible {
		t.Fatalf("CopyGateState = %v, want %v", inbound.GetCanSpliceCopy(), session.CopyGateEligible)
	}
}

func TestVisionReaderCommandPaddingEndForcesUserspaceGate(t *testing.T) {
	uuid := []byte("0123456789abcdef")
	ts := NewTrafficState(uuid)

	inbound := &session.Inbound{CanSpliceCopy: int32(session.CopyGatePendingDetach)}
	outbound := &session.Outbound{CanSpliceCopy: int32(session.CopyGatePendingDetach)}
	ctx := session.ContextWithInbound(context.Background(), inbound)
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{outbound})

	userUUID := append([]byte(nil), uuid...)
	padded := XtlsPadding(buf.FromBytes([]byte("ok")), CommandPaddingEnd, &userUUID, false, ctx, []uint32{0, 0, 0, 1})
	reader := &singleReadReader{mb: buf.MultiBuffer{padded}}

	vr := NewVisionReader(reader, ts, true, ctx, nil, nil, nil, nil, outbound)
	mb, err := vr.ReadMultiBuffer()
	if err != nil {
		t.Fatalf("ReadMultiBuffer() error = %v", err)
	}
	defer buf.ReleaseMulti(mb)

	if got := mb.Len(); got != 2 {
		t.Fatalf("payload length=%d, want 2", got)
	}
	if inbound.GetCanSpliceCopy() != session.CopyGateForcedUserspace {
		t.Fatalf("inbound copy gate=%v, want %v", inbound.GetCanSpliceCopy(), session.CopyGateForcedUserspace)
	}
	if inbound.CopyGateReason() != session.CopyGateReasonVisionNoDetach {
		t.Fatalf("inbound copy gate reason=%v, want %v", inbound.CopyGateReason(), session.CopyGateReasonVisionNoDetach)
	}
	if outbound.GetCanSpliceCopy() != session.CopyGateForcedUserspace {
		t.Fatalf("outbound copy gate=%v, want %v", outbound.GetCanSpliceCopy(), session.CopyGateForcedUserspace)
	}
	if outbound.CopyGateReason() != session.CopyGateReasonVisionNoDetach {
		t.Fatalf("outbound copy gate reason=%v, want %v", outbound.CopyGateReason(), session.CopyGateReasonVisionNoDetach)
	}
}

func TestVisionReaderCommandPaddingEndOverridesCommandContinueHandoff(t *testing.T) {
	uuid := []byte("0123456789abcdef")
	ts := NewTrafficState(uuid)

	inbound := &session.Inbound{}
	inbound.SetCopyGate(session.CopyGatePendingDetach, session.CopyGateReasonUnspecified)
	outbound := &session.Outbound{}
	outbound.SetCopyGate(session.CopyGatePendingDetach, session.CopyGateReasonUnspecified)
	ctx := session.ContextWithInbound(context.Background(), inbound)
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{outbound})

	userUUID := append([]byte(nil), uuid...)
	padded := XtlsPadding(buf.FromBytes([]byte("ok")), CommandPaddingEnd, &userUUID, false, ctx, []uint32{0, 0, 0, 1})
	reader := &singleReadReader{mb: buf.MultiBuffer{padded}}

	vr := NewVisionReader(reader, ts, true, ctx, nil, nil, nil, nil, outbound)
	mb, err := vr.ReadMultiBuffer()
	if err != nil {
		t.Fatalf("ReadMultiBuffer() error = %v", err)
	}
	defer buf.ReleaseMulti(mb)

	if inbound.GetCanSpliceCopy() != session.CopyGateForcedUserspace {
		t.Fatalf("inbound copy gate=%v, want %v", inbound.GetCanSpliceCopy(), session.CopyGateForcedUserspace)
	}
	if inbound.CopyGateReason() != session.CopyGateReasonVisionNoDetach {
		t.Fatalf("inbound copy gate reason=%v, want %v", inbound.CopyGateReason(), session.CopyGateReasonVisionNoDetach)
	}
	if outbound.GetCanSpliceCopy() != session.CopyGateForcedUserspace {
		t.Fatalf("outbound copy gate=%v, want %v", outbound.GetCanSpliceCopy(), session.CopyGateForcedUserspace)
	}
	if outbound.CopyGateReason() != session.CopyGateReasonVisionNoDetach {
		t.Fatalf("outbound copy gate reason=%v, want %v", outbound.CopyGateReason(), session.CopyGateReasonVisionNoDetach)
	}
}

func TestVisionReaderDetectsRawDNSPayloadBypass(t *testing.T) {
	ts := NewTrafficState([]byte("0123456789abcdef"))
	rawDNS := []byte{
		0x00, 0x2c, // tcp length
		0x12, 0x34, // dns id
		0x01, 0x00, // flags
		0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x03, 'w', 'w', 'w', 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm', 0x00,
		0x00, 0x01, 0x00, 0x01,
	}
	b := buf.FromBytes(rawDNS)
	reader := &singleReadReader{mb: buf.MultiBuffer{b}}

	inbound := &session.Inbound{
		Local: xnet.TCPDestination(xnet.IPAddress([]byte{127, 0, 0, 1}), xnet.Port(2036)),
	}
	outbound := &session.Outbound{
		Target: xnet.TCPDestination(xnet.IPAddress([]byte{1, 1, 1, 1}), xnet.Port(53)),
	}
	ctx := session.ContextWithInbound(context.Background(), inbound)
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{outbound})

	vr := NewVisionReader(reader, ts, true, ctx, nil, nil, nil, nil, outbound)
	mb, err := vr.ReadMultiBuffer()
	if err != nil {
		t.Fatalf("ReadMultiBuffer() error = %v", err)
	}
	defer buf.ReleaseMulti(mb)

	if got := mb.Len(); got != int32(len(rawDNS)) {
		t.Fatalf("raw payload length = %d, want %d", got, len(rawDNS))
	}
	if !ts.VisionPayloadBypassObserved {
		t.Fatal("VisionPayloadBypassObserved should be latched for raw DNS payload")
	}
	if inbound.GetCanSpliceCopy() != session.CopyGateForcedUserspace {
		t.Fatalf("CopyGateState = %v, want %v", inbound.GetCanSpliceCopy(), session.CopyGateForcedUserspace)
	}
}

func TestVisionWriterBypassesPaddingAfterRawDNSObservation(t *testing.T) {
	var out bytes.Buffer
	ts := NewTrafficState([]byte("0123456789abcdef"))
	ts.VisionPayloadBypassObserved = true

	inbound := &session.Inbound{
		Local: xnet.TCPDestination(xnet.IPAddress([]byte{127, 0, 0, 1}), xnet.Port(2036)),
	}
	outbound := &session.Outbound{
		Target: xnet.TCPDestination(xnet.IPAddress([]byte{1, 1, 1, 1}), xnet.Port(53)),
	}
	ctx := session.ContextWithInbound(context.Background(), inbound)
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{outbound})

	w := NewVisionWriter(buf.NewWriter(&out), ts, false, ctx, nil, nil, nil)
	payload := []byte{0x00, 0x10, 0xde, 0xad, 0x81, 0x80}
	if err := w.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(payload)}); err != nil {
		t.Fatalf("WriteMultiBuffer() error = %v", err)
	}

	if got := out.Bytes(); !bytes.Equal(got, payload) {
		t.Fatalf("raw response payload = %x, want %x", got, payload)
	}
}

// --- Constants ---

func TestCommandPaddingConstants(t *testing.T) {
	if CommandPaddingContinue != 0x00 {
		t.Fatalf("CommandPaddingContinue = 0x%02x, want 0x00", CommandPaddingContinue)
	}
	if CommandPaddingEnd != 0x01 {
		t.Fatalf("CommandPaddingEnd = 0x%02x, want 0x01", CommandPaddingEnd)
	}
	if CommandPaddingDirect != 0x02 {
		t.Fatalf("CommandPaddingDirect = 0x%02x, want 0x02", CommandPaddingDirect)
	}
}

func TestHandshakeTypeConstants(t *testing.T) {
	if TlsHandshakeTypeClientHello != 0x01 {
		t.Fatalf("TlsHandshakeTypeClientHello = 0x%02x, want 0x01", TlsHandshakeTypeClientHello)
	}
	if TlsHandshakeTypeServerHello != 0x02 {
		t.Fatalf("TlsHandshakeTypeServerHello = 0x%02x, want 0x02", TlsHandshakeTypeServerHello)
	}
}

// --- IsRAWTransportWithoutSecurity ---
// Note: This is tested through net.TCPConn behavior, which requires actual connections.
// We test the nil case only.

func TestUnwrapRawConnNil(t *testing.T) {
	conn, readCounter, writeCounter, handler := UnwrapRawConn(nil)
	if conn != nil {
		t.Fatal("expected nil conn for nil input")
	}
	if readCounter != nil {
		t.Fatal("expected nil readCounter for nil input")
	}
	if writeCounter != nil {
		t.Fatal("expected nil writeCounter for nil input")
	}
	if handler != nil {
		t.Fatal("expected nil handler for nil input")
	}
}

// --- DetermineSocketCryptoHint ---

func TestDetermineSocketCryptoHintNil(t *testing.T) {
	conn, hint := DetermineSocketCryptoHint(nil)
	if conn != nil {
		t.Fatal("expected nil conn for nil input")
	}
	if hint != 0 { // CryptoNone = 0
		t.Fatalf("expected CryptoNone for nil input, got %d", hint)
	}
}

func TestBuildVisionDecisionInputRefreshesCryptoHint(t *testing.T) {
	left, right := mustTCPPair(t)
	defer left.Close()
	defer right.Close()

	wrappedReader := &encryption.CommonConn{Conn: &tls.DeferredRustConn{}}
	wrappedWriter := &encryption.CommonConn{Conn: right}
	caps := pipeline.CapabilitySummary{SpliceSupported: true}

	first, _, _, _, _ := buildVisionDecisionInput(wrappedReader, wrappedWriter, caps, false)
	if first.ReaderCrypto != "userspace-tls" {
		t.Fatalf("first ReaderCrypto=%q, want userspace-tls", first.ReaderCrypto)
	}

	// Switch the wrapped connection to raw TCP and verify the next decision
	// snapshot reflects the new state.
	wrappedReader.Conn = left
	second, _, _, _, _ := buildVisionDecisionInput(wrappedReader, wrappedWriter, caps, false)
	if second.ReaderCrypto != "none" {
		t.Fatalf("second ReaderCrypto=%q, want none", second.ReaderCrypto)
	}
}

func TestBuildVisionDecisionInputForCopyGatePrefersRawEligibleVisionPath(t *testing.T) {
	left, right := mustTCPPair(t)
	defer left.Close()
	defer right.Close()

	wrappedReader := &tls.DeferredRustConn{}
	caps := pipeline.CapabilitySummary{SpliceSupported: true}

	got, _, _, _, _ := buildVisionDecisionInputForCopyGate(
		wrappedReader,
		right,
		left,
		right,
		caps,
		false,
		session.CopyGateEligible,
	)
	if got.ReaderCrypto != "none" {
		t.Fatalf("ReaderCrypto=%q, want none when Vision direct-copy gate is eligible", got.ReaderCrypto)
	}
	if got.WriterCrypto != "none" {
		t.Fatalf("WriterCrypto=%q, want none when Vision direct-copy gate is eligible", got.WriterCrypto)
	}
	if snap := pipeline.DecideVisionPath(got); snap.Path != pipeline.PathSplice {
		t.Fatalf("DecideVisionPath(...).Path=%q, want %q", snap.Path, pipeline.PathSplice)
	}
}

func TestBuildVisionDecisionInputForCopyGateKeepsWrapperGuardBeforeEligibility(t *testing.T) {
	left, right := mustTCPPair(t)
	defer left.Close()
	defer right.Close()

	wrappedReader := &tls.DeferredRustConn{}
	caps := pipeline.CapabilitySummary{SpliceSupported: true}

	got, _, _, _, _ := buildVisionDecisionInputForCopyGate(
		wrappedReader,
		right,
		left,
		right,
		caps,
		false,
		session.CopyGatePendingDetach,
	)
	if got.ReaderCrypto != "userspace-tls" {
		t.Fatalf("ReaderCrypto=%q, want userspace-tls before Vision direct-copy eligibility", got.ReaderCrypto)
	}
	if snap := pipeline.DecideVisionPath(got); snap.Reason != pipeline.ReasonUserspaceTLSGuard {
		t.Fatalf("DecideVisionPath(...).Reason=%q, want %q", snap.Reason, pipeline.ReasonUserspaceTLSGuard)
	}
}

func TestCopyRawConnIfExistUserspaceActiveTrafficBeyondFiveSeconds(t *testing.T) {
	readerPeer, readerConn := gonet.Pipe()
	defer readerPeer.Close()
	defer readerConn.Close()

	copyCtx, cancelCopy := context.WithCancel(context.Background())
	defer cancelCopy()
	timer := signal.CancelAfterInactivity(copyCtx, cancelCopy, 30*time.Second)
	defer timer.SetTimeout(0)

	inbound := &session.Inbound{
		CanSpliceCopy: int32(session.CopyGateUnset),
		Local:         xnet.TCPDestination(xnet.IPAddress([]byte{127, 0, 0, 1}), xnet.Port(2036)),
	}
	outbound := &session.Outbound{CanSpliceCopy: int32(session.CopyGateUnset)}
	ctx := session.ContextWithInbound(context.Background(), inbound)
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{outbound})

	errCh := make(chan error, 1)
	go func() {
		errCh <- CopyRawConnIfExist(ctx, readerConn, nil, buf.Discard, timer, nil)
	}()

	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.NewTimer(5500 * time.Millisecond)
	defer deadline.Stop()

	for {
		select {
		case <-ticker.C:
			if _, err := readerPeer.Write([]byte("ping")); err != nil {
				t.Fatalf("writer side failed before timeout window: %v", err)
			}
		case <-deadline.C:
			readerPeer.Close()
			err := <-errCh
			if err != nil {
				t.Fatalf("CopyRawConnIfExist() error=%v, want nil after active userspace traffic", err)
			}
			return
		case err := <-errCh:
			if goerrors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("CopyRawConnIfExist() returned hard timeout during active traffic: %v", err)
			}
			t.Fatalf("CopyRawConnIfExist() exited early: %v", err)
		}
	}
}

func TestMarkVisionCommandContinueEvidenceLeavesCopyGateUntouched(t *testing.T) {
	inbound := &session.Inbound{
		CanSpliceCopy: int32(session.CopyGatePendingDetach),
	}
	outbound := &session.Outbound{
		CanSpliceCopy: int32(session.CopyGatePendingDetach),
	}
	ctx := session.ContextWithInbound(context.Background(), inbound)

	if !markVisionCommandContinueEvidence(ctx, nil, outbound) {
		t.Fatal("markVisionCommandContinueEvidence() = false, want true")
	}
	if got := inbound.GetCanSpliceCopy(); got != session.CopyGatePendingDetach {
		t.Fatalf("inbound state=%v, want pending_detach", got)
	}
	if got := outbound.GetCanSpliceCopy(); got != session.CopyGatePendingDetach {
		t.Fatalf("outbound state=%v, want pending_detach", got)
	}
	if got := inbound.CopyGateReason(); got != session.CopyGateReasonUnspecified {
		t.Fatalf("inbound reason=%v, want unspecified", got)
	}
	if got := outbound.CopyGateReason(); got != session.CopyGateReasonUnspecified {
		t.Fatalf("outbound reason=%v, want unspecified", got)
	}
}

func TestObserveVisionUplinkCompleteLeavesNativeDeferredFlowSemanticsUntouched(t *testing.T) {
	inbound := &session.Inbound{Conn: &tls.DeferredRustConn{}}
	inbound.SetCanSpliceCopy(session.CopyGatePendingDetach)
	outbound := &session.Outbound{}
	outbound.SetCanSpliceCopy(session.CopyGatePendingDetach)

	if !ObserveVisionUplinkComplete(context.Background(), inbound, outbound) {
		t.Fatal("ObserveVisionUplinkComplete() = false, want true")
	}
	if got := inbound.GetCanSpliceCopy(); got != session.CopyGatePendingDetach {
		t.Fatalf("inbound state=%v, want pending_detach", got)
	}
	if got := inbound.CopyGateReason(); got != session.CopyGateReasonUnspecified {
		t.Fatalf("inbound reason=%v, want unspecified", got)
	}
	if got := outbound.GetCanSpliceCopy(); got != session.CopyGatePendingDetach {
		t.Fatalf("outbound state=%v, want pending_detach", got)
	}
	if got := outbound.CopyGateReason(); got != session.CopyGateReasonUnspecified {
		t.Fatalf("outbound reason=%v, want unspecified", got)
	}
}

func TestObserveVisionUplinkCompleteRecordsPendingSignal(t *testing.T) {
	writerConn := &tls.DeferredRustConn{}
	inbound := &session.Inbound{Conn: writerConn}
	inbound.SetCanSpliceCopy(session.CopyGatePendingDetach)
	outbound := &session.Outbound{}
	outbound.SetCanSpliceCopy(session.CopyGatePendingDetach)
	visionCh := make(chan session.VisionSignal, 1)
	ctx := session.ContextWithVisionSignal(context.Background(), visionCh)

	if !ObserveVisionUplinkComplete(ctx, inbound, outbound) {
		t.Fatal("ObserveVisionUplinkComplete() = false, want true")
	}
	select {
	case sig := <-visionCh:
		if sig.Command != 0 {
			t.Fatalf("signal command=%d, want 0", sig.Command)
		}
	default:
		t.Fatal("ObserveVisionUplinkComplete() did not record pending signal")
	}
}

func TestObserveVisionUplinkCompleteDoesNotSignalExplicitNativeDeferredFlow(t *testing.T) {
	writerConn := &tls.DeferredRustConn{}
	inbound := &session.Inbound{Conn: writerConn}
	inbound.SetCanSpliceCopy(session.CopyGatePendingDetach)
	outbound := &session.Outbound{}
	outbound.SetCanSpliceCopy(session.CopyGatePendingDetach)
	visionCh := make(chan session.VisionSignal, 1)
	ctx := session.ContextWithInbound(session.ContextWithVisionSignal(context.Background(), visionCh), inbound)
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{outbound})
	markVisionPostDetachObserved(ctx, outbound)

	if !ObserveVisionUplinkComplete(ctx, inbound, outbound) {
		t.Fatal("ObserveVisionUplinkComplete() = false, want true")
	}
	select {
	case sig := <-visionCh:
		t.Fatalf("unexpected signal command=%d for explicit post-detach flow", sig.Command)
	default:
	}
}

func TestObserveVisionUplinkCompleteLeavesNonDeferredFlowUntouched(t *testing.T) {
	readerPeer, readerConn := gonet.Pipe()
	defer readerPeer.Close()
	defer readerConn.Close()

	inbound := &session.Inbound{Conn: readerConn}
	inbound.SetCanSpliceCopy(session.CopyGatePendingDetach)
	outbound := &session.Outbound{}
	outbound.SetCanSpliceCopy(session.CopyGatePendingDetach)
	outbound.Target = xnet.TCPDestination(xnet.IPAddress([]byte{203, 0, 113, 10}), xnet.Port(8443))
	ctx := session.ContextWithInbound(context.Background(), inbound)
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{outbound})

	if !ObserveVisionUplinkComplete(ctx, inbound, outbound) {
		t.Fatal("ObserveVisionUplinkComplete() = false, want true for pending flow")
	}
	if got := inbound.GetCanSpliceCopy(); got != session.CopyGatePendingDetach {
		t.Fatalf("inbound state=%v, want pending_detach for non-deferred flow", got)
	}
	if got := inbound.CopyGateReason(); got != session.CopyGateReasonUnspecified {
		t.Fatalf("inbound reason=%v, want unspecified for non-deferred flow", got)
	}
	if got := outbound.GetCanSpliceCopy(); got != session.CopyGatePendingDetach {
		t.Fatalf("outbound state=%v, want pending_detach for non-deferred flow", got)
	}
	if got := outbound.CopyGateReason(); got != session.CopyGateReasonUnspecified {
		t.Fatalf("outbound reason=%v, want unspecified for non-deferred flow", got)
	}
}

func TestShouldReportNativeDeferredRuntimeRegression(t *testing.T) {
	inbound := &session.Inbound{
		Tag:  "native-vision",
		Conn: &tls.DeferredRustConn{},
	}
	inbound.SetCanSpliceCopy(session.CopyGatePendingDetach)
	outbound := &session.Outbound{}
	outbound.SetCanSpliceCopy(session.CopyGatePendingDetach)
	decision := &pipeline.DecisionSnapshot{
		Path:           pipeline.PathUserspace,
		Reason:         pipeline.ReasonUserspaceIdleTimeout,
		UserspaceBytes: 0,
		UserspaceExit:  pipeline.UserspaceExitTimeout,
	}

	if !shouldReportNativeDeferredRuntimeRegression(inbound, []*session.Outbound{outbound}, copyLoopPhaseAwaitSignal, true, decision) {
		t.Fatal("shouldReportNativeDeferredRuntimeRegression() = false, want true for unresolved native deferred timeout")
	}
	decision.UserspaceBytes = 64
	if !shouldReportNativeDeferredRuntimeRegression(inbound, []*session.Outbound{outbound}, copyLoopPhaseAwaitSignal, true, decision) {
		t.Fatal("shouldReportNativeDeferredRuntimeRegression() = false, want true for unresolved native deferred timeout with userspace bytes")
	}

	markVisionNoDetachObserved(session.ContextWithInbound(context.Background(), inbound), outbound)
	if shouldReportNativeDeferredRuntimeRegression(inbound, []*session.Outbound{outbound}, copyLoopPhaseAwaitSignal, true, decision) {
		t.Fatal("shouldReportNativeDeferredRuntimeRegression() = true, want false once explicit no-detach semantic truth exists")
	}
}

func TestShouldReportNativeDeferredRuntimeRecovery(t *testing.T) {
	inbound := &session.Inbound{
		Tag:  "native-vision",
		Conn: &tls.DeferredRustConn{},
	}
	inbound.SetCanSpliceCopy(session.CopyGatePendingDetach)
	outbound := &session.Outbound{}
	outbound.SetCanSpliceCopy(session.CopyGatePendingDetach)

	promoteVisionSemanticPhase(session.VisionSemanticPhasePostDetach, inbound, []*session.Outbound{outbound})
	spliceDecision := &pipeline.DecisionSnapshot{
		Path:        pipeline.PathSplice,
		Reason:      pipeline.ReasonSplicePrimary,
		SpliceBytes: 1024,
	}
	if !shouldReportNativeDeferredRuntimeRecovery(inbound, []*session.Outbound{outbound}, spliceDecision) {
		t.Fatal("shouldReportNativeDeferredRuntimeRecovery() = false, want true for healthy post-detach splice")
	}

	postDetachRetryDecision := &pipeline.DecisionSnapshot{
		Path:          pipeline.PathSplice,
		Reason:        pipeline.ReasonSplicePrimary,
		UserspaceExit: pipeline.UserspaceExitPostDetachRetrySuccess,
	}
	if !shouldReportNativeDeferredRuntimeRecovery(inbound, []*session.Outbound{outbound}, postDetachRetryDecision) {
		t.Fatal("shouldReportNativeDeferredRuntimeRecovery() = false, want true for healthy post-detach retry success")
	}

	inbound = &session.Inbound{
		Tag:  "native-vision",
		Conn: &tls.DeferredRustConn{},
	}
	inbound.SetCanSpliceCopy(session.CopyGateForcedUserspace)
	outbound = &session.Outbound{}
	outbound.SetCanSpliceCopy(session.CopyGateForcedUserspace)
	markVisionNoDetachObserved(session.ContextWithInbound(context.Background(), inbound), outbound)
	noDetachDecision := &pipeline.DecisionSnapshot{
		Path:           pipeline.PathUserspace,
		Reason:         pipeline.ReasonVisionNoDetachUserspace,
		UserspaceBytes: 64,
		UserspaceExit:  pipeline.UserspaceExitStableUserspaceClose,
	}
	if shouldReportNativeDeferredRuntimeRecovery(inbound, []*session.Outbound{outbound}, noDetachDecision) {
		t.Fatal("shouldReportNativeDeferredRuntimeRecovery() = true, want false for no-detach userspace")
	}
}

func TestMarkVisionNoDetachObservedOverridesCommandContinue(t *testing.T) {
	inbound := &session.Inbound{}
	inbound.SetCopyGate(session.CopyGatePendingDetach, session.CopyGateReasonUnspecified)
	outbound := &session.Outbound{}
	outbound.SetCopyGate(session.CopyGatePendingDetach, session.CopyGateReasonUnspecified)
	ctx := session.ContextWithInbound(context.Background(), inbound)

	markVisionNoDetachObserved(ctx, outbound)

	if got := inbound.CopyGateReason(); got != session.CopyGateReasonVisionNoDetach {
		t.Fatalf("inbound reason=%v, want vision_no_detach", got)
	}
	if got := outbound.CopyGateReason(); got != session.CopyGateReasonVisionNoDetach {
		t.Fatalf("outbound reason=%v, want vision_no_detach", got)
	}
	if got := inbound.GetCanSpliceCopy(); got != session.CopyGateForcedUserspace {
		t.Fatalf("inbound state=%v, want forced userspace", got)
	}
	if got := outbound.GetCanSpliceCopy(); got != session.CopyGateForcedUserspace {
		t.Fatalf("outbound state=%v, want forced userspace", got)
	}
	if got := inbound.VisionSemanticPhase(); got != session.VisionSemanticPhaseNoDetach {
		t.Fatalf("inbound semantic=%v, want %v", got, session.VisionSemanticPhaseNoDetach)
	}
	if got := outbound.VisionSemanticPhase(); got != session.VisionSemanticPhaseNoDetach {
		t.Fatalf("outbound semantic=%v, want %v", got, session.VisionSemanticPhaseNoDetach)
	}
}

func TestMarkVisionNoDetachObservedAnnotatesExistingUserspaceGate(t *testing.T) {
	inbound := &session.Inbound{}
	inbound.SetCopyGate(session.CopyGateForcedUserspace, session.CopyGateReasonUnspecified)
	outbound := &session.Outbound{}
	outbound.SetCopyGate(session.CopyGateForcedUserspace, session.CopyGateReasonUnspecified)
	ctx := session.ContextWithInbound(context.Background(), inbound)

	markVisionNoDetachObserved(ctx, outbound)

	if got := inbound.CopyGateReason(); got != session.CopyGateReasonVisionNoDetach {
		t.Fatalf("inbound reason=%v, want vision_no_detach", got)
	}
	if got := outbound.CopyGateReason(); got != session.CopyGateReasonVisionNoDetach {
		t.Fatalf("outbound reason=%v, want vision_no_detach", got)
	}
	if got := inbound.GetCanSpliceCopy(); got != session.CopyGateForcedUserspace {
		t.Fatalf("inbound state=%v, want forced userspace", got)
	}
	if got := outbound.GetCanSpliceCopy(); got != session.CopyGateForcedUserspace {
		t.Fatalf("outbound state=%v, want forced userspace", got)
	}
}

func TestMarkVisionPostDetachObservedPromotesExplicitSemanticTruth(t *testing.T) {
	inbound := &session.Inbound{}
	outbound := &session.Outbound{}
	ctx := session.ContextWithInbound(context.Background(), inbound)
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{outbound})

	markVisionPostDetachObserved(ctx, outbound)

	if got := inbound.VisionSemanticPhase(); got != session.VisionSemanticPhasePostDetach {
		t.Fatalf("inbound semantic=%v, want %v", got, session.VisionSemanticPhasePostDetach)
	}
	if got := outbound.VisionSemanticPhase(); got != session.VisionSemanticPhasePostDetach {
		t.Fatalf("outbound semantic=%v, want %v", got, session.VisionSemanticPhasePostDetach)
	}
}

func TestCommittedVisionSemanticPhasePrefersStrongerExplicitState(t *testing.T) {
	inbound := &session.Inbound{}
	inbound.PromoteVisionSemanticPhase(session.VisionSemanticPhaseNoDetach)
	outbound := &session.Outbound{}
	outbound.PromoteVisionSemanticPhase(session.VisionSemanticPhasePostDetach)

	if got := committedVisionSemanticPhase(inbound, []*session.Outbound{outbound}); got != session.VisionSemanticPhasePostDetach {
		t.Fatalf("committedVisionSemanticPhase()=%v, want %v", got, session.VisionSemanticPhasePostDetach)
	}
}

func TestUnwrapVisionDeferredConnRecursesThroughWrappers(t *testing.T) {
	reader, writer := gonet.Pipe()
	defer reader.Close()
	defer writer.Close()

	dc := &tls.DeferredRustConn{}
	wrapped := &visionDeferredWrapConn{Conn: reader, inner: dc}
	commonConn := encryption.NewCommonConn(wrapped, false)
	statsConn := &stat.CounterConnection{Connection: commonConn}

	if got := unwrapVisionDeferredConn(statsConn); got != dc {
		t.Fatalf("unwrapVisionDeferredConn() = %T, want original deferred conn", got)
	}
}

func TestCopyRawConnIfExistDNSGuardRecordsFirstResponseLatency(t *testing.T) {
	readerPeer, readerConn := gonet.Pipe()
	defer readerPeer.Close()
	defer readerConn.Close()

	copyCtx, cancelCopy := context.WithCancel(context.Background())
	defer cancelCopy()
	timer := signal.CancelAfterInactivity(copyCtx, cancelCopy, time.Second)
	defer timer.SetTimeout(0)

	inbound := &session.Inbound{
		CanSpliceCopy: int32(session.CopyGateUnset),
		Local:         xnet.TCPDestination(xnet.IPAddress([]byte{127, 0, 0, 1}), xnet.Port(2036)),
	}
	outbound := &session.Outbound{
		CanSpliceCopy: int32(session.CopyGateUnset),
		Target:        xnet.TCPDestination(xnet.IPAddress([]byte{1, 1, 1, 1}), xnet.Port(53)),
	}
	ctx := session.ContextWithInbound(context.Background(), inbound)
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{outbound})

	errCh := make(chan error, 1)
	go func() {
		errCh <- CopyRawConnIfExist(ctx, readerConn, nil, buf.Discard, timer, nil)
	}()

	if _, err := readerPeer.Write([]byte("dns-ok")); err != nil {
		t.Fatalf("writer side failed: %v", err)
	}
	_ = readerPeer.Close()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("CopyRawConnIfExist() error=%v, want nil", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for DNS guard flow completion")
	}

}

func TestCopyRawConnIfExistDNSGuardReturnsAfterSingleResponseFrame(t *testing.T) {
	readerPeer, readerConn := gonet.Pipe()
	defer readerPeer.Close()
	defer readerConn.Close()

	copyCtx, cancelCopy := context.WithCancel(context.Background())
	defer cancelCopy()
	timer := signal.CancelAfterInactivity(copyCtx, cancelCopy, 30*time.Second)
	defer timer.SetTimeout(0)

	inbound := &session.Inbound{
		CanSpliceCopy: int32(session.CopyGateUnset),
		Local:         xnet.TCPDestination(xnet.IPAddress([]byte{127, 0, 0, 1}), xnet.Port(2036)),
	}
	outbound := &session.Outbound{
		CanSpliceCopy: int32(session.CopyGateUnset),
		Target:        xnet.TCPDestination(xnet.IPAddress([]byte{1, 1, 1, 1}), xnet.Port(53)),
	}
	ctx := session.ContextWithInbound(context.Background(), inbound)
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{outbound})

	errCh := make(chan error, 1)
	go func() {
		errCh <- CopyRawConnIfExist(ctx, readerConn, nil, buf.Discard, timer, nil)
	}()

	frame := []byte{0x00, 0x04, 'd', 'n', 's', '!'}
	if _, err := readerPeer.Write(frame); err != nil {
		t.Fatalf("writer side failed: %v", err)
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("CopyRawConnIfExist() error=%v, want nil", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timeout waiting for guarded DNS flow to retire after one response frame")
	}

}

func TestCopyRawConnIfExistDNSGuardZeroByteTimeoutMetric(t *testing.T) {
	inbound := &session.Inbound{
		CanSpliceCopy: int32(session.CopyGateUnset),
		Local:         xnet.TCPDestination(xnet.IPAddress([]byte{127, 0, 0, 1}), xnet.Port(2036)),
	}
	outbound := &session.Outbound{
		CanSpliceCopy: int32(session.CopyGateUnset),
		Target:        xnet.TCPDestination(xnet.IPAddress([]byte{1, 1, 1, 1}), xnet.Port(53)),
	}
	ctx := session.ContextWithInbound(context.Background(), inbound)
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{outbound})

	err := CopyRawConnIfExist(ctx, testTimeoutConn{}, nil, buf.Discard, nil, nil)
	if !goerrors.Is(err, io.EOF) {
		t.Fatalf("CopyRawConnIfExist() error=%v, want io.EOF timeout close", err)
	}

}

func TestCopyRawConnIfExistVisionBypassDNSUsesImmediateUserspacePath(t *testing.T) {
	readerPeer, readerConn := gonet.Pipe()
	defer readerPeer.Close()
	defer readerConn.Close()

	copyCtx, cancelCopy := context.WithCancel(context.Background())
	defer cancelCopy()
	timer := signal.CancelAfterInactivity(copyCtx, cancelCopy, 30*time.Second)
	defer timer.SetTimeout(0)

	inbound := &session.Inbound{
		Local: xnet.TCPDestination(xnet.IPAddress([]byte{127, 0, 0, 1}), xnet.Port(2036)),
	}
	inbound.SetCopyGate(session.CopyGateForcedUserspace, session.CopyGateReasonVisionBypass)
	outbound := &session.Outbound{
		Target: xnet.TCPDestination(xnet.IPAddress([]byte{1, 1, 1, 1}), xnet.Port(53)),
	}
	outbound.SetCopyGate(session.CopyGateForcedUserspace, session.CopyGateReasonVisionBypass)

	ctx := session.ContextWithInbound(context.Background(), inbound)
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{outbound})

	errCh := make(chan error, 1)
	go func() {
		errCh <- CopyRawConnIfExist(ctx, readerConn, nil, buf.Discard, timer, nil)
	}()

	if _, err := readerPeer.Write([]byte("dns-ok")); err != nil {
		t.Fatalf("writer side failed: %v", err)
	}
	_ = readerPeer.Close()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("CopyRawConnIfExist() error=%v, want nil", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for vision bypass DNS flow completion")
	}

}

func TestCopyRawConnIfExistWakeOnLaterVisionNoDetachSignal(t *testing.T) {
	readerPeer, readerConn := gonet.Pipe()
	defer readerPeer.Close()
	defer readerConn.Close()

	writerConn := &tls.DeferredRustConn{}
	copyCtx, cancelCopy := context.WithCancel(context.Background())
	defer cancelCopy()
	timer := signal.CancelAfterInactivity(copyCtx, cancelCopy, 30*time.Second)
	defer timer.SetTimeout(0)

	inbound := &session.Inbound{
		CanSpliceCopy: int32(session.CopyGatePendingDetach),
	}
	outbound := &session.Outbound{
		CanSpliceCopy: int32(session.CopyGatePendingDetach),
		Target:        xnet.TCPDestination(xnet.IPAddress([]byte{57, 144, 15, 63}), xnet.Port(443)),
	}
	visionCh := make(chan session.VisionSignal, 1)
	ctx := session.ContextWithInbound(session.ContextWithVisionSignal(context.Background(), visionCh), inbound)
	ctx = session.ContextWithVisionTimestamps(ctx, &session.VisionTimestamps{})
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{outbound})

	startedAt := time.Now()
	errCh := make(chan error, 1)
	go func() {
		errCh <- CopyRawConnIfExist(ctx, readerConn, writerConn, buf.Discard, timer, nil)
	}()

	time.AfterFunc(1200*time.Millisecond, func() {
		markVisionNoDetachObserved(ctx, outbound)
		sendVisionSignal(visionCh, session.VisionSignal{Command: 1})
	})
	time.AfterFunc(2500*time.Millisecond, func() {
		_, _ = readerPeer.Write([]byte("late-stable-response"))
		_ = readerPeer.Close()
	})

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("CopyRawConnIfExist() error=%v, want nil after explicit no-detach wake", err)
		}
		elapsed := time.Since(startedAt)
		if elapsed < 2*time.Second || elapsed > 5*time.Second {
			t.Fatalf("CopyRawConnIfExist() elapsed=%v, want later stable-userspace response after explicit wake", elapsed)
		}
		if got := inbound.GetCanSpliceCopy(); got != session.CopyGateForcedUserspace {
			t.Fatalf("inbound state=%v, want forced userspace after later command=1 signal", got)
		}
		if got := outbound.GetCanSpliceCopy(); got != session.CopyGateForcedUserspace {
			t.Fatalf("outbound state=%v, want forced userspace after later command=1 signal", got)
		}
	case <-time.After(7 * time.Second):
		t.Fatal("timeout waiting for later explicit no-detach wake flow")
	}
}

func TestCopyRawConnIfExistWaitsForExplicitPostDetachSignal(t *testing.T) {
	readerPeer, readerConn := gonet.Pipe()
	defer readerPeer.Close()
	defer readerConn.Close()

	writerConn := &tls.DeferredRustConn{}
	copyCtx, cancelCopy := context.WithCancel(context.Background())
	defer cancelCopy()
	timer := signal.CancelAfterInactivity(copyCtx, cancelCopy, 30*time.Second)
	defer timer.SetTimeout(0)

	inbound := &session.Inbound{
		CanSpliceCopy: int32(session.CopyGatePendingDetach),
	}
	outbound := &session.Outbound{
		CanSpliceCopy: int32(session.CopyGatePendingDetach),
		Target:        xnet.TCPDestination(xnet.IPAddress([]byte{57, 144, 14, 36}), xnet.Port(443)),
	}
	visionCh := make(chan session.VisionSignal, 1)
	ctx := session.ContextWithInbound(session.ContextWithVisionSignal(context.Background(), visionCh), inbound)
	ctx = session.ContextWithVisionTimestamps(ctx, &session.VisionTimestamps{})
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{outbound})

	var written bytes.Buffer
	errCh := make(chan error, 1)
	go func() {
		errCh <- CopyRawConnIfExist(ctx, readerConn, writerConn, buf.NewWriter(&written), timer, nil)
	}()

	time.AfterFunc(500*time.Millisecond, func() {
		ObserveVisionUplinkComplete(ctx, inbound, outbound)
	})
	time.AfterFunc(700*time.Millisecond, func() {
		markVisionPostDetachObserved(ctx, outbound)
		markDeferredRustConnDetachedForTest(writerConn)
		sendVisionSignal(visionCh, session.VisionSignal{Command: 2})
	})
	time.AfterFunc(1200*time.Millisecond, func() {
		_, _ = readerPeer.Write([]byte("post-detach-response"))
		_ = readerPeer.Close()
	})

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("CopyRawConnIfExist() error=%v, want nil after explicit post-detach wake", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for explicit post-detach wake flow")
	}

	if got := written.String(); got != "post-detach-response" {
		t.Fatalf("written payload=%q, want post-detach payload after explicit signal", got)
	}
}

func TestCopyRawConnIfExistDoesNotReportNativeDeferredRuntimeRecoveryOnNoDetachSuccess(t *testing.T) {
	readerPeer, readerConn := gonet.Pipe()
	defer readerPeer.Close()
	defer readerConn.Close()

	writerConn := &tls.DeferredRustConn{}
	copyCtx, cancelCopy := context.WithCancel(context.Background())
	defer cancelCopy()
	timer := signal.CancelAfterInactivity(copyCtx, cancelCopy, 30*time.Second)
	defer timer.SetTimeout(0)

	inbound := &session.Inbound{
		Tag:           "native-vision-recovery",
		CanSpliceCopy: int32(session.CopyGatePendingDetach),
		Conn:          writerConn,
	}
	outbound := &session.Outbound{
		CanSpliceCopy: int32(session.CopyGatePendingDetach),
		Target:        xnet.TCPDestination(xnet.IPAddress([]byte{57, 144, 15, 63}), xnet.Port(443)),
	}
	visionCh := make(chan session.VisionSignal, 1)
	ctx := session.ContextWithInbound(session.ContextWithVisionSignal(context.Background(), visionCh), inbound)
	ctx = session.ContextWithVisionTimestamps(ctx, &session.VisionTimestamps{})
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{outbound})

	oldReport := reportNativeRuntimeRecoveryByTagFn
	var (
		reportCalls int
	)
	reportNativeRuntimeRecoveryByTagFn = func(tag string) bool {
		reportCalls++
		return true
	}
	defer func() {
		reportNativeRuntimeRecoveryByTagFn = oldReport
	}()

	errCh := make(chan error, 1)
	go func() {
		errCh <- CopyRawConnIfExist(ctx, readerConn, writerConn, buf.Discard, timer, nil)
	}()

	time.AfterFunc(1200*time.Millisecond, func() {
		markVisionNoDetachObserved(ctx, outbound)
		sendVisionSignal(visionCh, session.VisionSignal{Command: 1})
	})
	time.AfterFunc(2500*time.Millisecond, func() {
		_, _ = readerPeer.Write([]byte("late-stable-response"))
		_ = readerPeer.Close()
	})

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("CopyRawConnIfExist() error=%v, want nil after explicit no-detach wake", err)
		}
		if reportCalls != 0 {
			t.Fatalf("runtime recovery reports=%d, want 0", reportCalls)
		}
	case <-time.After(7 * time.Second):
		t.Fatal("timeout waiting for no-detach recovery flow")
	}
}

func TestCopyRawConnIfExistReportsNativeDeferredRuntimeRegressionOnTimeout(t *testing.T) {
	readerPeer, readerConn := gonet.Pipe()
	defer readerPeer.Close()
	defer readerConn.Close()

	writerConn := &tls.DeferredRustConn{}
	copyCtx, cancelCopy := context.WithCancel(context.Background())
	defer cancelCopy()
	timer := signal.CancelAfterInactivity(copyCtx, cancelCopy, 30*time.Second)
	defer timer.SetTimeout(0)

	inbound := &session.Inbound{
		Tag:           "native-vision-timeout",
		CanSpliceCopy: int32(session.CopyGatePendingDetach),
		Conn:          writerConn,
	}
	outbound := &session.Outbound{
		CanSpliceCopy: int32(session.CopyGatePendingDetach),
		Target:        xnet.TCPDestination(xnet.IPAddress([]byte{163, 70, 159, 175}), xnet.Port(5222)),
	}
	visionCh := make(chan session.VisionSignal, 1)
	ctx := session.ContextWithInbound(session.ContextWithVisionSignal(context.Background(), visionCh), inbound)
	ctx = session.ContextWithVisionTimestamps(ctx, &session.VisionTimestamps{})
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{outbound})

	oldReport := reportNativeRuntimeRegressionByTagFn
	var (
		reportedTag string
		reportCalls int
	)
	reportNativeRuntimeRegressionByTagFn = func(tag string) bool {
		reportedTag = tag
		reportCalls++
		return true
	}
	defer func() {
		reportNativeRuntimeRegressionByTagFn = oldReport
	}()

	startedAt := time.Now()
	errCh := make(chan error, 1)
	go func() {
		errCh <- CopyRawConnIfExist(ctx, readerConn, writerConn, buf.Discard, timer, nil)
	}()

	select {
	case err := <-errCh:
		if err != nil && !goerrors.Is(err, io.EOF) {
			t.Fatalf("CopyRawConnIfExist() error=%v, want nil/EOF after bounded unresolved native timeout", err)
		}
		elapsed := time.Since(startedAt)
		if elapsed < 2500*time.Millisecond || elapsed > 4500*time.Millisecond {
			t.Fatalf("CopyRawConnIfExist() elapsed=%v, want bounded unresolved native timeout", elapsed)
		}
		if reportCalls != 1 {
			t.Fatalf("runtime regression reports=%d, want 1", reportCalls)
		}
		if reportedTag != inbound.Tag {
			t.Fatalf("reportedTag=%q, want %q", reportedTag, inbound.Tag)
		}
	case <-time.After(7 * time.Second):
		t.Fatal("timeout waiting for unresolved native timeout flow")
	}
}

func TestCopyRawConnIfExistReportsNativeDeferredRuntimeRegressionOnTimeoutAfterUserspaceBytes(t *testing.T) {
	readerPeer, readerConn := gonet.Pipe()
	defer readerPeer.Close()
	defer readerConn.Close()

	writerConn := &tls.DeferredRustConn{}
	copyCtx, cancelCopy := context.WithCancel(context.Background())
	defer cancelCopy()
	timer := signal.CancelAfterInactivity(copyCtx, cancelCopy, 30*time.Second)
	defer timer.SetTimeout(0)

	inbound := &session.Inbound{
		Tag:           "native-vision-timeout-bytes",
		CanSpliceCopy: int32(session.CopyGatePendingDetach),
		Conn:          writerConn,
	}
	outbound := &session.Outbound{
		CanSpliceCopy: int32(session.CopyGatePendingDetach),
		Target:        xnet.TCPDestination(xnet.IPAddress([]byte{57, 144, 14, 36}), xnet.Port(443)),
	}
	visionCh := make(chan session.VisionSignal, 1)
	ctx := session.ContextWithInbound(session.ContextWithVisionSignal(context.Background(), visionCh), inbound)
	ctx = session.ContextWithVisionTimestamps(ctx, &session.VisionTimestamps{})
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{outbound})

	oldReport := reportNativeRuntimeRegressionByTagFn
	var (
		reportedTag string
		reportCalls int
	)
	reportNativeRuntimeRegressionByTagFn = func(tag string) bool {
		reportedTag = tag
		reportCalls++
		return true
	}
	defer func() {
		reportNativeRuntimeRegressionByTagFn = oldReport
	}()

	errCh := make(chan error, 1)
	go func() {
		errCh <- CopyRawConnIfExist(ctx, readerConn, writerConn, buf.Discard, timer, nil)
	}()

	time.AfterFunc(200*time.Millisecond, func() {
		_, _ = readerPeer.Write([]byte("early-userspace-response"))
	})

	select {
	case err := <-errCh:
		if err != nil && !goerrors.Is(err, io.EOF) {
			t.Fatalf("CopyRawConnIfExist() error=%v, want nil/EOF after bounded unresolved native timeout", err)
		}
		if reportCalls != 1 {
			t.Fatalf("runtime regression reports=%d, want 1", reportCalls)
		}
		if reportedTag != inbound.Tag {
			t.Fatalf("reportedTag=%q, want %q", reportedTag, inbound.Tag)
		}
	case <-time.After(7 * time.Second):
		t.Fatal("timeout waiting for unresolved native timeout with userspace bytes")
	}
}

func TestCopyRawConnIfExistWaitsForHardDeadlineAfterUnresolvedUplinkComplete(t *testing.T) {
	readerPeer, readerConn := gonet.Pipe()
	defer readerPeer.Close()
	defer readerConn.Close()

	writerConn := &tls.DeferredRustConn{}
	copyCtx, cancelCopy := context.WithCancel(context.Background())
	defer cancelCopy()
	timer := signal.CancelAfterInactivity(copyCtx, cancelCopy, 30*time.Second)
	defer timer.SetTimeout(0)

	inbound := &session.Inbound{
		Tag:           "native-vision-uplink-complete",
		CanSpliceCopy: int32(session.CopyGatePendingDetach),
		Conn:          writerConn,
	}
	outbound := &session.Outbound{
		CanSpliceCopy: int32(session.CopyGatePendingDetach),
		Target:        xnet.TCPDestination(xnet.IPAddress([]byte{157, 240, 199, 175}), xnet.Port(5222)),
	}
	visionCh := make(chan session.VisionSignal, 1)
	ctx := session.ContextWithInbound(session.ContextWithVisionSignal(context.Background(), visionCh), inbound)
	ctx = session.ContextWithVisionTimestamps(ctx, &session.VisionTimestamps{})
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{outbound})

	oldReport := reportNativeRuntimeRegressionByTagFn
	var reportCalls int
	reportNativeRuntimeRegressionByTagFn = func(tag string) bool {
		reportCalls++
		return true
	}
	defer func() {
		reportNativeRuntimeRegressionByTagFn = oldReport
	}()

	startedAt := time.Now()
	errCh := make(chan error, 1)
	go func() {
		errCh <- CopyRawConnIfExist(ctx, readerConn, writerConn, buf.Discard, timer, nil)
	}()

	time.AfterFunc(500*time.Millisecond, func() {
		ObserveVisionUplinkComplete(ctx, inbound, outbound)
	})

	select {
	case err := <-errCh:
		if err != nil && !goerrors.Is(err, io.EOF) {
			t.Fatalf("CopyRawConnIfExist() error=%v, want nil/EOF after unresolved uplink completion", err)
		}
		elapsed := time.Since(startedAt)
		if elapsed < 2500*time.Millisecond || elapsed > 4500*time.Millisecond {
			t.Fatalf("CopyRawConnIfExist() elapsed=%v, want hard pre-detach deadline after unresolved uplink completion", elapsed)
		}
		if reportCalls != 1 {
			t.Fatalf("runtime regression reports=%d, want 1", reportCalls)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("timeout waiting for unresolved uplink completion hard deadline")
	}
}

func TestCopyRawConnIfExistKeepsPersistentCommandContinueTelemetryOnly(t *testing.T) {
	readerPeer, readerConn := gonet.Pipe()
	defer readerPeer.Close()
	defer readerConn.Close()

	writerConn := &tls.DeferredRustConn{}
	copyCtx, cancelCopy := context.WithCancel(context.Background())
	defer cancelCopy()
	timer := signal.CancelAfterInactivity(copyCtx, cancelCopy, 30*time.Second)
	defer timer.SetTimeout(0)

	inbound := &session.Inbound{
		CanSpliceCopy: int32(session.CopyGatePendingDetach),
	}
	outbound := &session.Outbound{
		CanSpliceCopy: int32(session.CopyGatePendingDetach),
		Target:        xnet.TCPDestination(xnet.IPAddress([]byte{149, 154, 167, 50}), xnet.Port(443)),
	}
	timestamps := &session.VisionTimestamps{}
	ctx := session.ContextWithInbound(context.Background(), inbound)
	ctx = session.ContextWithVisionTimestamps(ctx, timestamps)
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{outbound})

	startedAt := time.Now()
	errCh := make(chan error, 1)
	go func() {
		errCh <- CopyRawConnIfExist(ctx, readerConn, writerConn, buf.Discard, timer, nil)
	}()

	time.AfterFunc(1*time.Second, func() {
		if got := inbound.GetCanSpliceCopy(); got != session.CopyGatePendingDetach {
			t.Errorf("inbound state=%v, want pending detach while command=0 remains telemetry-only", got)
		}
		if got := outbound.GetCanSpliceCopy(); got != session.CopyGatePendingDetach {
			t.Errorf("outbound state=%v, want pending detach while command=0 remains telemetry-only", got)
		}
	})

	select {
	case err := <-errCh:
		if !goerrors.Is(err, io.EOF) {
			t.Fatalf("CopyRawConnIfExist() error=%v, want EOF timeout while command=0 stays telemetry-only", err)
		}
		if elapsed := time.Since(startedAt); elapsed < 2500*time.Millisecond || elapsed > 4*time.Second {
			t.Fatalf("CopyRawConnIfExist() elapsed=%v, want bounded compatibility-first timeout around 3s", elapsed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for command=0 telemetry-only flow")
	}
}

func TestCopyRawConnIfExistKeepsEarlyCommandContinueEvidenceTelemetryOnly(t *testing.T) {
	readerPeer, readerConn := mustTCPPair(t)
	defer readerPeer.Close()
	defer readerConn.Close()

	writerConn := &tls.DeferredRustConn{}
	copyCtx, cancelCopy := context.WithCancel(context.Background())
	defer cancelCopy()
	timer := signal.CancelAfterInactivity(copyCtx, cancelCopy, 30*time.Second)
	defer timer.SetTimeout(0)

	inbound := &session.Inbound{
		CanSpliceCopy: int32(session.CopyGatePendingDetach),
	}
	outbound := &session.Outbound{
		CanSpliceCopy: int32(session.CopyGatePendingDetach),
		Target:        xnet.TCPDestination(xnet.IPAddress([]byte{151, 101, 1, 140}), xnet.Port(443)),
	}
	timestamps := &session.VisionTimestamps{}
	ctx := session.ContextWithInbound(context.Background(), inbound)
	ctx = session.ContextWithVisionTimestamps(ctx, timestamps)
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{outbound})

	startedAt := time.Now()
	errCh := make(chan error, 1)
	go func() {
		errCh <- CopyRawConnIfExist(ctx, readerConn, writerConn, buf.Discard, timer, nil)
	}()

	time.AfterFunc(100*time.Millisecond, func() {
		_ = markVisionCommandContinueEvidence(ctx, writerConn, outbound)
	})
	time.AfterFunc(500*time.Millisecond, func() {
		if got := inbound.GetCanSpliceCopy(); got != session.CopyGatePendingDetach {
			t.Errorf("inbound state=%v, want pending detach while command=0 evidence stays telemetry-only", got)
		}
		if got := outbound.GetCanSpliceCopy(); got != session.CopyGatePendingDetach {
			t.Errorf("outbound state=%v, want pending detach while command=0 evidence stays telemetry-only", got)
		}
	})
	time.AfterFunc(1200*time.Millisecond, func() {
		_, _ = readerPeer.Write([]byte("late-response"))
		_ = readerPeer.Close()
	})

	select {
	case err := <-errCh:
		if err != nil && !goerrors.Is(err, io.EOF) {
			t.Fatalf("CopyRawConnIfExist() error=%v, want nil/EOF after telemetry-only command=0 evidence", err)
		}
		elapsed := time.Since(startedAt)
		if elapsed < time.Second {
			t.Fatalf("CopyRawConnIfExist() elapsed=%v, want > 1s to wait for late response", elapsed)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("timeout waiting for command=0 telemetry-only flow")
	}
}

func TestClassifyUserspaceExit(t *testing.T) {
	cases := []struct {
		name            string
		err             error
		userspaceBytes  int64
		stableUserspace bool
		want            pipeline.UserspaceExit
	}{
		{
			name:           "remote eof no response",
			err:            io.EOF,
			userspaceBytes: 0,
			want:           pipeline.UserspaceExitRemoteEOFNoResponse,
		},
		{
			name:            "stable userspace eof",
			err:             io.EOF,
			userspaceBytes:  0,
			stableUserspace: true,
			want:            pipeline.UserspaceExitStableUserspaceClose,
		},
		{
			name:           "remote reset",
			err:            syscall.ECONNRESET,
			userspaceBytes: 0,
			want:           pipeline.UserspaceExitRemoteReset,
		},
		{
			name:           "local close no response",
			err:            gonet.ErrClosed,
			userspaceBytes: 0,
			want:           pipeline.UserspaceExitLocalCloseNoResponse,
		},
		{
			name:           "complete after bytes",
			err:            io.EOF,
			userspaceBytes: 64,
			want:           pipeline.UserspaceExitComplete,
		},
		{
			name: "nil error",
			err:  nil,
			want: pipeline.UserspaceExitNone,
		},
	}

	for _, tc := range cases {
		if got := classifyUserspaceExit(tc.err, tc.userspaceBytes, tc.stableUserspace); got != tc.want {
			t.Fatalf("%s: classifyUserspaceExit() = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestIsExpectedSpliceReadFromError(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{io.ErrClosedPipe, true},
		{gonet.ErrClosed, true},
		{context.Canceled, true},
		{syscall.EPIPE, true},
		{syscall.ECONNRESET, true},
		{syscall.ENOTCONN, true},
		{syscall.ESHUTDOWN, true},
		{io.EOF, false},
		{goerrors.New("boom"), false},
	}
	for _, tc := range cases {
		got := isExpectedSpliceReadFromError(tc.err)
		if got != tc.want {
			t.Fatalf("isExpectedSpliceReadFromError(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}

func TestDeferredConnRequiresTLS(t *testing.T) {
	if deferredConnRequiresTLS(nil) {
		t.Fatal("nil conn should not require deferred TLS")
	}

	left, right := mustTCPPair(t)
	defer left.Close()
	defer right.Close()
	if deferredConnRequiresTLS(left) {
		t.Fatal("raw TCP conn should not require deferred TLS")
	}

	// Zero-value DeferredRustConn is non-detached and not kTLS-active.
	if !deferredConnRequiresTLS(&tls.DeferredRustConn{}) {
		t.Fatal("DeferredRustConn should require TLS while non-detached and non-kTLS")
	}
}

func TestVisionTimestampsHelpers(t *testing.T) {
	timestamps := &session.VisionTimestamps{}

	timestamps.StoreDetach(789)
	if got, ok := timestamps.ConsumeDetach(); !ok || got != 789 {
		t.Fatalf("VisionTimestamps.ConsumeDetach() got (%d,%v), want (789,true)", got, ok)
	}
	if _, ok := timestamps.ConsumeDetach(); ok {
		t.Fatal("second VisionTimestamps.ConsumeDetach() should be empty")
	}
}

func TestVisionTimestampsClear(t *testing.T) {
	timestamps := &session.VisionTimestamps{}
	timestamps.StoreDetach(456)
	timestamps.Clear()

	if _, ok := timestamps.ConsumeDetach(); ok {
		t.Fatal("detach timestamp should be cleared")
	}
}

func TestVisionDetachFutureTimeoutState(t *testing.T) {
	fut := &visionDetachFuture{
		done: make(chan struct{}),
	}
	fut.state.Store(visionDetachPending)
	fut.state.Store(visionDetachTimedOut)
	if got := fut.state.Load(); got != visionDetachTimedOut {
		t.Fatalf("state=%d, want %d", got, visionDetachTimedOut)
	}
	// Simulate late completion
	close(fut.done)
	_ = fut.state.CompareAndSwap(visionDetachPending, visionDetachDone)
	if got := fut.state.Load(); got != visionDetachTimedOut {
		t.Fatalf("late completion must not clear timeout state; got=%d want=%d", got, visionDetachTimedOut)
	}
}

type singleReadReader struct {
	mb   buf.MultiBuffer
	err  error
	read bool
}

func (r *singleReadReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if r.read {
		return nil, io.EOF
	}
	r.read = true
	return r.mb, r.err
}

type testTimeoutError struct{}

func (testTimeoutError) Error() string   { return "i/o timeout" }
func (testTimeoutError) Timeout() bool   { return true }
func (testTimeoutError) Temporary() bool { return true }

type testTimeoutConn struct{}

func (testTimeoutConn) Read([]byte) (int, error)         { return 0, testTimeoutError{} }
func (testTimeoutConn) Write(b []byte) (int, error)      { return len(b), nil }
func (testTimeoutConn) Close() error                     { return nil }
func (testTimeoutConn) LocalAddr() gonet.Addr            { return testDummyAddr("timeout-local") }
func (testTimeoutConn) RemoteAddr() gonet.Addr           { return testDummyAddr("timeout-remote") }
func (testTimeoutConn) SetDeadline(time.Time) error      { return nil }
func (testTimeoutConn) SetReadDeadline(time.Time) error  { return nil }
func (testTimeoutConn) SetWriteDeadline(time.Time) error { return nil }

type deadlineSpyConn struct {
	mu            sync.Mutex
	readDeadline  time.Time
	readDeadlineN int
}

func (c *deadlineSpyConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *deadlineSpyConn) Write(b []byte) (int, error)      { return len(b), nil }
func (c *deadlineSpyConn) Close() error                     { return nil }
func (c *deadlineSpyConn) LocalAddr() gonet.Addr            { return testDummyAddr("deadline-spy-local") }
func (c *deadlineSpyConn) RemoteAddr() gonet.Addr           { return testDummyAddr("deadline-spy-remote") }
func (c *deadlineSpyConn) SetDeadline(time.Time) error      { return nil }
func (c *deadlineSpyConn) SetWriteDeadline(time.Time) error { return nil }

func (c *deadlineSpyConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = t
	c.readDeadlineN++
	return nil
}

func (c *deadlineSpyConn) ReadDeadlineCalls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.readDeadlineN
}

type stagedEOFThenDataConn struct {
	mu           sync.Mutex
	eofReady     chan struct{}
	dataReady    chan struct{}
	data         []byte
	returnedEOF  bool
	returnedData bool
}

func newStagedEOFThenDataConn(data []byte) *stagedEOFThenDataConn {
	return &stagedEOFThenDataConn{
		eofReady:  make(chan struct{}),
		dataReady: make(chan struct{}),
		data:      append([]byte(nil), data...),
	}
}

func (c *stagedEOFThenDataConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	if !c.returnedEOF {
		ch := c.eofReady
		c.mu.Unlock()
		<-ch
		c.mu.Lock()
		c.returnedEOF = true
		c.mu.Unlock()
		return 0, io.EOF
	}
	if !c.returnedData {
		ch := c.dataReady
		c.mu.Unlock()
		<-ch
		c.mu.Lock()
		c.returnedData = true
		n := copy(b, c.data)
		c.mu.Unlock()
		return n, nil
	}
	c.mu.Unlock()
	return 0, io.EOF
}

func (c *stagedEOFThenDataConn) Write(b []byte) (int, error)      { return len(b), nil }
func (c *stagedEOFThenDataConn) Close() error                     { return nil }
func (c *stagedEOFThenDataConn) LocalAddr() gonet.Addr            { return testDummyAddr("staged-local") }
func (c *stagedEOFThenDataConn) RemoteAddr() gonet.Addr           { return testDummyAddr("staged-remote") }
func (c *stagedEOFThenDataConn) SetDeadline(time.Time) error      { return nil }
func (c *stagedEOFThenDataConn) SetReadDeadline(time.Time) error  { return nil }
func (c *stagedEOFThenDataConn) SetWriteDeadline(time.Time) error { return nil }

func markDeferredRustConnDetachedForTest(dc *tls.DeferredRustConn) {
	field := reflect.ValueOf(dc).Elem().FieldByName("detached")
	if !field.IsValid() {
		panic("DeferredRustConn.detached field not found")
	}
	detached := (*atomic.Bool)(unsafe.Pointer(field.UnsafeAddr()))
	detached.Store(true)
}

func mustTCPPair(t *testing.T) (*gonet.TCPConn, *gonet.TCPConn) {
	t.Helper()

	ln, err := gonet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() failed: %v", err)
	}
	defer ln.Close()

	acceptCh := make(chan *gonet.TCPConn, 1)
	errCh := make(chan error, 1)
	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			errCh <- aerr
			return
		}
		tc, ok := conn.(*gonet.TCPConn)
		if !ok {
			_ = conn.Close()
			errCh <- goerrors.New("accepted conn is not *net.TCPConn")
			return
		}
		acceptCh <- tc
	}()

	clientConn, err := gonet.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("Dial() failed: %v", err)
	}
	clientTCP, ok := clientConn.(*gonet.TCPConn)
	if !ok {
		_ = clientConn.Close()
		t.Fatal("dialed conn is not *net.TCPConn")
	}

	select {
	case aerr := <-errCh:
		_ = clientTCP.Close()
		t.Fatalf("Accept() failed: %v", aerr)
	case serverTCP := <-acceptCh:
		return clientTCP, serverTCP
	case <-time.After(2 * time.Second):
		_ = clientTCP.Close()
		t.Fatal("timeout waiting for accept")
	}
	return nil, nil
}
