package proxy

import (
	"context"
	goerrors "errors"
	"io"
	gonet "net"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/internet/tls"
)

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

	inbound := &session.Inbound{CanSpliceCopy: 2}
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

	if inbound.GetCanSpliceCopy() != 2 {
		t.Fatalf("CanSpliceCopy = %d, want 2", inbound.GetCanSpliceCopy())
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

	inbound := &session.Inbound{CanSpliceCopy: 2}
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

	if inbound.GetCanSpliceCopy() != 1 {
		t.Fatalf("CanSpliceCopy = %d, want 1", inbound.GetCanSpliceCopy())
	}
}

func TestVisionReaderDirectCopyPromotesInboundSpliceState(t *testing.T) {
	left, right := mustTCPPair(t)
	defer left.Close()
	defer right.Close()

	ts := NewTrafficState(nil)
	ts.Outbound.WithinPaddingBuffers = true
	ts.Outbound.CurrentCommand = 2

	inbound := &session.Inbound{CanSpliceCopy: 2, Conn: left}
	ctx := session.ContextWithInbound(context.Background(), inbound)

	b := buf.New()
	b.Write([]byte("abc"))
	reader := &singleReadReader{
		mb: buf.MultiBuffer{b},
	}
	vr := NewVisionReader(reader, ts, false, ctx, left, nil, nil, nil)
	mb, err := vr.ReadMultiBuffer()
	if err != nil {
		t.Fatalf("ReadMultiBuffer() error = %v", err)
	}
	buf.ReleaseMulti(mb)

	if !ts.Outbound.DownlinkReaderDirectCopy {
		t.Fatal("DownlinkReaderDirectCopy should be true after command=2")
	}
	if inbound.GetCanSpliceCopy() != 1 {
		t.Fatalf("CanSpliceCopy = %d, want 1", inbound.GetCanSpliceCopy())
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

func TestFmtMarkerWithDelta(t *testing.T) {
	if got := fmtMarkerWithDelta(12, 0); got != "12" {
		t.Fatalf("fmtMarkerWithDelta(12,0)=%q, want %q", got, "12")
	}
	if got := fmtMarkerWithDelta(12, 3); got != "12(+3)" {
		t.Fatalf("fmtMarkerWithDelta(12,3)=%q, want %q", got, "12(+3)")
	}
}

func TestFmtAverageNanos(t *testing.T) {
	if got := fmtAverageNanos(0, 0); got != "0" {
		t.Fatalf("fmtAverageNanos(0,0)=%q, want 0", got)
	}
	if got := fmtAverageNanos(100, 4); got != "25" {
		t.Fatalf("fmtAverageNanos(100,4)=%q, want 25", got)
	}
}

func TestMarkerSnapshot(t *testing.T) {
	var total atomic.Uint64
	var last atomic.Uint64
	total.Store(10)
	current, delta := markerSnapshot(&total, &last)
	if current != 10 || delta != 10 {
		t.Fatalf("first snapshot got current=%d delta=%d, want 10/10", current, delta)
	}
	current, delta = markerSnapshot(&total, &last)
	if current != 10 || delta != 0 {
		t.Fatalf("second snapshot got current=%d delta=%d, want 10/0", current, delta)
	}
	total.Store(15)
	current, delta = markerSnapshot(&total, &last)
	if current != 15 || delta != 5 {
		t.Fatalf("third snapshot got current=%d delta=%d, want 15/5", current, delta)
	}
}

func TestRecordSpliceHistogramBuckets(t *testing.T) {
	resetSpliceHistogramCounters()
	recordSpliceHistogram(1000, uint64(500*time.Microsecond))
	recordSpliceHistogram(5*1024, uint64(2*time.Millisecond))
	recordSpliceHistogram(70*1024, uint64(10*time.Millisecond))
	recordSpliceHistogram(2*1024*1024, uint64(50*time.Millisecond))
	recordSpliceHistogram(2*1024*1024, uint64(200*time.Millisecond))

	if got := pipelineMarkerSpliceBytesLt4K.Load(); got != 1 {
		t.Fatalf("bytes<4k=%d, want 1", got)
	}
	if got := pipelineMarkerSpliceBytes4KTo64K.Load(); got != 1 {
		t.Fatalf("bytes4k_64k=%d, want 1", got)
	}
	if got := pipelineMarkerSpliceBytes64KTo1M.Load(); got != 1 {
		t.Fatalf("bytes64k_1m=%d, want 1", got)
	}
	if got := pipelineMarkerSpliceBytesGe1M.Load(); got != 2 {
		t.Fatalf("bytes>=1m=%d, want 2", got)
	}
	if got := pipelineMarkerSpliceDurLt1ms.Load(); got != 1 {
		t.Fatalf("dur<1ms=%d, want 1", got)
	}
	if got := pipelineMarkerSpliceDur1To5ms.Load(); got != 1 {
		t.Fatalf("dur1_5ms=%d, want 1", got)
	}
	if got := pipelineMarkerSpliceDur5To20ms.Load(); got != 1 {
		t.Fatalf("dur5_20ms=%d, want 1", got)
	}
	if got := pipelineMarkerSpliceDur20To100ms.Load(); got != 1 {
		t.Fatalf("dur20_100ms=%d, want 1", got)
	}
	if got := pipelineMarkerSpliceDurGe100ms.Load(); got != 1 {
		t.Fatalf("dur>=100ms=%d, want 1", got)
	}
}

func TestRecordRawUnwrapToDetachHistogramBuckets(t *testing.T) {
	resetRawUnwrapHistogramCounters()
	recordRawUnwrapToDetachHistogram(uint64(1 * time.Millisecond))
	recordRawUnwrapToDetachHistogram(uint64(10 * time.Millisecond))
	recordRawUnwrapToDetachHistogram(uint64(50 * time.Millisecond))
	recordRawUnwrapToDetachHistogram(uint64(150 * time.Millisecond))

	if got := pipelineMarkerRawUnwrapToDetachLt5ms.Load(); got != 1 {
		t.Fatalf("lt5ms=%d, want 1", got)
	}
	if got := pipelineMarkerRawUnwrapToDetach5To20ms.Load(); got != 1 {
		t.Fatalf("5_20ms=%d, want 1", got)
	}
	if got := pipelineMarkerRawUnwrapToDetach20To100ms.Load(); got != 1 {
		t.Fatalf("20_100ms=%d, want 1", got)
	}
	if got := pipelineMarkerRawUnwrapToDetachGe100ms.Load(); got != 1 {
		t.Fatalf("ge100ms=%d, want 1", got)
	}
}

func TestVisionRawUnwrapWarningTimestampHelpers(t *testing.T) {
	clearSyncMap(&pipelineVisionRawUnwrapUnixByConn)
	clearSyncMap(&pipelineVisionDetachUnixByConn)
	conn := &tls.DeferredRustConn{}

	storeVisionRawUnwrapWarningTimestamp(conn, 123)
	storeVisionRawUnwrapWarningTimestamp(conn, 456) // keep first
	if got, ok := consumeVisionRawUnwrapWarningTimestamp(conn); !ok || got != 123 {
		t.Fatalf("consume raw unwrap got (%d,%v), want (123,true)", got, ok)
	}
	if _, ok := consumeVisionRawUnwrapWarningTimestamp(conn); ok {
		t.Fatal("second consume should be empty")
	}

	storeVisionDetachTimestamp(conn, 789)
	if got, ok := consumeVisionDetachTimestamp(conn); !ok || got != 789 {
		t.Fatalf("consume detach got (%d,%v), want (789,true)", got, ok)
	}
	if _, ok := consumeVisionDetachTimestamp(conn); ok {
		t.Fatal("second detach consume should be empty")
	}
}

func TestRecordPipelineFlowMix(t *testing.T) {
	pipelineMarkerFlowMuxUDP.Store(0)
	pipelineMarkerFlowPureTCP.Store(0)
	pipelineMarkerFlowMuxTCP.Store(0)
	pipelineMarkerFlowOther.Store(0)

	RecordPipelineFlowMix(context.Background(), xnet.Network_TCP, xnet.Network_UDP)
	RecordPipelineFlowMix(context.Background(), xnet.Network_TCP, xnet.Network_Unknown)
	RecordPipelineFlowMix(context.Background(), xnet.Network_TCP, xnet.Network_TCP)
	RecordPipelineFlowMix(context.Background(), xnet.Network_UDP, xnet.Network_UDP)

	if got := pipelineMarkerFlowMuxUDP.Load(); got != 1 {
		t.Fatalf("mux_udp=%d, want 1", got)
	}
	if got := pipelineMarkerFlowPureTCP.Load(); got != 1 {
		t.Fatalf("pure_tcp=%d, want 1", got)
	}
	if got := pipelineMarkerFlowMuxTCP.Load(); got != 1 {
		t.Fatalf("mux_tcp=%d, want 1", got)
	}
	if got := pipelineMarkerFlowOther.Load(); got != 1 {
		t.Fatalf("other=%d, want 1", got)
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

func resetSpliceHistogramCounters() {
	pipelineMarkerSpliceBytesLt4K.Store(0)
	pipelineMarkerSpliceBytes4KTo64K.Store(0)
	pipelineMarkerSpliceBytes64KTo1M.Store(0)
	pipelineMarkerSpliceBytesGe1M.Store(0)
	pipelineMarkerSpliceDurLt1ms.Store(0)
	pipelineMarkerSpliceDur1To5ms.Store(0)
	pipelineMarkerSpliceDur5To20ms.Store(0)
	pipelineMarkerSpliceDur20To100ms.Store(0)
	pipelineMarkerSpliceDurGe100ms.Store(0)
}

func resetRawUnwrapHistogramCounters() {
	pipelineMarkerRawUnwrapToDetachLt5ms.Store(0)
	pipelineMarkerRawUnwrapToDetach5To20ms.Store(0)
	pipelineMarkerRawUnwrapToDetach20To100ms.Store(0)
	pipelineMarkerRawUnwrapToDetachGe100ms.Store(0)
}

func clearSyncMap(m *sync.Map) {
	m.Range(func(k, _ any) bool {
		m.Delete(k)
		return true
	})
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
