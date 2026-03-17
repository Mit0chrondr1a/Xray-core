package proxy

import (
	"bytes"
	"context"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/native"
)

type visionUnpadSnapshot struct {
	RemainingCommand int32
	RemainingContent int32
	RemainingPadding int32
	CurrentCommand   int32
}

type visionFilterSnapshot struct {
	RemainingServerHello    int32
	NumberOfPacketsToFilter int32
	Cipher                  uint16
	IsTLS                   bool
	IsTLS12OrAbove          bool
	EnableXtls              bool
}

func requireNativeVisionParity(t *testing.T) {
	t.Helper()
	if !native.Available() {
		t.Skip("native Rust library not available")
	}
}

func chunkBytes(data []byte, splits ...int) [][]byte {
	chunks := make([][]byte, 0, len(splits)+1)
	start := 0
	for _, size := range splits {
		end := start + size
		if end > len(data) {
			end = len(data)
		}
		chunks = append(chunks, append([]byte(nil), data[start:end]...))
		start = end
		if start >= len(data) {
			break
		}
	}
	if start < len(data) {
		chunks = append(chunks, append([]byte(nil), data[start:]...))
	}
	if len(chunks) == 0 {
		chunks = append(chunks, []byte{})
	}
	return chunks
}

func appendVisionFrame(dst []byte, uuid []byte, command byte, content, padding []byte) []byte {
	if len(uuid) > 0 {
		dst = append(dst, uuid...)
	}
	dst = append(dst,
		command,
		byte(len(content)>>8),
		byte(len(content)),
		byte(len(padding)>>8),
		byte(len(padding)),
	)
	dst = append(dst, content...)
	dst = append(dst, padding...)
	return dst
}

func goUnpadSnapshot(ts *TrafficState, isUplink bool) visionUnpadSnapshot {
	if isUplink {
		return visionUnpadSnapshot{
			RemainingCommand: ts.Inbound.RemainingCommand,
			RemainingContent: ts.Inbound.RemainingContent,
			RemainingPadding: ts.Inbound.RemainingPadding,
			CurrentCommand:   int32(ts.Inbound.CurrentCommand),
		}
	}
	return visionUnpadSnapshot{
		RemainingCommand: ts.Outbound.RemainingCommand,
		RemainingContent: ts.Outbound.RemainingContent,
		RemainingPadding: ts.Outbound.RemainingPadding,
		CurrentCommand:   int32(ts.Outbound.CurrentCommand),
	}
}

func nativeUnpadSnapshot(state *native.VisionUnpadState) visionUnpadSnapshot {
	return visionUnpadSnapshot{
		RemainingCommand: state.RemainingCommand,
		RemainingContent: state.RemainingContent,
		RemainingPadding: state.RemainingPadding,
		CurrentCommand:   state.CurrentCommand,
	}
}

func runGoVisionUnpadChunk(t *testing.T, ts *TrafficState, isUplink bool, chunk []byte) ([]byte, visionUnpadSnapshot) {
	t.Helper()
	b := buf.New()
	if len(chunk) > 0 {
		b.Write(chunk)
	}
	out := XtlsUnpadding(b, ts, isUplink, context.Background())
	if out == nil {
		t.Fatal("XtlsUnpadding returned nil")
	}
	got := append([]byte(nil), out.Bytes()...)
	out.Release()
	return got, goUnpadSnapshot(ts, isUplink)
}

func runNativeVisionUnpadChunk(t *testing.T, state *native.VisionUnpadState, uuid, chunk []byte) ([]byte, visionUnpadSnapshot) {
	t.Helper()
	out := make([]byte, max(1, len(chunk)))
	n, err := native.VisionUnpad(chunk, state, uuid, out)
	if err != nil {
		t.Fatalf("VisionUnpad failed: %v", err)
	}
	return append([]byte(nil), out[:n]...), nativeUnpadSnapshot(state)
}

func filterSnapshotFromTrafficState(ts *TrafficState) visionFilterSnapshot {
	return visionFilterSnapshot{
		RemainingServerHello:    ts.RemainingServerHello,
		NumberOfPacketsToFilter: int32(ts.NumberOfPacketToFilter),
		Cipher:                  ts.Cipher,
		IsTLS:                   ts.IsTLS,
		IsTLS12OrAbove:          ts.IsTLS12orAbove,
		EnableXtls:              ts.EnableXtls,
	}
}

func filterSnapshotFromNative(state *native.VisionFilterState) visionFilterSnapshot {
	return visionFilterSnapshot{
		RemainingServerHello:    state.RemainingServerHello,
		NumberOfPacketsToFilter: state.NumberOfPacketsToFilter,
		Cipher:                  state.Cipher,
		IsTLS:                   state.IsTLS,
		IsTLS12OrAbove:          state.IsTLS12orAbove,
		EnableXtls:              state.EnableXtls,
	}
}

func buildMultiBuffer(chunks ...[]byte) buf.MultiBuffer {
	mb := make(buf.MultiBuffer, 0, len(chunks))
	for _, chunk := range chunks {
		b := buf.New()
		if len(chunk) > 0 {
			b.Write(chunk)
		}
		mb = append(mb, b)
	}
	return mb
}

func makeServerHello(totalLen int, sessionIDLen byte, cipher uint16, includeTLS13 bool) []byte {
	if totalLen < 80 {
		totalLen = 80
	}
	data := make([]byte, totalLen)
	data[0] = 0x16
	data[1] = 0x03
	data[2] = 0x03
	recordLen := totalLen - 5
	data[3] = byte(recordLen >> 8)
	data[4] = byte(recordLen)
	data[5] = TlsHandshakeTypeServerHello
	data[43] = sessionIDLen
	csOffset := 43 + min(int32(sessionIDLen), 32) + 1
	if csOffset+1 < int32(len(data)) {
		data[csOffset] = byte(cipher >> 8)
		data[csOffset+1] = byte(cipher)
	}
	if includeTLS13 {
		start := len(data) - len(Tls13SupportedVersions) - 2
		if start < 46 {
			start = 46
		}
		copy(data[start:], Tls13SupportedVersions)
	}
	return data
}

func TestNativeVisionIsCompleteRecordParity(t *testing.T) {
	requireNativeVisionParity(t)

	tests := []struct {
		name   string
		chunks [][]byte
	}{
		{
			name:   "empty",
			chunks: nil,
		},
		{
			name: "single-valid",
			chunks: [][]byte{
				{0x17, 0x03, 0x03, 0x00, 0x03, 0xAA, 0xBB, 0xCC},
			},
		},
		{
			name: "split-valid",
			chunks: [][]byte{
				{0x17, 0x03},
				{0x03, 0x00, 0x03, 0xAA, 0xBB, 0xCC},
			},
		},
		{
			name: "multiple-records",
			chunks: [][]byte{
				{0x17, 0x03, 0x03, 0x00, 0x02, 0xAA, 0xBB, 0x17, 0x03, 0x03, 0x00, 0x01, 0xCC},
			},
		},
		{
			name: "truncated",
			chunks: [][]byte{
				{0x17, 0x03, 0x03, 0x00, 0x05, 0xAA, 0xBB},
			},
		},
		{
			name: "wrong-header",
			chunks: [][]byte{
				{0x16, 0x03, 0x03, 0x00, 0x01, 0xFF},
			},
		},
		{
			name: "header-only-zero-length-record",
			chunks: [][]byte{
				{0x17, 0x03, 0x03, 0x00, 0x00},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mb := buildMultiBuffer(tc.chunks...)
			goResult := IsCompleteRecord(mb)
			buf.ReleaseMulti(mb)

			nativeInput := bytes.Join(tc.chunks, nil)
			nativeResult := native.VisionIsCompleteRecord(nativeInput)

			if nativeResult != goResult {
				t.Fatalf("VisionIsCompleteRecord parity mismatch: native=%v go=%v input=%x", nativeResult, goResult, nativeInput)
			}
		})
	}
}

func TestNativeVisionFilterTlsParity(t *testing.T) {
	requireNativeVisionParity(t)

	tests := []struct {
		name   string
		chunks [][]byte
	}{
		{
			name: "client-hello",
			chunks: [][]byte{
				{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00},
			},
		},
		{
			name:   "tls13-split",
			chunks: chunkBytes(makeServerHello(96, 0, 0x1301, true), 40),
		},
		{
			name:   "tls12-split",
			chunks: chunkBytes(makeServerHello(96, 0, 0x1301, false), 48),
		},
		{
			name: "large-session-id-clamp",
			chunks: [][]byte{
				makeServerHello(79, 0xFF, 0x1301, false),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			goState := NewTrafficState(nil)
			goState.NumberOfPacketToFilter = 8

			nativeState := &native.VisionFilterState{
				RemainingServerHello:    -1,
				NumberOfPacketsToFilter: 8,
			}

			for i, chunk := range tc.chunks {
				mb := buildMultiBuffer(chunk)
				XtlsFilterTls(mb, goState, context.Background())
				buf.ReleaseMulti(mb)

				_ = native.VisionFilterTls(chunk, nativeState)

				goSnap := filterSnapshotFromTrafficState(goState)
				nativeSnap := filterSnapshotFromNative(nativeState)
				if nativeSnap != goSnap {
					t.Fatalf("chunk %d parity mismatch:\n  native=%+v\n  go=%+v", i, nativeSnap, goSnap)
				}
			}
		})
	}
}

func TestNativeVisionUnpadParity(t *testing.T) {
	requireNativeVisionParity(t)

	uuid := []byte("0123456789ABCDEF")

	tests := []struct {
		name      string
		chunks    [][]byte
		wantFinal []byte
	}{
		{
			name:      "uuid-mismatch-passthrough",
			chunks:    [][]byte{[]byte("this does not start with the vision uuid")},
			wantFinal: []byte("this does not start with the vision uuid"),
		},
		{
			name: func() string { return "continue-then-end-across-chunks" }(),
			chunks: func() [][]byte {
				data := make([]byte, 0)
				data = appendVisionFrame(data, uuid, CommandPaddingContinue, []byte("he"), []byte{0xAA, 0xBB})
				data = appendVisionFrame(data, nil, CommandPaddingEnd, []byte("llo"), []byte{0xCC})
				return chunkBytes(data, 21, 4, 3)
			}(),
			wantFinal: []byte("hello"),
		},
		{
			name: func() string { return "direct-with-trailing-bytes" }(),
			chunks: func() [][]byte {
				data := make([]byte, 0)
				data = appendVisionFrame(data, uuid, CommandPaddingDirect, []byte("abc"), nil)
				data = append(data, []byte("tail")...)
				return chunkBytes(data, 21, 3)
			}(),
			wantFinal: []byte("abctail"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			goState := NewTrafficState(append([]byte(nil), uuid...))
			nativeState := native.NewVisionUnpadState()

			var goTotal []byte
			var nativeTotal []byte
			for i, chunk := range tc.chunks {
				goOut, goSnap := runGoVisionUnpadChunk(t, goState, true, chunk)
				nativeOut, nativeSnap := runNativeVisionUnpadChunk(t, nativeState, uuid, chunk)
				if !bytes.Equal(nativeOut, goOut) {
					t.Fatalf("chunk %d output mismatch:\n  native=%x\n  go=%x", i, nativeOut, goOut)
				}
				if nativeSnap != goSnap {
					t.Fatalf("chunk %d state mismatch:\n  native=%+v\n  go=%+v", i, nativeSnap, goSnap)
				}
				nativeTotal = append(nativeTotal, nativeOut...)
				goTotal = append(goTotal, goOut...)
			}

			if !bytes.Equal(nativeTotal, goTotal) {
				t.Fatalf("final output mismatch:\n  native=%x\n  go=%x", nativeTotal, goTotal)
			}
			if !bytes.Equal(goTotal, tc.wantFinal) {
				t.Fatalf("final output=%q, want %q", string(goTotal), string(tc.wantFinal))
			}
		})
	}
}
