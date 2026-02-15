package proxy

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common/buf"
)

func TestXtlsFilterTls_LargeSessionIdLen_NoPanic(t *testing.T) {
	// Craft a minimal TLS ServerHello with sessionIdLen=255 to trigger the
	// out-of-bounds read that existed before the clamp fix.
	// TLS record header: content_type(22) + version(0x0303) + length(74)
	// Handshake header: type(2=ServerHello) + ...
	// Total: we need at least 79 bytes in the buffer.
	hello := make([]byte, 79)
	// Record header
	hello[0] = 0x16 // content_type = Handshake
	hello[1] = 0x03 // version major
	hello[2] = 0x03 // version minor
	hello[3] = 0x00 // record length high byte
	hello[4] = 0x4A // record length low byte (74)
	// Handshake type
	hello[5] = 0x02 // ServerHello
	// Bytes 6..42: handshake length + server version + random (fill zeros)
	// Byte 43: session_id_length = 255 (malicious)
	hello[43] = 0xFF

	b := buf.New()
	b.Write(hello)

	ts := &TrafficState{
		NumberOfPacketToFilter: 8,
	}

	// This should NOT panic even with sessionIdLen=255
	XtlsFilterTls(buf.MultiBuffer{b}, ts, context.Background())

	if !ts.IsTLS {
		t.Error("expected IsTLS to be set")
	}
	if !ts.IsTLS12orAbove {
		t.Error("expected IsTLS12orAbove to be set")
	}
}

func TestXtlsFilterTls_NormalSessionId(t *testing.T) {
	// Craft a valid TLS ServerHello with sessionIdLen=32 and a known cipher suite.
	hello := make([]byte, 80)
	// Record header
	hello[0] = 0x16
	hello[1] = 0x03
	hello[2] = 0x03
	hello[3] = 0x00
	hello[4] = 0x4B // record length = 75
	// Handshake type
	hello[5] = 0x02 // ServerHello
	// Byte 43: session_id_length = 32
	hello[43] = 32
	// Cipher suite at offset 43+32+1=76, 2 bytes: TLS_AES_128_GCM_SHA256 = 0x13,0x01
	hello[76] = 0x13
	hello[77] = 0x01

	b := buf.New()
	b.Write(hello)

	ts := &TrafficState{
		NumberOfPacketToFilter: 8,
	}

	XtlsFilterTls(buf.MultiBuffer{b}, ts, context.Background())

	if ts.Cipher != 0x1301 {
		t.Errorf("expected cipher 0x1301, got 0x%04X", ts.Cipher)
	}
}
