package freedom

import (
	"bytes"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
)

type captureWriter struct {
	writes [][]byte
}

func (w *captureWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	var payload []byte
	for _, b := range mb {
		if b == nil {
			continue
		}
		payload = append(payload, b.Bytes()...)
	}
	w.writes = append(w.writes, payload)
	buf.ReleaseMulti(mb)
	return nil
}

func TestNoisePacketWriterSkipDNS53(t *testing.T) {
	tests := []struct {
		name         string
		overridePort net.Port
		destPort     net.Port
		wantWrites   int
	}{
		{
			name:         "skip_dns53_by_override",
			overridePort: 53,
			wantWrites:   1,
		},
		{
			name:       "skip_dns53_by_dest",
			destPort:   53,
			wantWrites: 1,
		},
		{
			name:       "skip_dns853_by_dest",
			destPort:   853,
			wantWrites: 1,
		},
		{
			name:       "apply_noise_for_non_dns_port",
			wantWrites: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wrapped := &captureWriter{}
			writer := &NoisePacketWriter{
				Writer: wrapped,
				noises: []*Noise{
					{Packet: []byte{0x11, 0x22}, ApplyTo: "ip"},
				},
				firstWrite: true,
				UDPOverride: net.Destination{
					Port: tt.overridePort,
				},
				DestPort:   tt.destPort,
				remoteAddr: net.IPAddress([]byte{1, 1, 1, 1}),
			}

			payload := []byte{0xAA, 0xBB}
			err := writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(payload)})
			if err != nil {
				t.Fatalf("WriteMultiBuffer() error = %v", err)
			}

			if got := len(wrapped.writes); got != tt.wantWrites {
				t.Fatalf("writes = %d, want %d", got, tt.wantWrites)
			}

			if tt.wantWrites == 1 {
				if !bytes.Equal(wrapped.writes[0], payload) {
					t.Fatalf("single write payload = %v, want %v", wrapped.writes[0], payload)
				}
				return
			}

			if !bytes.Equal(wrapped.writes[0], []byte{0x11, 0x22}) {
				t.Fatalf("noise payload = %v, want %v", wrapped.writes[0], []byte{0x11, 0x22})
			}
			if !bytes.Equal(wrapped.writes[1], payload) {
				t.Fatalf("data payload = %v, want %v", wrapped.writes[1], payload)
			}
		})
	}
}
