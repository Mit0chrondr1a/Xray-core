package mux_test

import (
	"bytes"
	"testing"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
)

func BenchmarkFrameWrite(b *testing.B) {
	frame := mux.FrameMetadata{
		Target:        net.TCPDestination(net.DomainAddress("www.example.com"), net.Port(80)),
		SessionID:     1,
		SessionStatus: mux.SessionStatusNew,
	}
	writer := buf.New()
	defer writer.Release()

	for i := 0; i < b.N; i++ {
		common.Must(frame.WriteTo(writer))
		writer.Clear()
	}
}

func TestFrameMetadataDNSRoundTrip(t *testing.T) {
	frame := mux.FrameMetadata{
		Target:        net.UDPDestination(net.IPAddress([]byte{1, 1, 1, 1}), net.Port(853)),
		SessionID:     7,
		SessionStatus: mux.SessionStatusNew,
		Option:        mux.OptionData,
		GlobalID:      [8]byte{1, 2, 3, 4, 5, 6, 7, 8},
		DNSFlowClass:  session.DNSFlowClassUDPControl,
		DNSPlane:      session.DNSPlaneMuxXUDP,
	}
	writer := buf.New()
	writer.UDP = &frame.Target
	defer writer.Release()

	common.Must(frame.WriteTo(writer))

	var got mux.FrameMetadata
	common.Must(got.Unmarshal(bytes.NewReader(writer.Bytes()), false))
	if got.Target != frame.Target {
		t.Fatalf("target=%v, want %v", got.Target, frame.Target)
	}
	if got.GlobalID != frame.GlobalID {
		t.Fatalf("globalID=%v, want %v", got.GlobalID, frame.GlobalID)
	}
	if got.DNSFlowClass != frame.DNSFlowClass {
		t.Fatalf("dnsFlowClass=%v, want %v", got.DNSFlowClass, frame.DNSFlowClass)
	}
	if got.DNSPlane != frame.DNSPlane {
		t.Fatalf("dnsPlane=%v, want %v", got.DNSPlane, frame.DNSPlane)
	}
}
