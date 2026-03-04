package splithttp

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
)

type dialerOpenStreamStub struct {
	openStreamCalls int
}

func (s *dialerOpenStreamStub) IsClosed() bool {
	return false
}

func (s *dialerOpenStreamStub) OpenStream(context.Context, string, string, io.Reader, bool) (io.ReadCloser, xnet.Addr, xnet.Addr, error) {
	s.openStreamCalls++
	return io.NopCloser(strings.NewReader("")), nil, nil, nil
}

func (s *dialerOpenStreamStub) PostPacket(context.Context, string, string, string, io.Reader, int64) error {
	return nil
}

type dialerXmuxConnStub struct{}

func (dialerXmuxConnStub) IsClosed() bool {
	return false
}

func TestDialPacketUpValidationErrorReleasesXmuxUsage(t *testing.T) {
	origGetHTTPClientFn := getHTTPClientFn
	defer func() {
		getHTTPClientFn = origGetHTTPClientFn
	}()

	stubClient := &dialerOpenStreamStub{}
	xmuxClient := &XmuxClient{XmuxConn: dialerXmuxConnStub{}}

	getHTTPClientFn = func(context.Context, xnet.Destination, *internet.MemoryStreamConfig) (DialerClient, *XmuxClient) {
		return stubClient, xmuxClient
	}

	streamSettings := &internet.MemoryStreamConfig{
		ProtocolSettings: &Config{
			Mode: "packet-up",
			ScMaxEachPostBytes: &RangeConfig{
				From: buf.Size,
				To:   buf.Size,
			},
		},
	}
	dest := xnet.TCPDestination(xnet.DomainAddress("example.com"), xnet.Port(443))

	_, err := Dial(context.Background(), dest, streamSettings)
	if err == nil {
		t.Fatal("Dial() error = nil, want packet-up validation error")
	}
	if !strings.Contains(err.Error(), "scMaxEachPostBytes") {
		t.Fatalf("Dial() error = %q, want scMaxEachPostBytes validation failure", err.Error())
	}
	if got := xmuxClient.OpenUsage.Load(); got != 0 {
		t.Fatalf("xmux OpenUsage = %d, want 0 after Dial() validation failure", got)
	}
	if stubClient.openStreamCalls != 1 {
		t.Fatalf("OpenStream calls = %d, want 1", stubClient.openStreamCalls)
	}
}
