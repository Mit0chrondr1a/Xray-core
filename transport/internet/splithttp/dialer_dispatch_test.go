package splithttp

import (
	"context"
	"io"
	"testing"

	xnet "github.com/xtls/xray-core/common/net"
)

type dispatchStrategyStub struct{}

func (dispatchStrategyStub) IsClosed() bool { return false }
func (dispatchStrategyStub) OpenStream(context.Context, string, string, io.Reader, bool) (io.ReadCloser, xnet.Addr, xnet.Addr, error) {
	return nil, nil, nil, nil
}
func (dispatchStrategyStub) PostPacket(context.Context, string, string, string, io.Reader, int64) error {
	return nil
}

func TestShouldWaitForPacketPostDispatch(t *testing.T) {
	if !shouldWaitForPacketPostDispatch(&DefaultDialerClient{httpVersion: "1.1"}) {
		t.Fatal("HTTP/1.1 uploads should wait for request dispatch")
	}
	if shouldWaitForPacketPostDispatch(&DefaultDialerClient{httpVersion: "2"}) {
		t.Fatal("HTTP/2 uploads should not wait for request dispatch")
	}
	if shouldWaitForPacketPostDispatch(&DefaultDialerClient{httpVersion: "3"}) {
		t.Fatal("HTTP/3 uploads should not wait for request dispatch")
	}
	if shouldWaitForPacketPostDispatch(dispatchStrategyStub{}) {
		t.Fatal("non-default dialer clients should preserve non-blocking behavior")
	}
}
