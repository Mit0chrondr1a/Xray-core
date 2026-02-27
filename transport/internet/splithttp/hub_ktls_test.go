package splithttp

import (
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
)

func TestXHTTPKTLSListenerEligible(t *testing.T) {
	basePort := net.Port(443)

	tests := []struct {
		name              string
		port              net.Port
		socketSettings    *internet.SocketConfig
		nativeAvailable   bool
		fullKTLSSupported bool
		want              bool
	}{
		{
			name:              "unix socket port",
			port:              net.Port(0),
			nativeAvailable:   true,
			fullKTLSSupported: true,
			want:              false,
		},
		{
			name:              "native unavailable",
			port:              basePort,
			nativeAvailable:   false,
			fullKTLSSupported: true,
			want:              false,
		},
		{
			name:              "full ktls unsupported",
			port:              basePort,
			nativeAvailable:   true,
			fullKTLSSupported: false,
			want:              false,
		},
		{
			name:              "proxy protocol enabled",
			port:              basePort,
			socketSettings:    &internet.SocketConfig{AcceptProxyProtocol: true},
			nativeAvailable:   true,
			fullKTLSSupported: true,
			want:              false,
		},
		{
			name:              "eligible",
			port:              basePort,
			nativeAvailable:   true,
			fullKTLSSupported: true,
			want:              true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := xhttpKTLSListenerEligible(tc.port, tc.socketSettings, tc.nativeAvailable, tc.fullKTLSSupported)
			if got != tc.want {
				t.Fatalf("xhttpKTLSListenerEligible() = %v, want %v", got, tc.want)
			}
		})
	}
}
