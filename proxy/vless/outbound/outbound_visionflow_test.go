package outbound

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/proxy/vless"
)

func TestContextWithOutboundVisionFlow(t *testing.T) {
	tests := []struct {
		name string
		flow string
		want bool
	}{
		{name: "empty flow", flow: "", want: false},
		{name: "vision flow", flow: vless.XRV, want: true},
		{name: "vision udp443 flow", flow: vless.XRV + "-udp443", want: true},
		{name: "non vision flow", flow: "xtls-rprx-direct", want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := contextWithOutboundVisionFlow(context.Background(), tc.flow)
			if got := session.VisionFlowFromContext(ctx); got != tc.want {
				t.Fatalf("VisionFlowFromContext() = %v, want %v for flow %q", got, tc.want, tc.flow)
			}
		})
	}
}
