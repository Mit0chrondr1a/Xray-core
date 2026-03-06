package outbound

import (
	gonet "net"
	"testing"

	"github.com/xtls/xray-core/common/native"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/transport/internet/tls"
)

func TestGetVisionBuffersForRustConn(t *testing.T) {
	t.Run("non xrv flow ignored", func(t *testing.T) {
		handled, input, rawInput, err := getVisionBuffersForRustConn(&tls.RustConn{}, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if handled {
			t.Fatal("expected non-XRV flow to skip RustConn handling")
		}
		if input != nil || rawInput != nil {
			t.Fatal("expected nil buffers when flow is not XRV")
		}
	})

	t.Run("xrv non rust conn ignored", func(t *testing.T) {
		client, server := gonet.Pipe()
		defer client.Close()
		defer server.Close()

		handled, input, rawInput, err := getVisionBuffersForRustConn(client, vless.XRV)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if handled {
			t.Fatal("expected non-Rust conn to skip RustConn handling")
		}
		if input != nil || rawInput != nil {
			t.Fatal("expected nil buffers for non-Rust conn")
		}
	})

	t.Run("xrv rust conn without full ktls rejected", func(t *testing.T) {
		handled, input, rawInput, err := getVisionBuffersForRustConn(&tls.RustConn{}, vless.XRV)
		if !handled {
			t.Fatal("expected RustConn branch to be handled")
		}
		if err == nil {
			t.Fatal("expected error for RustConn without full kTLS")
		}
		if input != nil || rawInput != nil {
			t.Fatal("expected nil buffers when RustConn is rejected")
		}
	})

	t.Run("xrv rust conn with full ktls rejected", func(t *testing.T) {
		client, server := gonet.Pipe()
		defer server.Close()

		rc, err := tls.NewRustConnChecked(client, &native.TlsResult{
			KtlsTx:  true,
			KtlsRx:  true,
			Version: 0x0304,
		}, "example.com")
		if err != nil {
			t.Fatalf("failed to create test RustConn: %v", err)
		}
		defer rc.Close()

		handled, input, rawInput, err := getVisionBuffersForRustConn(rc, vless.XRV)
		if !handled {
			t.Fatal("expected RustConn branch to be handled")
		}
		if err == nil {
			t.Fatal("expected Vision to reject RustConn with active kTLS")
		}
		if input != nil || rawInput != nil {
			t.Fatal("expected nil buffers when Vision rejects RustConn")
		}
	})
}
