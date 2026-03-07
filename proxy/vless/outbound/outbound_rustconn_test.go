package outbound

import (
	"bytes"
	gonet "net"
	"reflect"
	"testing"
	"unsafe"

	"github.com/xtls/xray-core/common/native"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/vless/encryption"
	"github.com/xtls/xray-core/transport/internet/tls"
)

func TestBuildVisionTransitionSource(t *testing.T) {
	t.Run("common conn supported path drains buffered state", func(t *testing.T) {
		client, server := gonet.Pipe()
		defer client.Close()
		defer server.Close()

		commonConn := encryption.NewCommonConn(client, false)
		setCommonConnBufferedState(t, commonConn, []byte("plain"), []byte("raw"))

		source, err := proxy.BuildVisionTransitionSource(commonConn, commonConn)
		if err != nil {
			t.Fatalf("BuildVisionTransitionSource() error = %v", err)
		}
		if source == nil {
			t.Fatal("expected transition source for CommonConn")
		}

		plain, rawAhead := source.DrainBufferedState()
		if got := string(plain); got != "plain" {
			t.Fatalf("plaintext = %q, want %q", got, "plain")
		}
		if got := string(rawAhead); got != "raw" {
			t.Fatalf("rawAhead = %q, want %q", got, "raw")
		}
	})

	t.Run("public common conn wins over stale inner conn", func(t *testing.T) {
		client, server := gonet.Pipe()
		defer client.Close()
		defer server.Close()

		commonConn := encryption.NewCommonConn(client, false)

		source, err := proxy.BuildVisionTransitionSource(commonConn, client)
		if err != nil {
			t.Fatalf("BuildVisionTransitionSource() error = %v", err)
		}
		if source == nil {
			t.Fatal("expected transition source for outer CommonConn")
		}
		if source.Conn() != commonConn {
			t.Fatal("expected transition source to keep outer CommonConn as public conn")
		}
	})

	t.Run("plain net conn rejected", func(t *testing.T) {
		client, server := gonet.Pipe()
		defer client.Close()
		defer server.Close()

		source, err := proxy.BuildVisionTransitionSource(client, client)
		if err == nil {
			t.Fatal("expected plain net.Conn to be rejected")
		}
		if source != nil {
			t.Fatal("expected nil transition source for unsupported conn")
		}
	})

	t.Run("rust conn without full ktls rejected", func(t *testing.T) {
		source, err := proxy.BuildVisionTransitionSource(nil, &tls.RustConn{})
		if err == nil {
			t.Fatal("expected error for RustConn without full kTLS")
		}
		if source != nil {
			t.Fatal("expected nil transition source when RustConn is rejected")
		}
	})

	t.Run("rust conn with full ktls rejected", func(t *testing.T) {
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

		source, err := proxy.BuildVisionTransitionSource(client, rc)
		if err == nil {
			t.Fatal("expected Vision to reject RustConn with active kTLS")
		}
		if source != nil {
			t.Fatal("expected nil transition source when Vision rejects RustConn")
		}
	})
}

func setCommonConnBufferedState(t *testing.T, conn *encryption.CommonConn, plain []byte, raw []byte) {
	t.Helper()

	connValue := reflect.ValueOf(conn).Elem()

	inputField := connValue.FieldByName("input")
	inputReader := bytes.NewReader(plain)
	reflect.NewAt(inputField.Type(), unsafe.Pointer(inputField.UnsafeAddr())).Elem().Set(reflect.ValueOf(*inputReader))

	rawField := connValue.FieldByName("rawInput")
	var rawBuffer bytes.Buffer
	rawBuffer.Write(raw)
	reflect.NewAt(rawField.Type(), unsafe.Pointer(rawField.UnsafeAddr())).Elem().Set(reflect.ValueOf(rawBuffer))
}
