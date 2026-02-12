package conf_test

import (
	"testing"

	"github.com/xtls/xray-core/common"
	. "github.com/xtls/xray-core/infra/conf"
	http_header "github.com/xtls/xray-core/transport/internet/headers/http"
)

func TestAuthenticatorRequestStrictMarker(t *testing.T) {
	config, err := (&AuthenticatorRequest{
		Strict: true,
	}).Build()
	common.Must(err)

	found := false
	for _, header := range config.GetHeader() {
		if header.GetName() == http_header.StrictMatchMarkerHeaderName {
			found = true
			if len(header.GetValue()) != 1 || header.GetValue()[0] != http_header.StrictMatchMarkerHeaderValue {
				t.Fatalf("unexpected strict marker values: %v", header.GetValue())
			}
		}
	}
	if !found {
		t.Fatal("expected strict marker header")
	}
}

func TestAuthenticatorRequestWithoutStrictMarker(t *testing.T) {
	config, err := (&AuthenticatorRequest{}).Build()
	common.Must(err)

	for _, header := range config.GetHeader() {
		if header.GetName() == http_header.StrictMatchMarkerHeaderName {
			t.Fatal("strict marker should not exist when strict mode is disabled")
		}
	}
}
