package router

import (
	"regexp"
	"sync/atomic"
	"testing"

	"github.com/xtls/xray-core/common/net"
)

type processMatcherTestContext struct {
	sourceIPs  []net.IP
	sourcePort net.Port
	network    net.Network
}

func (c processMatcherTestContext) GetInboundTag() string            { return "" }
func (c processMatcherTestContext) GetSourceIPs() []net.IP           { return c.sourceIPs }
func (c processMatcherTestContext) GetSourcePort() net.Port          { return c.sourcePort }
func (c processMatcherTestContext) GetTargetIPs() []net.IP           { return nil }
func (c processMatcherTestContext) GetTargetPort() net.Port          { return 0 }
func (c processMatcherTestContext) GetLocalIPs() []net.IP            { return nil }
func (c processMatcherTestContext) GetLocalPort() net.Port           { return 0 }
func (c processMatcherTestContext) GetTargetDomain() string          { return "" }
func (c processMatcherTestContext) GetNetwork() net.Network          { return c.network }
func (c processMatcherTestContext) GetProtocol() string              { return "" }
func (c processMatcherTestContext) GetUser() string                  { return "" }
func (c processMatcherTestContext) GetVlessRoute() net.Port          { return 0 }
func (c processMatcherTestContext) GetAttributes() map[string]string { return nil }
func (c processMatcherTestContext) GetSkipDNSResolve() bool          { return false }

func TestAttributeMatcherMatchCaseInsensitiveFallback(t *testing.T) {
	m := &AttributeMatcher{
		configuredKeys: map[string]*regexp.Regexp{
			"custom": regexp.MustCompile(`^peach$`),
		},
	}

	if !m.Match(map[string]string{"Custom": "peach"}) {
		t.Fatal("expected case-insensitive attribute match to succeed")
	}
}

func TestProcessNameMatcherCachesProcessLookup(t *testing.T) {
	originalFindProcess := findProcess
	defer func() {
		findProcess = originalFindProcess
	}()

	var calls int32
	findProcess = func(dest net.Destination) (int, string, string, error) {
		atomic.AddInt32(&calls, 1)
		return 100, "curl", "/usr/bin/curl", nil
	}

	matcher := NewProcessNameMatcher([]string{"curl"})
	ctx := processMatcherTestContext{
		sourceIPs:  []net.IP{net.ParseIP("127.0.0.1")},
		sourcePort: net.Port(12345),
		network:    net.Network_TCP,
	}

	if !matcher.Apply(ctx) {
		t.Fatal("expected first apply to match")
	}
	if !matcher.Apply(ctx) {
		t.Fatal("expected second apply to match")
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("expected process lookup to be cached, got %d calls", got)
	}
}
