package proxy

import (
	"context"
	"sync"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/native"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/pipeline"
	"github.com/xtls/xray-core/transport/internet/ebpf"
	"github.com/xtls/xray-core/transport/internet/tls"
)

var (
	pipelineCapsOnce sync.Once
	pipelineCaps     *pipeline.CapabilityCache
)

func computePipelineCapabilities() pipeline.CapabilitySummary {
	summary := native.CapabilitiesSummary()
	// Merge with Go-side probes to avoid regressions while Rust probe is conservative.
	if goCaps := ebpf.GetCapabilities(); goCaps.SockmapSupported {
		summary.SockmapSupported = true
	}
	if tls.NativeFullKTLSSupported() {
		summary.KTLSSupported = true
	}
	// Splice is always available on Linux TCP; keep default true.
	if summary.SpliceSupported == false {
		summary.SpliceSupported = true
	}
	return summary
}

func pipelineCapabilities() pipeline.CapabilitySummary {
	pipelineCapsOnce.Do(func() {
		summary := computePipelineCapabilities()
		pipelineCaps = pipeline.NewCapabilityCache(summary)
		errors.LogInfo(context.Background(),
			"proxy markers[kind=pipeline-capabilities]: ",
			"ktls_supported=", summary.KTLSSupported,
			" sockmap_supported=", summary.SockmapSupported,
			" splice_supported=", summary.SpliceSupported)
	})
	return pipelineCaps.Summary()
}

// RefreshPipelineCapabilities re-probes acceleration capabilities and updates the cache.
func RefreshPipelineCapabilities() pipeline.CapabilitySummary {
	summary := computePipelineCapabilities()
	pipelineCapsOnce.Do(func() {
		pipelineCaps = pipeline.NewCapabilityCache(summary)
	})
	pipelineCaps.Update(summary)
	errors.LogInfo(context.Background(),
		"proxy markers[kind=pipeline-capabilities-refresh]: ",
		"ktls_supported=", summary.KTLSSupported,
		" sockmap_supported=", summary.SockmapSupported,
		" splice_supported=", summary.SpliceSupported)
	return pipelineCaps.Summary()
}

// IsLoopbackDestination returns true if destination is loopback; used for scope decisions.
func IsLoopbackDestination(dest net.Destination) bool {
	addr := dest.Address
	if ip := addr.IP(); ip != nil && ip.IsLoopback() {
		return true
	}
	return false
}
