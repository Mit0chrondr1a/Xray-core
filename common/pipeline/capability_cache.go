package pipeline

import "sync/atomic"

// CapabilityCache holds a process-wide view of acceleration features
// (kTLS, sockmap, splice). Populate once at startup and reuse.
type CapabilityCache struct {
	ktls    atomic.Bool
	sockmap atomic.Bool
	splice  atomic.Bool
}

func NewCapabilityCache(summary CapabilitySummary) *CapabilityCache {
	c := &CapabilityCache{}
	c.ktls.Store(summary.KTLSSupported)
	c.sockmap.Store(summary.SockmapSupported)
	c.splice.Store(summary.SpliceSupported)
	return c
}

func (c *CapabilityCache) Summary() CapabilitySummary {
	return CapabilitySummary{
		KTLSSupported:    c.ktls.Load(),
		SockmapSupported: c.sockmap.Load(),
		SpliceSupported:  c.splice.Load(),
	}
}

// Update allows a future single probe to refresh cached capabilities.
func (c *CapabilityCache) Update(summary CapabilitySummary) {
	c.ktls.Store(summary.KTLSSupported)
	c.sockmap.Store(summary.SockmapSupported)
	c.splice.Store(summary.SpliceSupported)
}
