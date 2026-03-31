package session

import "sync/atomic"

// FlowTimings carries one-shot latency milestones for a single proxied flow.
// The values are stored as Unix nanoseconds so request, dial, uplink, and
// response paths can contribute from different goroutines without locks.
type FlowTimings struct {
	acceptStartUnixNano        atomic.Int64
	requestParsedUnixNano      atomic.Int64
	firstVisionCommandUnixNano atomic.Int64
	requestStartUnixNano       atomic.Int64
	dnsResolvedUnixNano        atomic.Int64
	connectStartUnixNano       atomic.Int64
	connectOpenUnixNano        atomic.Int64
	uplinkStartUnixNano        atomic.Int64
	uplinkFirstWriteUnixNano   atomic.Int64
	uplinkLastWriteUnixNano    atomic.Int64
	uplinkCompleteUnixNano     atomic.Int64
	firstResponseUnixNano      atomic.Int64
}

func (t *FlowTimings) StoreAcceptStart(unixNano int64) {
	if t == nil || unixNano <= 0 {
		return
	}
	if t.acceptStartUnixNano.Load() == 0 {
		t.acceptStartUnixNano.CompareAndSwap(0, unixNano)
	}
}

func (t *FlowTimings) StoreRequestParsed(unixNano int64) {
	if t == nil || unixNano <= 0 {
		return
	}
	if t.requestParsedUnixNano.Load() == 0 {
		t.requestParsedUnixNano.CompareAndSwap(0, unixNano)
	}
}

func (t *FlowTimings) StoreFirstVisionCommand(unixNano int64) {
	if t == nil || unixNano <= 0 {
		return
	}
	if t.firstVisionCommandUnixNano.Load() == 0 {
		t.firstVisionCommandUnixNano.CompareAndSwap(0, unixNano)
	}
}

func (t *FlowTimings) StoreRequestStart(unixNano int64) {
	if t == nil || unixNano <= 0 {
		return
	}
	if t.requestStartUnixNano.Load() == 0 {
		t.requestStartUnixNano.CompareAndSwap(0, unixNano)
	}
}

func (t *FlowTimings) StoreDNSResolved(unixNano int64) {
	if t == nil || unixNano <= 0 {
		return
	}
	t.dnsResolvedUnixNano.Store(unixNano)
}

func (t *FlowTimings) StoreConnectStart(unixNano int64) {
	if t == nil || unixNano <= 0 {
		return
	}
	t.connectStartUnixNano.Store(unixNano)
}

func (t *FlowTimings) StoreConnectOpen(unixNano int64) {
	if t == nil || unixNano <= 0 {
		return
	}
	t.connectOpenUnixNano.Store(unixNano)
}

func (t *FlowTimings) StoreUplinkStart(unixNano int64) {
	if t == nil || unixNano <= 0 {
		return
	}
	if t.uplinkStartUnixNano.Load() == 0 {
		t.uplinkStartUnixNano.CompareAndSwap(0, unixNano)
	}
}

func (t *FlowTimings) ObserveUplinkWrite(unixNano int64, n int) {
	if t == nil || unixNano <= 0 || n <= 0 {
		return
	}
	if t.uplinkFirstWriteUnixNano.Load() == 0 {
		t.uplinkFirstWriteUnixNano.CompareAndSwap(0, unixNano)
	}
	t.uplinkLastWriteUnixNano.Store(unixNano)
}

func (t *FlowTimings) StoreUplinkComplete(unixNano int64) {
	if t == nil || unixNano <= 0 {
		return
	}
	t.uplinkCompleteUnixNano.Store(unixNano)
}

func (t *FlowTimings) StoreFirstResponse(unixNano int64) {
	if t == nil || unixNano <= 0 {
		return
	}
	if t.firstResponseUnixNano.Load() == 0 {
		t.firstResponseUnixNano.CompareAndSwap(0, unixNano)
	}
}

func (t *FlowTimings) RequestStartUnixNano() int64 {
	if t == nil {
		return 0
	}
	return t.requestStartUnixNano.Load()
}

func (t *FlowTimings) AcceptStartUnixNano() int64 {
	if t == nil {
		return 0
	}
	return t.acceptStartUnixNano.Load()
}

func (t *FlowTimings) RequestParsedUnixNano() int64 {
	if t == nil {
		return 0
	}
	return t.requestParsedUnixNano.Load()
}

func (t *FlowTimings) FirstVisionCommandUnixNano() int64 {
	if t == nil {
		return 0
	}
	return t.firstVisionCommandUnixNano.Load()
}

func (t *FlowTimings) DNSResolvedUnixNano() int64 {
	if t == nil {
		return 0
	}
	return t.dnsResolvedUnixNano.Load()
}

func (t *FlowTimings) ConnectStartUnixNano() int64 {
	if t == nil {
		return 0
	}
	return t.connectStartUnixNano.Load()
}

func (t *FlowTimings) ConnectOpenUnixNano() int64 {
	if t == nil {
		return 0
	}
	return t.connectOpenUnixNano.Load()
}

func (t *FlowTimings) UplinkStartUnixNano() int64 {
	if t == nil {
		return 0
	}
	return t.uplinkStartUnixNano.Load()
}

func (t *FlowTimings) UplinkFirstWriteUnixNano() int64 {
	if t == nil {
		return 0
	}
	return t.uplinkFirstWriteUnixNano.Load()
}

func (t *FlowTimings) UplinkLastWriteUnixNano() int64 {
	if t == nil {
		return 0
	}
	return t.uplinkLastWriteUnixNano.Load()
}

func (t *FlowTimings) UplinkCompleteUnixNano() int64 {
	if t == nil {
		return 0
	}
	return t.uplinkCompleteUnixNano.Load()
}

func (t *FlowTimings) FirstResponseUnixNano() int64 {
	if t == nil {
		return 0
	}
	return t.firstResponseUnixNano.Load()
}
