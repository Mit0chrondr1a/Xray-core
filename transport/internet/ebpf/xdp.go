package ebpf

import (
	"net"
	"sync"
)

// XDPManager manages XDP programs for UDP acceleration.
// It offloads known UDP flows to XDP after the first packet
// establishes a session.
type XDPManager struct {
	mu      sync.RWMutex
	config  XDPConfig
	enabled bool
	flows   map[FlowKey]*FlowEntry
}

// FlowKey identifies a UDP flow (5-tuple).
type FlowKey struct {
	SrcIP   [16]byte
	DstIP   [16]byte
	SrcPort uint16
	DstPort uint16
	Proto   uint8
}

// FlowEntry contains flow state for XDP offload.
type FlowEntry struct {
	// RewriteSrcIP is the source IP to rewrite to (if any).
	RewriteSrcIP net.IP
	// RewriteDstIP is the destination IP to rewrite to.
	RewriteDstIP net.IP
	// RewriteSrcPort is the source port to rewrite to.
	RewriteSrcPort uint16
	// RewriteDstPort is the destination port to rewrite to.
	RewriteDstPort uint16
	// Packets is the number of packets processed.
	Packets uint64
	// Bytes is the number of bytes processed.
	Bytes uint64
	// LastSeen is the last time this flow was seen (unix timestamp).
	LastSeen int64
}

// XDPAction represents XDP program return values.
type XDPAction int

const (
	// XDPAborted indicates an error occurred.
	XDPAborted XDPAction = 0
	// XDPDrop drops the packet.
	XDPDrop XDPAction = 1
	// XDPPass passes the packet to the kernel stack.
	XDPPass XDPAction = 2
	// XDPTx bounces the packet back out the same interface.
	XDPTx XDPAction = 3
	// XDPRedirect redirects the packet to another interface or CPU.
	XDPRedirect XDPAction = 4
)

// NewXDPManager creates a new XDP manager with the given configuration.
func NewXDPManager(config XDPConfig) *XDPManager {
	return &XDPManager{
		config: config,
		flows:  make(map[FlowKey]*FlowEntry),
	}
}

// Enable activates XDP acceleration on the specified interface.
// Returns an error if XDP is not supported or if attachment fails.
func (m *XDPManager) Enable(ifname string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	caps := GetCapabilities()
	if !caps.XDPSupported {
		return ErrXDPNotSupported
	}

	if err := m.attachXDP(ifname); err != nil {
		return err
	}

	m.enabled = true
	return nil
}

// Disable deactivates XDP acceleration.
func (m *XDPManager) Disable() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.enabled {
		return nil
	}

	if err := m.detachXDP(); err != nil {
		return err
	}

	m.enabled = false
	return nil
}

// RegisterFlow registers a UDP flow for XDP offload.
// Once registered, matching packets will be processed by XDP
// without going through the full kernel stack.
func (m *XDPManager) RegisterFlow(key FlowKey, entry *FlowEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.enabled {
		return ErrXDPNotEnabled
	}

	m.flows[key] = entry

	// Update BPF map
	return m.updateFlowMap(key, entry)
}

// UnregisterFlow removes a flow from XDP offload.
func (m *XDPManager) UnregisterFlow(key FlowKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.flows, key)

	if !m.enabled {
		return nil
	}

	return m.deleteFlowMap(key)
}

// GetStats returns statistics for a flow.
func (m *XDPManager) GetStats(key FlowKey) (*FlowEntry, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	entry, ok := m.flows[key]
	if !ok {
		return nil, false
	}

	// Read stats from BPF map
	if m.enabled {
		m.readFlowStats(key, entry)
	}

	return entry, true
}

// IsEnabled returns true if XDP is active.
func (m *XDPManager) IsEnabled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.enabled
}

// attachXDP attaches the XDP program to an interface.
// Platform-specific implementation in xdp_linux.go.
func (m *XDPManager) attachXDP(ifname string) error {
	return attachXDPImpl(ifname, m.config)
}

// detachXDP detaches the XDP program from all interfaces.
func (m *XDPManager) detachXDP() error {
	return detachXDPImpl()
}

// updateFlowMap updates a flow entry in the BPF map.
func (m *XDPManager) updateFlowMap(key FlowKey, entry *FlowEntry) error {
	return updateFlowMapImpl(key, entry)
}

// deleteFlowMap removes a flow entry from the BPF map.
func (m *XDPManager) deleteFlowMap(key FlowKey) error {
	return deleteFlowMapImpl(key)
}

// readFlowStats reads flow statistics from the BPF map.
func (m *XDPManager) readFlowStats(key FlowKey, entry *FlowEntry) error {
	return readFlowStatsImpl(key, entry)
}
