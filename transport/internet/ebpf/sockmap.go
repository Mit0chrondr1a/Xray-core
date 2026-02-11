package ebpf

import (
	"net"
	"sync"
)

// SockmapManager manages sockmap-based zero-copy TCP proxying.
// It enables direct data transfer between sockets without copying
// through userspace.
type SockmapManager struct {
	mu      sync.RWMutex
	config  SockmapConfig
	enabled bool
	pairs   map[SockPairKey]*SockPair
}

// SockPairKey identifies a socket pair for proxying.
type SockPairKey struct {
	InboundFD  int
	OutboundFD int
}

// SockPair represents a pair of sockets being proxied.
type SockPair struct {
	// InboundConn is the inbound connection (client side).
	InboundConn net.Conn
	// OutboundConn is the outbound connection (server side).
	OutboundConn net.Conn
	// BytesForwarded is the total bytes forwarded.
	BytesForwarded uint64
	// Active indicates if the pair is actively proxying.
	Active bool
}

// NewSockmapManager creates a new sockmap manager.
func NewSockmapManager(config SockmapConfig) *SockmapManager {
	return &SockmapManager{
		config: config,
		pairs:  make(map[SockPairKey]*SockPair),
	}
}

// Enable activates sockmap-based proxying.
func (m *SockmapManager) Enable() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	caps := GetCapabilities()
	if !caps.SockmapSupported {
		return ErrSockmapNotSupported
	}

	if err := m.setupSockmap(); err != nil {
		return err
	}

	m.enabled = true
	return nil
}

// Disable deactivates sockmap-based proxying.
func (m *SockmapManager) Disable() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.enabled {
		return nil
	}

	// Close all active pairs
	for key := range m.pairs {
		m.unregisterPairLocked(key)
	}

	if err := m.teardownSockmap(); err != nil {
		return err
	}

	m.enabled = false
	return nil
}

// RegisterPair registers a socket pair for zero-copy proxying.
// Both connections must be TCP connections without TLS encryption.
func (m *SockmapManager) RegisterPair(inbound, outbound net.Conn) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.enabled {
		return ErrSockmapNotEnabled
	}

	inboundFD, err := getConnFD(inbound)
	if err != nil {
		return err
	}

	outboundFD, err := getConnFD(outbound)
	if err != nil {
		return err
	}

	key := SockPairKey{
		InboundFD:  inboundFD,
		OutboundFD: outboundFD,
	}

	pair := &SockPair{
		InboundConn:  inbound,
		OutboundConn: outbound,
		Active:       true,
	}

	// Add both sockets to sockmap
	if err := m.addToSockmap(inboundFD); err != nil {
		return err
	}
	if err := m.addToSockmap(outboundFD); err != nil {
		m.removeFromSockmap(inboundFD)
		return err
	}

	// Setup sk_msg program to forward data
	if err := m.setupForwarding(inboundFD, outboundFD); err != nil {
		m.removeFromSockmap(inboundFD)
		m.removeFromSockmap(outboundFD)
		return err
	}

	m.pairs[key] = pair
	return nil
}

// UnregisterPair removes a socket pair from sockmap proxying.
func (m *SockmapManager) UnregisterPair(inbound, outbound net.Conn) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	inboundFD, err := getConnFD(inbound)
	if err != nil {
		return err
	}

	outboundFD, err := getConnFD(outbound)
	if err != nil {
		return err
	}

	key := SockPairKey{
		InboundFD:  inboundFD,
		OutboundFD: outboundFD,
	}

	return m.unregisterPairLocked(key)
}

// unregisterPairLocked removes a pair without holding the lock.
func (m *SockmapManager) unregisterPairLocked(key SockPairKey) error {
	pair, ok := m.pairs[key]
	if !ok {
		return nil
	}

	pair.Active = false
	m.removeFromSockmap(key.InboundFD)
	m.removeFromSockmap(key.OutboundFD)

	delete(m.pairs, key)
	return nil
}

// GetStats returns statistics for a socket pair.
func (m *SockmapManager) GetStats(inbound, outbound net.Conn) (*SockPair, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	inboundFD, err := getConnFD(inbound)
	if err != nil {
		return nil, false
	}

	outboundFD, err := getConnFD(outbound)
	if err != nil {
		return nil, false
	}

	key := SockPairKey{
		InboundFD:  inboundFD,
		OutboundFD: outboundFD,
	}

	pair, ok := m.pairs[key]
	return pair, ok
}

// IsEnabled returns true if sockmap proxying is active.
func (m *SockmapManager) IsEnabled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.enabled
}

// CanUseZeroCopy returns true if the connection pair can use zero-copy.
// This requires both connections to be raw TCP without encryption.
func CanUseZeroCopy(inbound, outbound net.Conn) bool {
	// Check if both are TCP connections
	_, ok1 := inbound.(*net.TCPConn)
	_, ok2 := outbound.(*net.TCPConn)
	return ok1 && ok2
}

// getConnFD extracts the file descriptor from a net.Conn.
func getConnFD(conn net.Conn) (int, error) {
	return getConnFDImpl(conn)
}

// Platform-specific implementations
func (m *SockmapManager) setupSockmap() error {
	return setupSockmapImpl(m.config)
}

func (m *SockmapManager) teardownSockmap() error {
	return teardownSockmapImpl()
}

func (m *SockmapManager) addToSockmap(fd int) error {
	return addToSockmapImpl(fd)
}

func (m *SockmapManager) removeFromSockmap(fd int) error {
	return removeFromSockmapImpl(fd)
}

func (m *SockmapManager) setupForwarding(inboundFD, outboundFD int) error {
	return setupForwardingImpl(inboundFD, outboundFD)
}
