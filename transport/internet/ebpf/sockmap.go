package ebpf

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	xerrors "github.com/xtls/xray-core/common/errors"
)

// SockmapManager manages sockmap-based zero-copy TCP proxying.
// It enables direct data transfer between sockets without copying
// through userspace.
type SockmapManager struct {
	mu      sync.RWMutex // read lock guards pair ops; write lock guards setup/teardown
	config  SockmapConfig
	enabled atomic.Bool
	pairs   sync.Map // SockPairKey → *SockPair

	// Capacity monitoring
	activePairs   atomic.Int64
	totalPairs    atomic.Int64 // lifetime total
	fullRejects   atomic.Int64 // registration failures due to capacity
	peakPairs     atomic.Int64 // high-water mark
	staleCleanups atomic.Int64 // entries removed by sweeper
	lastWarningNs atomic.Int64 // rate-limit warnings to 1/min

	// Contention detection
	regFailures       atomic.Int64 // RegisterPair failures (lifetime, any cause)
	regWindowStartNs  atomic.Int64 // start time of registration failure window
	regWindowTotal    atomic.Int64 // registrations attempted in current window
	regWindowFailures atomic.Int64 // failed registrations in current window
	sweepStaleRatio   atomic.Int64 // last sweep: stale-found * 1000 / total-checked (permille)
	spliceFallbacks   atomic.Int64 // times sockmap was skipped due to contention

	// Userspace LRU eviction for SOCKHASH
	lruList  *list.List                    // front=MRU, back=LRU
	lruIndex map[SockPairKey]*list.Element // O(1) lookup
	lruMu    sync.Mutex                    // guards lruList and lruIndex

	// Sweeper lifecycle
	sweepDone chan struct{}
	sweepWG   sync.WaitGroup
}

// SockmapStats provides a snapshot of sockmap manager statistics.
type SockmapStats struct {
	ActivePairs     int64
	TotalPairs      int64
	FullRejects     int64
	PeakPairs       int64
	StaleCleanups   int64
	RegFailures     int64
	SpliceFallbacks int64
	Enabled         bool
	MaxEntries      uint32
}

// SockPairKey identifies a socket pair for proxying.
type SockPairKey struct {
	InboundFD  int
	OutboundFD int
}

// CryptoHint describes the TLS/crypto state of a socket for redirect policy decisions.
type CryptoHint uint8

const (
	CryptoNone         CryptoHint = 0 // raw TCP
	CryptoKTLSBoth     CryptoHint = 1 // kTLS TX+RX
	CryptoKTLSTxOnly   CryptoHint = 2
	CryptoKTLSRxOnly   CryptoHint = 3
	CryptoUserspaceTLS CryptoHint = 4 // Go/uTLS — not eligible
)

const (
	PolicyAllowRedirect uint32 = 1 << 0
	PolicyUseIngress    uint32 = 1 << 1
	PolicyKTLSActive    uint32 = 1 << 2
)

// SockPair represents a pair of sockets being proxied.
type SockPair struct {
	// InboundConn is the inbound connection (client side).
	InboundConn net.Conn
	// OutboundConn is the outbound connection (server side).
	OutboundConn net.Conn
	// InboundCookie is the stable socket cookie used for sockhash cleanup.
	InboundCookie uint64
	// OutboundCookie is the stable socket cookie used for sockhash cleanup.
	OutboundCookie uint64
	// BytesForwarded is the total bytes forwarded.
	BytesForwarded uint64
	// Active indicates if the pair is actively proxying.
	Active bool
	// InboundCrypto is the crypto state of the inbound connection.
	InboundCrypto CryptoHint
	// OutboundCrypto is the crypto state of the outbound connection.
	OutboundCrypto CryptoHint
}

// maxEvictRetries is the maximum number of LRU eviction attempts when
// SOCKHASH is full.
const (
	maxEvictRetries      = 3
	regFailureWindow     = 60 * time.Second
	regFailureMinSamples = int64(20)
)

// NewSockmapManager creates a new sockmap manager.
func NewSockmapManager(config SockmapConfig) *SockmapManager {
	return &SockmapManager{
		config:   config,
		lruList:  list.New(),
		lruIndex: make(map[SockPairKey]*list.Element),
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

	done := make(chan struct{})
	m.sweepDone = done
	m.sweepWG.Add(1)
	go m.sweepStaleEntries(done)

	nowNs := time.Now().UnixNano()
	m.regWindowStartNs.Store(nowNs)
	m.regWindowTotal.Store(0)
	m.regWindowFailures.Store(0)
	m.sweepStaleRatio.Store(0)

	m.enabled.Store(true)
	return nil
}

// Disable deactivates sockmap-based proxying.
func (m *SockmapManager) Disable() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.enabled.Load() {
		return nil
	}

	// Stop sweeper before cleaning up pairs.
	if m.sweepDone != nil {
		close(m.sweepDone)
		m.sweepWG.Wait()
		m.sweepDone = nil
	}

	// Close all active pairs
	m.pairs.Range(func(k, v any) bool {
		key := k.(SockPairKey)
		m.unregisterPairLocked(key)
		return true
	})

	if err := m.teardownSockmap(); err != nil {
		return err
	}

	m.enabled.Store(false)
	return nil
}

// RegisterPair registers a socket pair for zero-copy proxying.
// Both connections must be TCP connections without TLS encryption.
func (m *SockmapManager) RegisterPair(inbound, outbound net.Conn) error {
	return m.RegisterPairWithCrypto(inbound, outbound, CryptoNone, CryptoNone)
}

// RegisterPairWithCrypto registers a socket pair for zero-copy proxying with crypto awareness.
// The crypto hints are used to compute a redirect policy that the verdict program consults.
func (m *SockmapManager) RegisterPairWithCrypto(inbound, outbound net.Conn, inboundCrypto, outboundCrypto CryptoHint) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.enabled.Load() {
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

	inboundCookie, err := getSocketCookie(inboundFD)
	if err != nil {
		return err
	}
	outboundCookie, err := getSocketCookie(outboundFD)
	if err != nil {
		return err
	}

	// Compute redirect policy from crypto hints.
	policy := computeRedirectPolicy(inboundCrypto, outboundCrypto)

	// Write policy entries before forwarding registration so the verdict program
	// can consult them as soon as data arrives.
	if err := setPolicyEntry(inboundCookie, policy); err != nil {
		return err
	}
	if err := setPolicyEntry(outboundCookie, policy); err != nil {
		deletePolicyEntry(inboundCookie)
		return err
	}

	// Setup forwarding — inserts both sockets into SOCKHASH.
	// On capacity error, attempt LRU eviction and retry.
	if err := m.setupForwardingWithEviction(inboundFD, outboundFD, inboundCookie, outboundCookie); err != nil {
		m.regFailures.Add(1)
		m.recordRegistrationAttempt(true)
		deletePolicyEntry(inboundCookie)
		deletePolicyEntry(outboundCookie)
		if isSockmapFull(err) {
			m.fullRejects.Add(1)
		}
		return err
	}
	m.recordRegistrationAttempt(false)

	// Prevent GC from finalizing connections while BPF ops used their FDs.
	runtime.KeepAlive(inbound)
	runtime.KeepAlive(outbound)

	pair := &SockPair{
		InboundConn:    inbound,
		OutboundConn:   outbound,
		InboundCookie:  inboundCookie,
		OutboundCookie: outboundCookie,
		Active:         true,
		InboundCrypto:  inboundCrypto,
		OutboundCrypto: outboundCrypto,
	}

	m.pairs.Store(key, pair)

	// Push to LRU front (most recently used).
	m.lruMu.Lock()
	elem := m.lruList.PushFront(key)
	m.lruIndex[key] = elem
	m.lruMu.Unlock()

	// Update capacity counters.
	active := m.activePairs.Add(1)
	m.totalPairs.Add(1)
	m.updatePeakPairs(active)
	m.checkUtilization(active)

	return nil
}

// setupForwardingWithEviction attempts setupForwarding, evicting LRU pairs
// on ENOSPC/E2BIG errors (up to maxEvictRetries attempts).
func (m *SockmapManager) setupForwardingWithEviction(inboundFD, outboundFD int, inboundCookie, outboundCookie uint64) error {
	err := m.setupForwarding(inboundFD, outboundFD, inboundCookie, outboundCookie)
	if err == nil {
		return nil
	}
	if !isSockmapFull(err) {
		return err
	}

	for i := 0; i < maxEvictRetries; i++ {
		if !m.evictLRU() {
			return err // nothing to evict
		}
		err = m.setupForwarding(inboundFD, outboundFD, inboundCookie, outboundCookie)
		if err == nil {
			return nil
		}
		if !isSockmapFull(err) {
			return err
		}
	}
	return err
}

// evictLRU removes the least-recently-used pair. Returns false if no pairs to evict.
func (m *SockmapManager) evictLRU() bool {
	m.lruMu.Lock()
	back := m.lruList.Back()
	if back == nil {
		m.lruMu.Unlock()
		return false
	}
	key := back.Value.(SockPairKey)
	m.lruList.Remove(back)
	delete(m.lruIndex, key)
	m.lruMu.Unlock()

	m.unregisterPairLocked(key)
	return true
}

// UnregisterPair removes a socket pair from sockmap proxying.
func (m *SockmapManager) UnregisterPair(inbound, outbound net.Conn) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

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

	err = m.unregisterPairLocked(key)

	// Prevent GC from finalizing connections while BPF cleanup used their FDs.
	runtime.KeepAlive(inbound)
	runtime.KeepAlive(outbound)

	return err
}

// unregisterPairLocked removes a pair. Safe to call concurrently.
func (m *SockmapManager) unregisterPairLocked(key SockPairKey) error {
	v, loaded := m.pairs.LoadAndDelete(key)
	if !loaded {
		return nil
	}

	pair := v.(*SockPair)
	pair.Active = false

	// Remove from LRU tracking.
	m.lruMu.Lock()
	if elem, ok := m.lruIndex[key]; ok {
		m.lruList.Remove(elem)
		delete(m.lruIndex, key)
	}
	m.lruMu.Unlock()

	var firstErr error
	if err := m.removeForwarding(key.InboundFD, key.OutboundFD, pair.InboundCookie, pair.OutboundCookie); err != nil {
		firstErr = err
	}
	deletePolicyEntry(pair.InboundCookie)
	deletePolicyEntry(pair.OutboundCookie)

	m.activePairs.Add(-1)
	return firstErr
}

// GetStats returns a snapshot of statistics for a socket pair.
// The returned SockPair is a copy; callers cannot mutate internal state.
func (m *SockmapManager) GetStats(inbound, outbound net.Conn) (SockPair, bool) {
	inboundFD, err := getConnFD(inbound)
	if err != nil {
		return SockPair{}, false
	}

	outboundFD, err := getConnFD(outbound)
	if err != nil {
		return SockPair{}, false
	}

	key := SockPairKey{
		InboundFD:  inboundFD,
		OutboundFD: outboundFD,
	}

	v, ok := m.pairs.Load(key)
	if !ok {
		return SockPair{}, false
	}
	return *v.(*SockPair), true
}

// GetSockmapStats returns a snapshot of overall sockmap statistics.
func (m *SockmapManager) GetSockmapStats() SockmapStats {
	return SockmapStats{
		ActivePairs:     m.activePairs.Load(),
		TotalPairs:      m.totalPairs.Load(),
		FullRejects:     m.fullRejects.Load(),
		PeakPairs:       m.peakPairs.Load(),
		StaleCleanups:   m.staleCleanups.Load(),
		RegFailures:     m.regFailures.Load(),
		SpliceFallbacks: m.spliceFallbacks.Load(),
		Enabled:         m.enabled.Load(),
		MaxEntries:      m.config.MaxEntries,
	}
}

// IsEnabled returns true if sockmap proxying is active.
func (m *SockmapManager) IsEnabled() bool {
	return m.enabled.Load()
}

// ShouldFallbackToSplice returns true when sockmap contention is detected,
// indicating callers should use splice(2) directly instead.
//
// Heuristic: if >20% of recent registrations failed, or the sweeper found
// >10% stale entries (indicating FD churn / redirect failures), skip sockmap.
// Resets automatically: registration failures are tracked in a rotating
// time window, and sweepStaleRatio is refreshed every sweep cycle (60s).
func (m *SockmapManager) ShouldFallbackToSplice() bool {
	if !m.enabled.Load() {
		return true
	}

	nowNs := time.Now().UnixNano()
	m.rotateRegFailureWindow(nowNs)

	// Check registration failure rate in the current window.
	total := m.regWindowTotal.Load()
	failures := m.regWindowFailures.Load()
	if total > regFailureMinSamples && failures*5 > total {
		// >20% failure rate with enough samples
		m.spliceFallbacks.Add(1)
		return true
	}

	// Check stale sweep ratio (permille).
	if m.sweepStaleRatio.Load() > 100 {
		// >10% of pairs were stale last sweep
		m.spliceFallbacks.Add(1)
		return true
	}

	return false
}

// CanUseZeroCopy returns true if the connection pair can use zero-copy.
// This requires both connections to be raw TCP without encryption.
func CanUseZeroCopy(inbound, outbound net.Conn) bool {
	// Check if both are TCP connections
	_, ok1 := inbound.(*net.TCPConn)
	_, ok2 := outbound.(*net.TCPConn)
	return ok1 && ok2
}

// CanUseZeroCopyWithCrypto returns true if the connection pair can use
// zero-copy given their crypto states. Both must be raw TCP connections
// and the redirect policy must allow it.
func CanUseZeroCopyWithCrypto(inbound, outbound net.Conn, inCrypto, outCrypto CryptoHint) bool {
	_, ok1 := inbound.(*net.TCPConn)
	_, ok2 := outbound.(*net.TCPConn)
	if !ok1 || !ok2 {
		return false
	}
	return computeRedirectPolicy(inCrypto, outCrypto)&PolicyAllowRedirect != 0
}

// computeRedirectPolicy determines the redirect policy flags for a pair of
// sockets based on their crypto states.
func computeRedirectPolicy(inbound, outbound CryptoHint) uint32 {
	switch {
	case inbound == CryptoNone && outbound == CryptoNone:
		return PolicyAllowRedirect // classic raw TCP
	case inbound == CryptoKTLSBoth && outbound == CryptoKTLSBoth:
		return PolicyAllowRedirect | PolicyKTLSActive // kernel handles encrypt/decrypt
	default:
		return 0 // asymmetric or partial — unsafe
	}
}

// getConnFD extracts the file descriptor from a net.Conn.
func getConnFD(conn net.Conn) (int, error) {
	return getConnFDImpl(conn)
}

// updatePeakPairs updates the high-water mark via CAS loop.
func (m *SockmapManager) updatePeakPairs(current int64) {
	for {
		peak := m.peakPairs.Load()
		if current <= peak {
			return
		}
		if m.peakPairs.CompareAndSwap(peak, current) {
			return
		}
	}
}

// rotateRegFailureWindow resets registration counters when the current
// observation window expires.
func (m *SockmapManager) rotateRegFailureWindow(nowNs int64) {
	start := m.regWindowStartNs.Load()
	if start == 0 {
		if m.regWindowStartNs.CompareAndSwap(0, nowNs) {
			m.regWindowTotal.Store(0)
			m.regWindowFailures.Store(0)
		}
		return
	}
	if nowNs-start < int64(regFailureWindow) {
		return
	}
	if m.regWindowStartNs.CompareAndSwap(start, nowNs) {
		m.regWindowTotal.Store(0)
		m.regWindowFailures.Store(0)
	}
}

// recordRegistrationAttempt updates recent registration counters used by
// contention fallback heuristics.
func (m *SockmapManager) recordRegistrationAttempt(failed bool) {
	nowNs := time.Now().UnixNano()
	m.rotateRegFailureWindow(nowNs)
	m.regWindowTotal.Add(1)
	if failed {
		m.regWindowFailures.Add(1)
	}
}

// checkUtilization logs warnings when approaching sockmap capacity.
func (m *SockmapManager) checkUtilization(active int64) {
	maxEntries := int64(m.config.MaxEntries)
	if maxEntries == 0 {
		return
	}

	// Each pair uses 2 entries in the SOCKHASH.
	utilization := float64(active*2) / float64(maxEntries)
	if utilization < 0.75 {
		return
	}

	// Rate-limit warnings to 1 per 60 seconds.
	now := time.Now().UnixNano()
	last := m.lastWarningNs.Load()
	if now-last < int64(60*time.Second) {
		return
	}
	if !m.lastWarningNs.CompareAndSwap(last, now) {
		return // another goroutine just warned
	}

	ctx := context.Background()
	if utilization >= 0.90 {
		xerrors.LogInfo(ctx, fmt.Sprintf("sockmap utilization critical: %d/%d entries (%.0f%%)", active*2, maxEntries, utilization*100))
	} else {
		xerrors.LogInfo(ctx, fmt.Sprintf("sockmap utilization high: %d/%d entries (%.0f%%)", active*2, maxEntries, utilization*100))
	}
}

// sweepStaleEntries periodically checks for stale sockmap entries.
// A stale entry is one where the FD is no longer valid or has been
// reused by a different socket (cookie mismatch).
func (m *SockmapManager) sweepStaleEntries(done <-chan struct{}) {
	defer m.sweepWG.Done()

	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			m.doSweep()
		}
	}
}

// doSweep performs one sweep pass over all pairs.
// After cleaning stale pairs, if utilization exceeds 90%, proactively
// evicts the oldest 10% of pairs.
func (m *SockmapManager) doSweep() {
	var staleKeys []SockPairKey
	var totalChecked int

	m.pairs.Range(func(k, v any) bool {
		totalChecked++
		key := k.(SockPairKey)
		pair := v.(*SockPair)

		// Check if inbound FD is still alive.
		if !isSocketAlive(key.InboundFD) {
			staleKeys = append(staleKeys, key)
			return true
		}
		// Check if outbound FD is still alive.
		if !isSocketAlive(key.OutboundFD) {
			staleKeys = append(staleKeys, key)
			return true
		}

		// Verify socket cookies haven't changed (FD reuse detection).
		if cookie, err := getSocketCookie(key.InboundFD); err == nil && cookie != pair.InboundCookie {
			staleKeys = append(staleKeys, key)
			return true
		}
		if cookie, err := getSocketCookie(key.OutboundFD); err == nil && cookie != pair.OutboundCookie {
			staleKeys = append(staleKeys, key)
			return true
		}

		return true
	})

	// Update stale ratio for contention detection.
	if totalChecked > 0 {
		m.sweepStaleRatio.Store(int64(len(staleKeys)) * 1000 / int64(totalChecked))
	} else {
		m.sweepStaleRatio.Store(0)
	}

	if len(staleKeys) > 0 {
		ctx := context.Background()
		for _, key := range staleKeys {
			if err := m.unregisterPairLocked(key); err != nil {
				xerrors.LogInfoInner(ctx, err, fmt.Sprintf("sockmap sweeper: failed to clean stale pair fd=%d↔%d", key.InboundFD, key.OutboundFD))
			} else {
				xerrors.LogInfo(ctx, fmt.Sprintf("sockmap sweeper: cleaned stale pair fd=%d↔%d", key.InboundFD, key.OutboundFD))
			}
			m.staleCleanups.Add(1)
		}
	}

	// Proactive LRU eviction at high utilization.
	maxEntries := int64(m.config.MaxEntries)
	if maxEntries > 0 {
		active := m.activePairs.Load()
		utilization := float64(active*2) / float64(maxEntries)
		if utilization > 0.90 {
			// Evict oldest 10% of pairs.
			evictCount := int(float64(active) * 0.10)
			if evictCount < 1 {
				evictCount = 1
			}
			for i := 0; i < evictCount; i++ {
				if !m.evictLRU() {
					break
				}
			}
		}
	}
}

// isSockmapFull returns true if the error indicates the SOCKHASH is at capacity.
func isSockmapFull(err error) bool {
	return errors.Is(err, syscall.ENOSPC) || errors.Is(err, syscall.E2BIG)
}

// Platform-specific implementations
func (m *SockmapManager) setupSockmap() error {
	return setupSockmapImpl(m.config)
}

func (m *SockmapManager) teardownSockmap() error {
	return teardownSockmapImpl()
}

func (m *SockmapManager) setupForwarding(inboundFD, outboundFD int, inboundCookie, outboundCookie uint64) error {
	return setupForwardingImpl(inboundFD, outboundFD, inboundCookie, outboundCookie)
}

func (m *SockmapManager) removeForwarding(inboundFD, outboundFD int, inboundCookie, outboundCookie uint64) error {
	return removeForwardingImpl(inboundFD, outboundFD, inboundCookie, outboundCookie)
}
