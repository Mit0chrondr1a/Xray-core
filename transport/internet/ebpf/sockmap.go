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
	mu              sync.RWMutex // read lock guards pair ops; write lock guards setup/teardown
	config          SockmapConfig
	enabled         atomic.Bool
	useNativeLoader bool     // true when Rust/Aya eBPF loader is active
	pairs           sync.Map // SockPairKey → *SockPair

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

	// kTLS splice fallback tracking
	ktlsSpliceFallbacks atomic.Int64 // times kTLS pairs routed to splice due to kernel incompatibility

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
	ActivePairs         int64
	TotalPairs          int64
	FullRejects         int64
	PeakPairs           int64
	StaleCleanups       int64
	RegFailures         int64
	SpliceFallbacks     int64
	KTLSSpliceFallbacks int64
	Enabled             bool
	MaxEntries          uint32
	NativeLoader        bool // true when Rust/Aya eBPF loader is active
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

func (h CryptoHint) String() string {
	switch h {
	case CryptoNone:
		return "none"
	case CryptoKTLSBoth:
		return "kTLS-both"
	case CryptoKTLSTxOnly:
		return "kTLS-TX"
	case CryptoKTLSRxOnly:
		return "kTLS-RX"
	case CryptoUserspaceTLS:
		return "userspace"
	default:
		return "unknown"
	}
}

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
	Active atomic.Bool
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

	// sweepStaleThresholdPermille is the permille threshold for stale entries
	// detected by the sweeper. If >10% (100 permille) of pairs were stale in
	// the last sweep, ShouldFallbackToSplice returns true.
	sweepStaleThresholdPermille = 100
)

// NewSockmapManager creates a new sockmap manager.
// The config is validated and clamped to safe bounds.
func NewSockmapManager(config SockmapConfig) *SockmapManager {
	// Clamp MaxEntries to sane bounds.
	if config.MaxEntries == 0 {
		config.MaxEntries = 65536
	}
	const maxSockmapEntries = 1 << 20 // 1M entries
	if config.MaxEntries > maxSockmapEntries {
		config.MaxEntries = maxSockmapEntries
	}
	return &SockmapManager{
		config:   config,
		lruList:  list.New(),
		lruIndex: make(map[SockPairKey]*list.Element),
	}
}

// Enable activates sockmap-based proxying.
// If the Rust/Aya eBPF loader is available (native.EbpfAvailable()), it is
// tried first — providing SK_SKB parser + verdict + SK_MSG cork (3 programs).
// On failure, falls back transparently to the Go-native loader (SK_SKB only, 2 programs).
func (m *SockmapManager) Enable() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	caps := GetCapabilities()
	if !caps.SockmapSupported {
		return ErrSockmapNotSupported
	}

	if nativeEbpfAvailable() {
		m.useNativeLoader = true
		if err := m.setupSockmap(); err != nil {
			xerrors.LogWarning(context.Background(),
				"sockmap: Rust/Aya eBPF loader failed (", err, "), falling back to Go-native")
			m.useNativeLoader = false
			if err2 := m.setupSockmap(); err2 != nil {
				return err2
			}
		}
	} else {
		if err := m.setupSockmap(); err != nil {
			return err
		}
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

	m.useNativeLoader = false
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
	if policy&PolicyAllowRedirect != 0 && inboundCrypto != outboundCrypto {
		xerrors.LogDebug(context.Background(),
			"sockmap: asymmetric crypto redirect (",
			inboundCrypto.String(), " <-> ", outboundCrypto.String(), ")")
	}

	if m.useNativeLoader {
		// Rust/Aya path: register_pair_impl handles policy map writes internally,
		// so skip Go-side setPolicyEntry() calls.
		if err := m.setupForwardingWithEviction(inboundFD, outboundFD, inboundCookie, outboundCookie, policy); err != nil {
			m.regFailures.Add(1)
			m.recordRegistrationAttempt(true)
			if isSockmapFull(err) {
				m.fullRejects.Add(1)
			}
			return err
		}
	} else {
		// Go-native path: write policy entries before forwarding registration so
		// the verdict program can consult them as soon as data arrives.
		if err := setPolicyEntry(inboundCookie, policy); err != nil {
			return err
		}
		if err := setPolicyEntry(outboundCookie, policy); err != nil {
			_ = deletePolicyEntry(inboundCookie) // best-effort cleanup
			return err
		}

		if err := m.setupForwardingWithEviction(inboundFD, outboundFD, inboundCookie, outboundCookie, 0); err != nil {
			m.regFailures.Add(1)
			m.recordRegistrationAttempt(true)
			_ = deletePolicyEntry(inboundCookie)  // best-effort cleanup
			_ = deletePolicyEntry(outboundCookie) // best-effort cleanup
			if isSockmapFull(err) {
				m.fullRejects.Add(1)
			}
			return err
		}
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
		InboundCrypto:  inboundCrypto,
		OutboundCrypto: outboundCrypto,
	}
	pair.Active.Store(true)

	// Insert LRU entry before pairs.Store so eviction can find the pair
	// if the map fills between the two operations (M13 fix).
	m.lruMu.Lock()
	elem := m.lruList.PushFront(key)
	m.lruIndex[key] = elem
	m.lruMu.Unlock()

	m.pairs.Store(key, pair)

	// Update capacity counters.
	active := m.activePairs.Add(1)
	m.totalPairs.Add(1)
	m.updatePeakPairs(active)
	m.checkUtilization(active)

	return nil
}

// setupForwardingWithEviction attempts setupForwarding, evicting LRU pairs
// on ENOSPC/E2BIG errors (up to maxEvictRetries attempts).
// policyFlags is passed through to the Rust loader; the Go-native path ignores it.
func (m *SockmapManager) setupForwardingWithEviction(inboundFD, outboundFD int, inboundCookie, outboundCookie uint64, policyFlags uint32) error {
	err := m.setupForwarding(inboundFD, outboundFD, inboundCookie, outboundCookie, policyFlags)
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
		err = m.setupForwarding(inboundFD, outboundFD, inboundCookie, outboundCookie, policyFlags)
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
	pair.Active.Store(false)

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
	// Rust/Aya unregister_pair_impl deletes policy entries internally;
	// only the Go-native path needs explicit Go-side cleanup.
	if !m.useNativeLoader {
		deletePolicyEntry(pair.InboundCookie)
		deletePolicyEntry(pair.OutboundCookie)
	}

	m.activePairs.Add(-1)
	return firstErr
}

// GetStats returns the socket pair for a connection, if registered.
func (m *SockmapManager) GetStats(inbound, outbound net.Conn) (*SockPair, bool) {
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

	v, ok := m.pairs.Load(key)
	if !ok {
		return nil, false
	}
	return v.(*SockPair), true
}

// GetSockmapStats returns a snapshot of overall sockmap statistics.
func (m *SockmapManager) GetSockmapStats() SockmapStats {
	return SockmapStats{
		ActivePairs:         m.activePairs.Load(),
		TotalPairs:          m.totalPairs.Load(),
		FullRejects:         m.fullRejects.Load(),
		PeakPairs:           m.peakPairs.Load(),
		StaleCleanups:       m.staleCleanups.Load(),
		RegFailures:         m.regFailures.Load(),
		SpliceFallbacks:     m.spliceFallbacks.Load(),
		KTLSSpliceFallbacks: m.ktlsSpliceFallbacks.Load(),
		Enabled:             m.enabled.Load(),
		MaxEntries:          m.config.MaxEntries,
		NativeLoader:        m.useNativeLoader,
	}
}

// UsingNativeLoader returns true if the Rust/Aya eBPF loader is active.
func (m *SockmapManager) UsingNativeLoader() bool {
	return m.useNativeLoader
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
	if m.sweepStaleRatio.Load() > sweepStaleThresholdPermille {
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

var (
	ktlsSockhashProbeOnce sync.Once
	ktlsSockhashOK        bool
	ktlsSockhashCompatFn  = KTLSSockhashCompatible
)

// KTLSSockhashCompatible reports whether the running kernel supports inserting
// kTLS sockets into SOCKHASH maps. This is probed once at startup by creating
// a real kTLS socket and attempting SOCKHASH insertion.
//
// Kernel 6.18 removed psock_update_sk_prot from TLS proto structs, breaking
// this path. When/if a future kernel restores the callback, this probe will
// automatically detect it — no code changes or version gates needed.
func KTLSSockhashCompatible() bool {
	ktlsSockhashProbeOnce.Do(func() {
		ktlsSockhashOK = probeKTLSSockhashCompat()
		if ktlsSockhashOK {
			xerrors.LogDebug(context.Background(), "sockmap: kTLS+SOCKHASH probe passed")
		} else {
			xerrors.LogInfo(context.Background(), "sockmap: kTLS+SOCKHASH probe failed (kernel ", unameRelease(), ") — kTLS sockets will use splice instead of sockmap")
		}
	})
	return ktlsSockhashOK
}

// IncrementKTLSSpliceFallback records that a kTLS-eligible connection pair was
// routed to splice(2) instead of sockmap due to kernel incompatibility.
func (m *SockmapManager) IncrementKTLSSpliceFallback() {
	m.ktlsSpliceFallbacks.Add(1)
}

// CanUseZeroCopyWithCrypto returns true if the connection pair can use
// zero-copy given their crypto states. Both must be raw TCP connections
// and the redirect policy must allow it.
//
// Security invariant: when this returns false for kTLS connections (e.g.
// KTLSSockhashCompatible() == false on kernel 6.18+), the caller falls
// through to splice(2). kTLS connections still get kernel-level encryption
// via the TLS ULP — only the forwarding mechanism changes from BPF redirect
// to splice pipe buffers. Data remains encrypted in transit and never passes
// through userspace in cleartext.
func CanUseZeroCopyWithCrypto(inbound, outbound net.Conn, inCrypto, outCrypto CryptoHint) bool {
	_, ok1 := inbound.(*net.TCPConn)
	_, ok2 := outbound.(*net.TCPConn)
	if !ok1 || !ok2 {
		return false
	}
	policy := computeRedirectPolicy(inCrypto, outCrypto)
	if policy&PolicyAllowRedirect == 0 {
		return false
	}
	// If either side is kTLS, verify this kernel supports kTLS+SOCKHASH.
	if policy&PolicyKTLSActive != 0 && !ktlsSockhashCompatFn() {
		return false
	}
	return true
}

// computeRedirectPolicy determines the redirect policy flags for a pair of
// sockets based on their crypto states.
//
// kTLS sockets are eligible for sockmap redirect because the kernel's kTLS
// layer sits below the socket layer — it transparently encrypts on TX and
// decrypts on RX. Sockmap operates at the socket layer (plaintext), so
// asymmetric pairs (kTLS ↔ plain TCP) work correctly: this is the normal
// proxy scenario where one side is encrypted (client) and the other is
// plain (upstream target).
func computeRedirectPolicy(inbound, outbound CryptoHint) uint32 {
	inOK := inbound == CryptoNone || inbound == CryptoKTLSBoth
	outOK := outbound == CryptoNone || outbound == CryptoKTLSBoth
	if !inOK || !outOK {
		return 0 // userspace TLS or partial kTLS — not eligible
	}
	policy := PolicyAllowRedirect
	if inbound == CryptoKTLSBoth || outbound == CryptoKTLSBoth {
		policy |= PolicyKTLSActive
	}
	return policy
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

const (
	sweepIntervalMin = 5 * time.Second
	sweepIntervalMax = 60 * time.Second
)

// sweepStaleEntries periodically checks for stale sockmap entries.
// A stale entry is one where the FD is no longer valid or has been
// reused by a different socket (cookie mismatch).
// The sweep interval adapts based on the stale ratio from the last sweep:
// >5% stale → halve interval (floor 5s), <1% stale → double interval (ceiling 60s).
func (m *SockmapManager) sweepStaleEntries(done <-chan struct{}) {
	defer m.sweepWG.Done()
	defer func() {
		if r := recover(); r != nil {
			xerrors.LogWarning(context.Background(), "sockmap sweeper panic: ", r, " — restarting in 5s")
			select {
			case <-done:
				return
			case <-time.After(5 * time.Second):
			}
			m.sweepWG.Add(1)
			go m.sweepStaleEntries(done)
		}
	}()

	interval := sweepIntervalMax
	timer := time.NewTimer(interval)
	defer timer.Stop()

	for {
		select {
		case <-done:
			return
		case <-timer.C:
			staleCount, totalCount := m.doSweep()
			interval = m.adaptSweepInterval(interval, staleCount, totalCount)
			timer.Reset(interval)
		}
	}
}

// adaptSweepInterval adjusts the sweep interval based on the stale ratio.
func (m *SockmapManager) adaptSweepInterval(current time.Duration, staleCount, totalCount int) time.Duration {
	if totalCount == 0 {
		return current
	}
	stalePermille := staleCount * 1000 / totalCount
	switch {
	case stalePermille > 50: // >5% stale → halve interval
		next := current / 2
		if next < sweepIntervalMin {
			next = sweepIntervalMin
		}
		return next
	case stalePermille < 10: // <1% stale → double interval
		next := current * 2
		if next > sweepIntervalMax {
			next = sweepIntervalMax
		}
		return next
	default:
		return current
	}
}

// doSweep performs one sweep pass over all pairs.
// After cleaning stale pairs, if utilization exceeds 90%, proactively
// evicts the oldest 10% of pairs.
// Returns (staleCount, totalChecked) for adaptive sweep interval tuning.
func (m *SockmapManager) doSweep() (int, int) {
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
		// Fail-closed: if getSocketCookie errors, treat pair as stale to prevent
		// data leakage from FD reuse between the liveness check and cookie check.
		if cookie, err := getSocketCookie(key.InboundFD); err != nil || cookie != pair.InboundCookie {
			staleKeys = append(staleKeys, key)
			return true
		}
		if cookie, err := getSocketCookie(key.OutboundFD); err != nil || cookie != pair.OutboundCookie {
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

	return len(staleKeys), totalChecked
}

// isSockmapFull returns true if the error indicates the SOCKHASH is at capacity.
func isSockmapFull(err error) bool {
	return errors.Is(err, syscall.ENOSPC) || errors.Is(err, syscall.E2BIG)
}

// Platform-specific implementations with Rust/Aya ↔ Go-native dispatch.
func (m *SockmapManager) setupSockmap() error {
	if m.useNativeLoader {
		return setupSockmapNative(m.config)
	}
	return setupSockmapImpl(m.config)
}

func (m *SockmapManager) teardownSockmap() error {
	if m.useNativeLoader {
		return teardownSockmapNative()
	}
	return teardownSockmapImpl()
}

func (m *SockmapManager) setupForwarding(inboundFD, outboundFD int, inboundCookie, outboundCookie uint64, policyFlags uint32) error {
	if m.useNativeLoader {
		return setupForwardingNative(inboundFD, outboundFD, inboundCookie, outboundCookie, policyFlags)
	}
	return setupForwardingImpl(inboundFD, outboundFD, inboundCookie, outboundCookie)
}

func (m *SockmapManager) removeForwarding(inboundFD, outboundFD int, inboundCookie, outboundCookie uint64) error {
	if m.useNativeLoader {
		return removeForwardingNative(inboundCookie, outboundCookie)
	}
	return removeForwardingImpl(inboundFD, outboundFD, inboundCookie, outboundCookie)
}
