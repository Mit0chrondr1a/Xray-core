//go:build linux

package ebpf

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

var (
	routingCacheMapFD int = -1
)

// bpfCacheEntry is the in-kernel representation of a cache entry.
type bpfCacheEntry struct {
	OutboundTagHash uint32
	RuleTagHash     uint32
	Version         uint64
	Hits            uint64
	Timestamp       uint64
}

// setupRoutingCacheImpl creates the BPF map for routing cache.
func setupRoutingCacheImpl(config RoutingCacheConfig) error {
	// Create LRU hash map for routing cache
	fd, err := createBPFMap(
		21, // BPF_MAP_TYPE_LRU_HASH
		uint32(unsafe.Sizeof(RoutingCacheKey{})),
		uint32(unsafe.Sizeof(bpfCacheEntry{})),
		config.MaxEntries,
	)
	if err != nil {
		return err
	}

	routingCacheMapFD = fd
	return nil
}

// teardownRoutingCacheImpl cleans up the routing cache BPF map.
func teardownRoutingCacheImpl() error {
	if routingCacheMapFD >= 0 {
		syscall.Close(routingCacheMapFD)
		routingCacheMapFD = -1
	}
	return nil
}

// lookupRoutingCacheImpl looks up an entry in the BPF map.
func lookupRoutingCacheImpl(key RoutingCacheKey) (*RoutingCacheEntry, bool) {
	if routingCacheMapFD < 0 {
		return nil, false
	}

	var bpfEntry bpfCacheEntry
	err := bpfMapLookup(routingCacheMapFD, unsafe.Pointer(&key), unsafe.Pointer(&bpfEntry))
	if err != nil {
		return nil, false
	}

	// Convert BPF entry to Go entry
	// Note: We store hashes, so we can't recover the original strings
	// This is a limitation of the BPF-based cache
	entry := &RoutingCacheEntry{
		Version: bpfEntry.Version,
		Hits:    bpfEntry.Hits,
	}

	return entry, true
}

// updateRoutingCacheImpl updates an entry in the BPF map.
func updateRoutingCacheImpl(key RoutingCacheKey, entry *RoutingCacheEntry) error {
	if routingCacheMapFD < 0 {
		return ErrRoutingCacheNotEnabled
	}

	bpfEntry := bpfCacheEntry{
		OutboundTagHash: hashString(entry.OutboundTag),
		RuleTagHash:     hashString(entry.RuleTag),
		Version:         entry.Version,
		Hits:            entry.Hits,
		Timestamp:       uint64(unixNano()),
	}

	return bpfMapUpdate(routingCacheMapFD, unsafe.Pointer(&key), unsafe.Pointer(&bpfEntry))
}

// deleteRoutingCacheImpl deletes an entry from the BPF map.
func deleteRoutingCacheImpl(key RoutingCacheKey) error {
	if routingCacheMapFD < 0 {
		return nil
	}

	return bpfMapDelete(routingCacheMapFD, unsafe.Pointer(&key))
}

// hashString computes a hash of a string for BPF storage.
func hashString(s string) uint32 {
	// FNV-1a hash
	var hash uint32 = 2166136261
	for i := 0; i < len(s); i++ {
		hash ^= uint32(s[i])
		hash *= 16777619
	}
	return hash
}

// unixNano returns the current Unix timestamp in nanoseconds.
func unixNano() int64 {
	var ts unix.Timespec
	unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return ts.Nano()
}
