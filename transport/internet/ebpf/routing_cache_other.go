//go:build !linux

package ebpf

// setupRoutingCacheImpl is a no-op on non-Linux systems.
func setupRoutingCacheImpl(config RoutingCacheConfig) error {
	return ErrRoutingCacheNotSupported
}

// teardownRoutingCacheImpl is a no-op on non-Linux systems.
func teardownRoutingCacheImpl() error {
	return nil
}

// lookupRoutingCacheImpl returns not found on non-Linux systems.
func lookupRoutingCacheImpl(key RoutingCacheKey) (*RoutingCacheEntry, bool) {
	return nil, false
}

// updateRoutingCacheImpl is a no-op on non-Linux systems.
func updateRoutingCacheImpl(key RoutingCacheKey, entry *RoutingCacheEntry) error {
	return ErrRoutingCacheNotSupported
}

// deleteRoutingCacheImpl is a no-op on non-Linux systems.
func deleteRoutingCacheImpl(key RoutingCacheKey) error {
	return nil
}
