//go:build !linux || (!amd64 && !arm64)

package udp

func canUseBatchRead() bool {
	return false
}

// startBatch is a stub on non-Linux platforms; canUseBatchRead() prevents it from being called.
func (h *Hub) startBatch() {
	panic("startBatch is not supported on this platform")
}
