//go:build linux

package tls

import (
	"sync"
	"syscall"
	"time"

	"github.com/xtls/xray-core/common/errors"
)

const (
	minPollInterval = 1 * time.Second
	maxPollInterval = 10 * time.Second
	// rxWarningRatio is the fraction of keyUpdateThreshold at which we log
	// a warning about the peer's RX record sequence approaching the limit.
	rxWarningRatio = 3.0 / 4.0
	// maxTransientErrors is the number of consecutive transient getsockopt
	// errors before the monitor gives up (to handle EINTR/EAGAIN bursts).
	maxTransientErrors = 3
)

// KeyUpdateMonitor reads exact TLS record sequence numbers from the kernel
// via getsockopt(SOL_TLS) and proactively rotates the TX key when the
// sequence counter approaches keyUpdateThreshold. It uses adaptive polling
// that scales the interval based on current throughput, and monitors the RX
// direction for defensive logging.
type KeyUpdateMonitor struct {
	fd      int
	handler *KTLSKeyUpdateHandler
	stopCh  chan struct{}
	once    sync.Once
}

// NewKeyUpdateMonitor creates a monitor for the given socket fd and handler.
// Returns nil if handler is nil.
func NewKeyUpdateMonitor(fd int, handler *KTLSKeyUpdateHandler) *KeyUpdateMonitor {
	if handler == nil {
		return nil
	}
	return &KeyUpdateMonitor{
		fd:      fd,
		handler: handler,
		stopCh:  make(chan struct{}),
	}
}

// Start begins the background polling goroutine. Safe to call on nil receiver.
func (m *KeyUpdateMonitor) Start() {
	if m == nil {
		return
	}
	go m.run()
}

// Stop terminates the background polling goroutine. Safe to call on nil
// receiver; idempotent.
func (m *KeyUpdateMonitor) Stop() {
	if m == nil {
		return
	}
	m.once.Do(func() { close(m.stopCh) })
}

// isTransientSockoptError returns true for errors that may resolve on retry
// (e.g., interrupted system call, resource temporarily unavailable).
func isTransientSockoptError(err error) bool {
	if errno, ok := err.(syscall.Errno); ok {
		return errno == syscall.EINTR || errno == syscall.EAGAIN
	}
	return false
}

func (m *KeyUpdateMonitor) run() {
	cs := m.handler.CipherSuiteID()
	interval := maxPollInterval
	var prevTxSeq uint64
	prevTime := time.Now()
	rxWarned := false
	transientErrors := 0

	timer := time.NewTimer(interval)
	defer timer.Stop()

	for {
		select {
		case <-m.stopCh:
			return
		case <-timer.C:
		}

		// TX: exact record count from kernel
		txSeq, err := getRecordSeq(m.fd, TLS_TX, cs)
		if err != nil {
			if isTransientSockoptError(err) && transientErrors < maxTransientErrors {
				transientErrors++
				timer.Reset(minPollInterval)
				continue
			}
			errors.LogWarning(nil, "kTLS monitor: getRecordSeq(TX) failed, stopping: ", err)
			return
		}
		transientErrors = 0

		if txSeq >= keyUpdateThreshold {
			if err := m.handler.InitiateUpdate(); err != nil {
				errors.LogWarning(nil, "kTLS monitor: proactive key rotation failed, stopping: ", err)
				return
			}
			// After InitiateUpdate, the kernel has new keys with rec_seq=0.
			prevTxSeq = 0
			prevTime = time.Now()
			rxWarned = false
			interval = maxPollInterval
			timer.Reset(interval)
			continue
		}

		// Adaptive interval based on TX throughput
		now := time.Now()
		elapsed := now.Sub(prevTime).Seconds()
		if elapsed > 0 && txSeq > prevTxSeq {
			rate := float64(txSeq-prevTxSeq) / elapsed
			remaining := float64(keyUpdateThreshold - txSeq)
			est := time.Duration(remaining/rate*float64(time.Second)) / 4
			interval = clampDuration(est, minPollInterval, maxPollInterval)
		} else {
			interval = maxPollInterval
		}
		prevTxSeq = txSeq
		prevTime = now

		// RX: defensive monitoring of peer's record sequence
		rxSeq, err := getRecordSeq(m.fd, TLS_RX, cs)
		if err == nil && !rxWarned && rxSeq >= uint64(float64(keyUpdateThreshold)*rxWarningRatio) {
			errors.LogWarning(nil, "kTLS: peer RX record sequence ", rxSeq,
				" approaching key update threshold ", keyUpdateThreshold)
			rxWarned = true
		}

		timer.Reset(interval)
	}
}

func clampDuration(d, min, max time.Duration) time.Duration {
	if d < min {
		return min
	}
	if d > max {
		return max
	}
	return d
}
