//go:build linux

package proxy

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/xtls/xray-core/common/net"
	"golang.org/x/sys/unix"
)

// sockmapPollTimeoutMs is the base idle timeout for sockmap forwarding detection.
// Keep tight but not overly aggressive; callers extend only when progress is seen.
const sockmapPollTimeoutMs = 5_000 // 5 seconds

const (
	sockmapIdleTimeout   = time.Duration(sockmapPollTimeoutMs) * time.Millisecond
	sockmapMaxIdleRounds = 1 // any 5s no-progress window is enough to fall back
	writerProbeInterval  = 500 * time.Millisecond
)

// waitForSockmapForwarding waits for sockmap forwarding completion without
// consuming userspace payload. It returns fallback=true if data remains pending
// on the reader socket and caller should fall back to splice/readv.
func waitForSockmapForwarding(readerConn, writerConn net.Conn) (fallback bool, obs sockmapForwardObservation, err error) {
	readerTCPConn, ok := readerConn.(*net.TCPConn)
	if !ok {
		return true, sockmapForwardObservation{}, fmt.Errorf("reader connection is not TCP")
	}
	writerTCPConn, ok := writerConn.(*net.TCPConn)
	if !ok {
		return true, sockmapForwardObservation{}, fmt.Errorf("writer connection is not TCP")
	}

	readerRawConn, err := readerTCPConn.SyscallConn()
	if err != nil {
		return true, sockmapForwardObservation{}, err
	}
	writerRawConn, err := writerTCPConn.SyscallConn()
	if err != nil {
		return true, sockmapForwardObservation{}, err
	}

	// Bound any temporary read deadlines to this function.
	defer func() {
		_ = readerTCPConn.SetReadDeadline(time.Time{})
	}()

	progressCursor, progressAvailable, err := readForwardProgressCursor(readerRawConn, writerRawConn)
	if err != nil {
		return true, sockmapForwardObservation{}, err
	}
	idleDeadline := time.Now().Add(sockmapIdleTimeout)
	idleRounds := 0
	for {
		readerState, err := probeSocketState(readerRawConn)
		if err != nil {
			return true, sockmapForwardObservation{}, err
		}
		writerState, err := probeSocketState(writerRawConn)
		if err != nil {
			return true, sockmapForwardObservation{}, err
		}
		if readerState.closed || writerState.closed {
			return false, obs, nil
		}
		// Any readable payload on reader means sockmap is not forwarding this
		// direction; caller should return to userspace/splice path.
		if readerState.hasData {
			return true, obs, nil
		}

		remaining := time.Until(idleDeadline)
		if remaining <= 0 {
			progressed, responseProgressed, err := forwardProgressAdvanced(readerRawConn, writerRawConn, &progressCursor, &progressAvailable)
			if err != nil {
				return true, sockmapForwardObservation{}, err
			}
			if responseProgressed && obs.FirstResponseAt.IsZero() {
				obs.FirstResponseAt = time.Now()
			}
			if progressed {
				idleRounds = 0
				idleDeadline = time.Now().Add(sockmapIdleTimeout)
				continue
			}
			idleRounds++
			if idleRounds >= sockmapMaxIdleRounds {
				return true, obs, nil
			}
			idleDeadline = time.Now().Add(sockmapIdleTimeout)
			continue
		}
		waitWindow := writerProbeInterval
		if remaining < waitWindow {
			waitWindow = remaining
		}

		if err := readerTCPConn.SetReadDeadline(time.Now().Add(waitWindow)); err != nil {
			return true, sockmapForwardObservation{}, err
		}

		event, err := waitForReadableOrClose(readerRawConn)
		if isTimeoutError(err) {
			progressed, responseProgressed, perr := forwardProgressAdvanced(readerRawConn, writerRawConn, &progressCursor, &progressAvailable)
			if perr != nil {
				return true, sockmapForwardObservation{}, perr
			}
			if responseProgressed && obs.FirstResponseAt.IsZero() {
				obs.FirstResponseAt = time.Now()
			}
			if progressed {
				idleRounds = 0
				idleDeadline = time.Now().Add(sockmapIdleTimeout)
			}
			continue
		}
		if err != nil {
			return true, sockmapForwardObservation{}, err
		}

		switch event {
		case readerEventData:
			return true, obs, nil
		case readerEventClosed:
			return false, obs, nil
		default:
			return true, sockmapForwardObservation{}, fmt.Errorf("unexpected reader event")
		}
	}
}

type readerEvent uint8

const (
	readerEventData readerEvent = iota + 1
	readerEventClosed
)

type socketProbe struct {
	hasData bool
	closed  bool
}

type forwardProgressCursor struct {
	readerBytesAcked    uint64
	readerBytesReceived uint64
	writerBytesAcked    uint64
	writerBytesReceived uint64
}

func (p forwardProgressCursor) advancedFrom(prev forwardProgressCursor) bool {
	return p.readerBytesAcked > prev.readerBytesAcked ||
		p.readerBytesReceived > prev.readerBytesReceived ||
		p.writerBytesAcked > prev.writerBytesAcked ||
		p.writerBytesReceived > prev.writerBytesReceived
}

func waitForReadableOrClose(rawConn syscall.RawConn) (readerEvent, error) {
	var (
		event readerEvent
		opErr error
		peek  [1]byte
	)

	// rawConn.Read integrates with Go netpoll. Returning false on EAGAIN asks
	// the runtime to wait for the next readable event without pinning an OS
	// thread in a blocking poll syscall.
	err := rawConn.Read(func(fd uintptr) bool {
		for {
			n, _, recvErr := unix.Recvfrom(int(fd), peek[:], unix.MSG_PEEK|unix.MSG_DONTWAIT)
			switch {
			case recvErr == nil && n > 0:
				event = readerEventData
				return true
			case recvErr == nil && n == 0:
				event = readerEventClosed
				return true
			case recvErr == unix.EINTR:
				continue
			case recvErr == unix.EAGAIN || recvErr == unix.EWOULDBLOCK:
				return false
			case isTerminalSocketError(recvErr):
				event = readerEventClosed
				return true
			default:
				opErr = recvErr
				return true
			}
		}
	})
	if err != nil {
		return 0, err
	}
	if opErr != nil {
		return 0, opErr
	}
	return event, nil
}

func probeSocketState(rawConn syscall.RawConn) (socketProbe, error) {
	var (
		out   socketProbe
		opErr error
		peek  [1]byte
	)

	// Use a non-blocking MSG_PEEK probe to detect hangup without consuming
	// payload. This runs under Control (no runtime poll wait) and returns
	// quickly when no data is pending.
	err := rawConn.Control(func(fd uintptr) {
		for {
			n, _, recvErr := unix.Recvfrom(int(fd), peek[:], unix.MSG_PEEK|unix.MSG_DONTWAIT)
			switch {
			case recvErr == nil && n == 0:
				out.closed = true
				return
			case recvErr == nil && n > 0:
				out.hasData = true
				return
			case recvErr == unix.EINTR:
				continue
			case recvErr == unix.EAGAIN || recvErr == unix.EWOULDBLOCK:
				return
			case isTerminalSocketError(recvErr):
				out.closed = true
				return
			default:
				opErr = recvErr
				return
			}
		}
	})
	if err != nil {
		return socketProbe{}, err
	}
	if opErr != nil {
		return socketProbe{}, opErr
	}
	return out, nil
}

func forwardProgressAdvanced(readerRawConn, writerRawConn syscall.RawConn, cursor *forwardProgressCursor, available *bool) (bool, bool, error) {
	current, currentAvailable, err := readForwardProgressCursor(readerRawConn, writerRawConn)
	if err != nil {
		return false, false, err
	}
	if !currentAvailable {
		*available = false
		return false, false, nil
	}
	if !*available {
		*cursor = current
		*available = true
		return true, false, nil
	}
	responseProgressed := current.readerBytesReceived > cursor.readerBytesReceived
	progressed := current.advancedFrom(*cursor)
	*cursor = current
	return progressed, responseProgressed, nil
}

func readForwardProgressCursor(readerRawConn, writerRawConn syscall.RawConn) (forwardProgressCursor, bool, error) {
	readerAcked, readerRecv, readerAvailable, err := readSocketTCPProgress(readerRawConn)
	if err != nil {
		return forwardProgressCursor{}, false, err
	}
	writerAcked, writerRecv, writerAvailable, err := readSocketTCPProgress(writerRawConn)
	if err != nil {
		return forwardProgressCursor{}, false, err
	}
	if !readerAvailable || !writerAvailable {
		return forwardProgressCursor{}, false, nil
	}
	return forwardProgressCursor{
		readerBytesAcked:    readerAcked,
		readerBytesReceived: readerRecv,
		writerBytesAcked:    writerAcked,
		writerBytesReceived: writerRecv,
	}, true, nil
}

func readSocketTCPProgress(rawConn syscall.RawConn) (bytesAcked uint64, bytesReceived uint64, available bool, err error) {
	var opErr error
	err = rawConn.Control(func(fd uintptr) {
		info, serr := unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
		if serr != nil {
			switch serr {
			case unix.ENOPROTOOPT, unix.EOPNOTSUPP:
				available = false
				return
			default:
				opErr = serr
				return
			}
		}
		available = true
		bytesAcked = info.Bytes_acked
		bytesReceived = info.Bytes_received
	})
	if err != nil {
		return 0, 0, false, err
	}
	if opErr != nil {
		return 0, 0, false, opErr
	}
	return bytesAcked, bytesReceived, available, nil
}

func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var netErr interface{ Timeout() bool }
	return errors.As(err, &netErr) && netErr.Timeout()
}

func isTerminalSocketError(err error) bool {
	return err == unix.ECONNRESET ||
		err == unix.ENOTCONN ||
		err == unix.EPIPE ||
		err == unix.ESHUTDOWN
}
