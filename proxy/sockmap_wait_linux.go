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

// sockmapPollTimeoutMs is the idle timeout for sockmap forwarding detection.
// If no events arrive within this window, we assume forwarding is stalled and
// fall back to splice/readv.
const sockmapPollTimeoutMs = 30_000 // 30 seconds

const (
	sockmapIdleTimeout  = time.Duration(sockmapPollTimeoutMs) * time.Millisecond
	writerProbeInterval = time.Second
)

// waitForSockmapForwarding waits for sockmap forwarding completion without
// consuming userspace payload. It returns fallback=true if data remains pending
// on the reader socket and caller should fall back to splice/readv.
func waitForSockmapForwarding(readerConn, writerConn net.Conn) (fallback bool, err error) {
	readerTCPConn, ok := readerConn.(*net.TCPConn)
	if !ok {
		return true, fmt.Errorf("reader connection is not TCP")
	}
	writerTCPConn, ok := writerConn.(*net.TCPConn)
	if !ok {
		return true, fmt.Errorf("writer connection is not TCP")
	}

	readerRawConn, err := readerTCPConn.SyscallConn()
	if err != nil {
		return true, err
	}
	writerRawConn, err := writerTCPConn.SyscallConn()
	if err != nil {
		return true, err
	}

	// Bound any temporary read deadlines to this function.
	defer func() {
		_ = readerTCPConn.SetReadDeadline(time.Time{})
	}()

	idleDeadline := time.Now().Add(sockmapIdleTimeout)
	for {
		closed, err := probeSocketClosed(writerRawConn)
		if err != nil {
			return true, err
		}
		if closed {
			return false, nil
		}

		remaining := time.Until(idleDeadline)
		if remaining <= 0 {
			return true, nil
		}
		waitWindow := writerProbeInterval
		if remaining < waitWindow {
			waitWindow = remaining
		}

		if err := readerTCPConn.SetReadDeadline(time.Now().Add(waitWindow)); err != nil {
			return true, err
		}

		event, err := waitForReadableOrClose(readerRawConn)
		if isTimeoutError(err) {
			continue
		}
		if err != nil {
			return true, err
		}

		switch event {
		case readerEventData:
			return true, nil
		case readerEventClosed:
			return false, nil
		default:
			return true, fmt.Errorf("unexpected reader event")
		}
	}
}

type readerEvent uint8

const (
	readerEventData readerEvent = iota + 1
	readerEventClosed
)

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

func probeSocketClosed(rawConn syscall.RawConn) (bool, error) {
	var (
		closed bool
		opErr  error
		peek   [1]byte
	)

	// Use a non-blocking MSG_PEEK probe to detect hangup without consuming
	// payload. This runs under Control (no runtime poll wait) and returns
	// quickly when no data is pending.
	err := rawConn.Control(func(fd uintptr) {
		for {
			n, _, recvErr := unix.Recvfrom(int(fd), peek[:], unix.MSG_PEEK|unix.MSG_DONTWAIT)
			switch {
			case recvErr == nil && n == 0:
				closed = true
				return
			case recvErr == nil && n > 0:
				return
			case recvErr == unix.EINTR:
				continue
			case recvErr == unix.EAGAIN || recvErr == unix.EWOULDBLOCK:
				return
			case isTerminalSocketError(recvErr):
				closed = true
				return
			default:
				opErr = recvErr
				return
			}
		}
	})
	if err != nil {
		return false, err
	}
	if opErr != nil {
		return false, opErr
	}
	return closed, nil
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
