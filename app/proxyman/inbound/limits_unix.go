//go:build unix

package inbound

import (
	"os"
	"strconv"
	"syscall"
)

const (
	maxConnectionsCap = 262144
	fdHeadroom        = 1024
	minFDHeadroom     = 32
)

func autoTuneMaxConnections(fdLimit uint64) int {
	if fdLimit == 0 {
		return 1
	}
	if fdLimit > uint64(maxConnectionsCap) {
		fdLimit = uint64(maxConnectionsCap)
	}

	limit := int(fdLimit)
	if limit <= 1 {
		return 1
	}

	// Reserve file descriptors for logs, sockets, and other runtime resources.
	reserve := limit / 8
	if reserve < minFDHeadroom {
		reserve = minFDHeadroom
	}
	if reserve > fdHeadroom {
		reserve = fdHeadroom
	}
	if reserve >= limit {
		reserve = limit - 1
	}

	return limit - reserve
}

func getMaxConnections() int {
	if s := os.Getenv("XRAY_MAX_CONNECTIONS"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			if n > maxConnectionsCap {
				n = maxConnectionsCap
			}
			return n
		}
	}
	var rlim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rlim); err == nil {
		return autoTuneMaxConnections(rlim.Cur)
	}
	return 65536
}
