//go:build unix

package inbound

import (
	"os"
	"strconv"
	"syscall"
)

const maxConnectionsCap = 262144

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
		limit := int(rlim.Cur) - 1024 // headroom for non-connection FDs
		if limit > 262144 {
			limit = 262144
		}
		if limit < 1024 {
			limit = 1024
		}
		return limit
	}
	return 65536
}
