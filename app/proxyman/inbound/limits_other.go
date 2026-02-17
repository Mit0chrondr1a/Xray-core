//go:build !unix

package inbound

import (
	"os"
	"strconv"
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
	return 65536
}
