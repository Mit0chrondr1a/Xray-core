package inbound

import (
	"os"
	"strconv"
	"time"
)

func getMaxUDPSessions() int {
	return getMaxConnections() / 4
}

const maxQueueTimeout = 30 * time.Second

func getQueueTimeout() time.Duration {
	if s := os.Getenv("XRAY_CONNECTION_QUEUE_TIMEOUT_MS"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			d := time.Duration(n) * time.Millisecond
			if d > maxQueueTimeout {
				d = maxQueueTimeout
			}
			return d
		}
	}
	return time.Second
}
