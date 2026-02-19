package inbound

import (
	"os"
	"strconv"
	"time"
)

const (
	defaultQueueTimeout     = 2 * time.Second
	maxQueueTimeout         = 30 * time.Second
	defaultUDPSessionsFloor = 256
	defaultUDPSessionsCap   = 16384
	maxUDPSessionsConfigCap = 65536
)

func autoTuneUDPSessions(maxConnections int) int {
	if maxConnections <= 0 {
		return defaultUDPSessionsFloor
	}

	sessions := maxConnections / 4
	if sessions < defaultUDPSessionsFloor {
		sessions = defaultUDPSessionsFloor
	}
	if sessions > defaultUDPSessionsCap {
		sessions = defaultUDPSessionsCap
	}
	return sessions
}

func parseMaxUDPSessions(raw string) int {
	if raw == "" {
		return 0
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return 0
	}
	if n > maxUDPSessionsConfigCap {
		n = maxUDPSessionsConfigCap
	}
	return n
}

func getMaxUDPSessions() int {
	// XRAY_MAX_UDP_SESSIONS allows explicit tuning for high-churn UDP workloads.
	if configured := parseMaxUDPSessions(os.Getenv("XRAY_MAX_UDP_SESSIONS")); configured > 0 {
		return configured
	}
	return autoTuneUDPSessions(getMaxConnections())
}

func parseQueueTimeoutMS(raw string) time.Duration {
	if raw == "" {
		return defaultQueueTimeout
	}

	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return defaultQueueTimeout
	}

	d := time.Duration(n) * time.Millisecond
	if d > maxQueueTimeout {
		d = maxQueueTimeout
	}
	return d
}

func getQueueTimeout() time.Duration {
	// XRAY_CONNECTION_QUEUE_TIMEOUT_MS controls how long new connections/sessions
	// may wait for a free worker slot before being rejected.
	return parseQueueTimeoutMS(os.Getenv("XRAY_CONNECTION_QUEUE_TIMEOUT_MS"))
}
