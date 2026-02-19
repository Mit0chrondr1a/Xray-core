package splithttp

import (
	"os"
	"strconv"
)

const (
	defaultMaxConcurrentSessions = 12288
	maxConcurrentSessionsCap     = 65536
)

func parseMaxConcurrentSessions(raw string) int64 {
	if raw == "" {
		return 0
	}

	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return 0
	}
	if n > maxConcurrentSessionsCap {
		n = maxConcurrentSessionsCap
	}
	return int64(n)
}

func getMaxConcurrentSessions() int64 {
	// XRAY_XHTTP_MAX_SESSIONS allows explicit tuning for XHTTP session fan-out.
	if configured := parseMaxConcurrentSessions(os.Getenv("XRAY_XHTTP_MAX_SESSIONS")); configured > 0 {
		return configured
	}
	return defaultMaxConcurrentSessions
}
