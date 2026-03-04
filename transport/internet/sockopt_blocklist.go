package internet

import "github.com/xtls/xray-core/common/errors"

// isBlockedSockopt returns true if the (level, opt) pair is blocked for security.
// These options could enable privilege escalation or traffic hijacking via user config.
// Uses raw integer constants to work across all platforms, since CustomSockopt
// Level/Opt are parsed from raw numeric strings in user config.
func isBlockedSockopt(level, opt int) bool {
	const (
		// SOL_SOCKET values differ by platform: Linux=1, Darwin/BSD/Windows=0xFFFF
		solSocketLinux = 1
		solSocketBSD   = 0xFFFF
		solTCP         = 6 // IPPROTO_TCP, same on all platforms

		soAttachBPF          = 50 // SO_ATTACH_BPF: load arbitrary BPF programs (Linux)
		soAttachFilter       = 26 // SO_ATTACH_FILTER: attach packet filters (Linux/BSD)
		soAttachReuseportBPF = 52 // SO_ATTACH_REUSEPORT_EBPF (Linux)
		tcpRepair            = 19 // TCP_REPAIR: hijack TCP connections (Linux)
	)

	// Block dangerous SOL_SOCKET options on both Linux (level=1) and BSD/Windows (level=0xFFFF)
	if level == solSocketLinux || level == solSocketBSD {
		switch opt {
		case soAttachBPF, soAttachFilter, soAttachReuseportBPF:
			return true
		}
	}

	// Block TCP_REPAIR (Linux-specific, but block the numeric value on all platforms)
	if level == solTCP && opt == tcpRepair {
		return true
	}

	return false
}

// validateCustomSockopt checks if a custom socket option is allowed.
// Returns an error if the option is blocked for security reasons.
func validateCustomSockopt(level, opt int) error {
	if isBlockedSockopt(level, opt) {
		return errors.New("CustomSockopt: blocked dangerous socket option level=", level, " opt=", opt)
	}
	return nil
}
