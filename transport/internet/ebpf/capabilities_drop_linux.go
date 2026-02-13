//go:build linux

package ebpf

import (
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// capUserHeader is the Linux capability header for _LINUX_CAPABILITY_VERSION_3.
type capUserHeader struct {
	Version uint32
	Pid     int32
}

// capUserData is the Linux capability data for one 32-bit word.
type capUserData struct {
	Effective   uint32
	Permitted   uint32
	Inheritable uint32
}

// capMask returns a bitmask for the given capability number.
func capMask(cap int) uint64 { return 1 << uint(cap) }

// dropExcessCapabilities restricts the process to only CAP_BPF and CAP_NET_ADMIN.
// This is defense-in-depth: after BPF maps and programs are set up, we shed all
// other capabilities to minimize the attack surface.
//
// Steps:
//  1. Drop capabilities from the bounding set (affects future threads)
//  2. Restrict effective + permitted sets via capset()
//  3. Set PR_SET_NO_NEW_PRIVS to prevent future privilege escalation
func dropExcessCapabilities() error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	keepSet := capMask(unix.CAP_BPF) | capMask(unix.CAP_NET_ADMIN)

	// 1. Drop from bounding set (inherited by future OS threads).
	lastCap := unix.CAP_LAST_CAP
	for cap := 0; cap <= lastCap; cap++ {
		if keepSet&capMask(cap) != 0 {
			continue
		}
		// PR_CAPBSET_DROP = 24
		_, _, errno := syscall.Syscall6(syscall.SYS_PRCTL, unix.PR_CAPBSET_DROP, uintptr(cap), 0, 0, 0, 0)
		if errno != 0 && errno != syscall.EINVAL {
			// EINVAL means cap number not recognized — safe to ignore
			return fmt.Errorf("PR_CAPBSET_DROP cap %d: %w", cap, errno)
		}
	}

	// 2. Restrict effective + permitted via capset() syscall.
	// _LINUX_CAPABILITY_VERSION_3 = 0x20080522, covers caps 0-63.
	var hdr capUserHeader
	var data [2]capUserData

	hdr.Version = 0x20080522
	hdr.Pid = 0 // current thread

	// Read current caps first.
	_, _, errno := syscall.Syscall(
		syscall.SYS_CAPGET,
		uintptr(unsafe.Pointer(&hdr)),
		uintptr(unsafe.Pointer(&data[0])),
		0,
	)
	if errno != 0 {
		return fmt.Errorf("capget: %w", errno)
	}

	// Restrict to only keepSet.
	for i := 0; i < 2; i++ {
		mask := uint32(keepSet >> (32 * i))
		data[i].Effective = mask
		data[i].Permitted = mask
		data[i].Inheritable = 0
	}

	_, _, errno = syscall.Syscall(
		syscall.SYS_CAPSET,
		uintptr(unsafe.Pointer(&hdr)),
		uintptr(unsafe.Pointer(&data[0])),
		0,
	)
	if errno != 0 {
		return fmt.Errorf("capset: %w", errno)
	}

	// 3. Prevent future privilege escalation.
	_, _, errno = syscall.Syscall6(syscall.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0, 0)
	if errno != 0 {
		return fmt.Errorf("PR_SET_NO_NEW_PRIVS: %w", errno)
	}

	return nil
}
