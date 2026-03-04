//go:build linux

package ebpf

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	bpfProgTypeSKSkb       = 14 // BPF_PROG_TYPE_SK_SKB
	bpfProgTypeSKReuseport = 21 // BPF_PROG_TYPE_SK_REUSEPORT
)

// probeCapabilities detects available eBPF features on Linux.
func probeCapabilities() Capabilities {
	caps := Capabilities{}

	// Detect kernel version
	caps.KernelVersion = getKernelVersion()

	// Check for basic eBPF support (requires CAP_BPF or CAP_SYS_ADMIN)
	if !checkBPFSyscall() {
		return caps
	}

	// XDP support: kernel 4.8+
	// XDP_REDIRECT: kernel 5.3+
	if caps.KernelVersion.AtLeast(4, 8, 0) {
		caps.XDPSupported = probXDPSupport()
		if caps.KernelVersion.AtLeast(5, 3, 0) {
			caps.XDPRedirectSupported = caps.XDPSupported
		}
	}

	// Sockmap support: kernel 4.17+
	// Full sk_skb stream parser/verdict: kernel 5.4+
	if caps.KernelVersion.AtLeast(4, 17, 0) {
		caps.SockmapSupported, caps.sockmapProbeStage, caps.sockmapProbeErrno = probeSockmapSupport()
		if caps.KernelVersion.AtLeast(5, 4, 0) {
			caps.SockmapSKSkbSupported = caps.SockmapSupported
		}
	}

	// TC BPF support: kernel 4.1+ (classact)
	if caps.KernelVersion.AtLeast(4, 1, 0) {
		caps.TCBPFSupported = probeTCBPFSupport()
	}

	// SO_REUSEPORT BPF: kernel 4.5+
	if caps.KernelVersion.AtLeast(4, 5, 0) {
		caps.ReuseportBPFSupported = probeReuseportBPFSupport()
	}

	// BTF support: kernel 4.18+
	if caps.KernelVersion.AtLeast(4, 18, 0) {
		caps.BTFSupported = probeBTFSupport()
	}

	return caps
}

// getKernelVersion parses the kernel version from /proc/version or uname.
func getKernelVersion() KernelVersion {
	var utsname unix.Utsname
	if err := unix.Uname(&utsname); err != nil {
		return KernelVersion{}
	}

	release := unix.ByteSliceToString(utsname.Release[:])
	return parseKernelVersion(release)
}

// parseKernelVersion parses a kernel version string like "5.15.0-generic".
func parseKernelVersion(release string) KernelVersion {
	parts := strings.SplitN(release, ".", 4)
	if len(parts) < 2 {
		return KernelVersion{}
	}

	ver := KernelVersion{}
	if v, err := strconv.Atoi(parts[0]); err == nil {
		ver.Major = v
	}
	if v, err := strconv.Atoi(parts[1]); err == nil {
		ver.Minor = v
	}
	if len(parts) >= 3 {
		// Patch might have suffix like "0-generic"
		patchStr := parts[2]
		if idx := strings.IndexAny(patchStr, "-+"); idx > 0 {
			patchStr = patchStr[:idx]
		}
		if v, err := strconv.Atoi(patchStr); err == nil {
			ver.Patch = v
		}
	}

	return ver
}

// checkBPFSyscall checks if the BPF syscall is available and we have permissions.
func checkBPFSyscall() bool {
	// Try a simple BPF_PROG_TYPE_SOCKET_FILTER verification
	// This requires minimal permissions
	attr := struct {
		progType    uint32
		insnCnt     uint32
		insns       uint64
		license     uint64
		logLevel    uint32
		logSize     uint32
		logBuf      uint64
		kernVersion uint32
	}{
		progType: 1, // BPF_PROG_TYPE_SOCKET_FILTER
		insnCnt:  2,
	}

	// Minimal BPF program: r0 = 0; exit
	insns := []uint64{
		0x00000000000000b7, // mov r0, 0
		0x0000000000000095, // exit
	}
	attr.insns = uint64(uintptr(unsafe.Pointer(&insns[0])))

	license := []byte("GPL\x00")
	attr.license = uint64(uintptr(unsafe.Pointer(&license[0])))

	fd, _, errno := syscall.Syscall(
		unix.SYS_BPF,
		5, // BPF_PROG_LOAD
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
	)

	if errno == 0 {
		syscall.Close(int(fd))
		return true
	}

	// EPERM means we don't have permission but BPF syscall exists
	// EINVAL might mean bad parameters but BPF exists
	return errno == syscall.EPERM || errno == syscall.EINVAL
}

// probXDPSupport checks if XDP is available.
func probXDPSupport() bool {
	// Check if we can create an XDP program type
	attr := struct {
		progType    uint32
		insnCnt     uint32
		insns       uint64
		license     uint64
		logLevel    uint32
		logSize     uint32
		logBuf      uint64
		kernVersion uint32
	}{
		progType: 6, // BPF_PROG_TYPE_XDP
		insnCnt:  2,
	}

	// Minimal XDP program: return XDP_PASS
	insns := []uint64{
		0x00000002000000b7, // mov r0, XDP_PASS (2)
		0x0000000000000095, // exit
	}
	attr.insns = uint64(uintptr(unsafe.Pointer(&insns[0])))

	license := []byte("GPL\x00")
	attr.license = uint64(uintptr(unsafe.Pointer(&license[0])))

	fd, _, errno := syscall.Syscall(
		unix.SYS_BPF,
		5, // BPF_PROG_LOAD
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
	)

	if errno == 0 {
		syscall.Close(int(fd))
		return true
	}

	return false
}

// probeSockmapSupport checks if sockmap is available.
// Probes both SOCKMAP creation and SK_SKB program loading, since the
// implementation requires sk_skb (stream parser + verdict) programs.
func probeSockmapSupport() (supported bool, stage sockmapProbeStage, errno syscall.Errno) {
	// Try to create a SOCKMAP
	mapAttr := struct {
		mapType    uint32
		keySize    uint32
		valueSize  uint32
		maxEntries uint32
	}{
		mapType:    15, // BPF_MAP_TYPE_SOCKMAP
		keySize:    4,
		valueSize:  4,
		maxEntries: 1,
	}

	mapFD, _, errno := syscall.Syscall(
		unix.SYS_BPF,
		0, // BPF_MAP_CREATE
		uintptr(unsafe.Pointer(&mapAttr)),
		unsafe.Sizeof(mapAttr),
	)

	if errno != 0 {
		return false, sockmapProbeStageMapCreate, errno
	}
	syscall.Close(int(mapFD))

	// Also verify we can load BPF_PROG_TYPE_SK_SKB (type 14).
	// A kernel that supports SOCKMAP but not sk_skb programs would
	// fail at setup time; detect this early to avoid noisy fallback logs.
	ok, progErrno := probeSKSkbSupport()
	if !ok {
		return false, sockmapProbeStageSKSkbLoad, progErrno
	}
	return true, sockmapProbeStageNone, 0
}

// probeSKSkbSupport checks if BPF_PROG_TYPE_SK_SKB programs can be loaded.
func probeSKSkbSupport() (bool, syscall.Errno) {
	// Minimal sk_skb program: r0 = 1 (SK_PASS); exit
	insns := []uint64{
		0x00000001000000b7, // mov r0, 1
		0x0000000000000095, // exit
	}

	license := []byte("GPL\x00")

	attr := struct {
		progType    uint32
		insnCnt     uint32
		insns       uint64
		license     uint64
		logLevel    uint32
		logSize     uint32
		logBuf      uint64
		kernVersion uint32
	}{
		progType: bpfProgTypeSKSkb,
		insnCnt:  uint32(len(insns)),
		insns:    uint64(uintptr(unsafe.Pointer(&insns[0]))),
		license:  uint64(uintptr(unsafe.Pointer(&license[0]))),
	}

	fd, _, errno := syscall.Syscall(
		unix.SYS_BPF,
		5, // BPF_PROG_LOAD
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
	)

	if errno == 0 {
		syscall.Close(int(fd))
		return true, 0
	}

	return false, errno
}

// probeTCBPFSupport checks if TC BPF classifier is available.
func probeTCBPFSupport() bool {
	// Check if we can create a sched_cls program
	attr := struct {
		progType    uint32
		insnCnt     uint32
		insns       uint64
		license     uint64
		logLevel    uint32
		logSize     uint32
		logBuf      uint64
		kernVersion uint32
	}{
		progType: 3, // BPF_PROG_TYPE_SCHED_CLS
		insnCnt:  2,
	}

	// Minimal TC program: return TC_ACT_OK
	insns := []uint64{
		0x00000000000000b7, // mov r0, TC_ACT_OK (0)
		0x0000000000000095, // exit
	}
	attr.insns = uint64(uintptr(unsafe.Pointer(&insns[0])))

	license := []byte("GPL\x00")
	attr.license = uint64(uintptr(unsafe.Pointer(&license[0])))

	fd, _, errno := syscall.Syscall(
		unix.SYS_BPF,
		5, // BPF_PROG_LOAD
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
	)

	if errno == 0 {
		syscall.Close(int(fd))
		return true
	}

	return false
}

// probeReuseportBPFSupport checks if SO_REUSEPORT BPF is available.
func probeReuseportBPFSupport() bool {
	// Check if we can create an SK_REUSEPORT program
	attr := struct {
		progType    uint32
		insnCnt     uint32
		insns       uint64
		license     uint64
		logLevel    uint32
		logSize     uint32
		logBuf      uint64
		kernVersion uint32
	}{
		progType: bpfProgTypeSKReuseport,
		insnCnt:  2,
	}

	// Minimal program: return 0 (select first socket)
	insns := []uint64{
		0x00000000000000b7, // mov r0, 0
		0x0000000000000095, // exit
	}
	attr.insns = uint64(uintptr(unsafe.Pointer(&insns[0])))

	license := []byte("GPL\x00")
	attr.license = uint64(uintptr(unsafe.Pointer(&license[0])))

	fd, _, errno := syscall.Syscall(
		unix.SYS_BPF,
		5, // BPF_PROG_LOAD
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
	)

	if errno == 0 {
		syscall.Close(int(fd))
		return true
	}

	return false
}

// probeBTFSupport checks if BTF is available.
func probeBTFSupport() bool {
	// Check if /sys/kernel/btf/vmlinux exists
	_, err := os.Stat("/sys/kernel/btf/vmlinux")
	return err == nil
}

// checkCgroupBPF checks if cgroup BPF is available by checking /sys/fs/cgroup.
func checkCgroupBPF() bool {
	file, err := os.Open("/proc/mounts")
	if err != nil {
		return false
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 3 && fields[2] == "cgroup2" {
			return true
		}
	}

	return false
}
