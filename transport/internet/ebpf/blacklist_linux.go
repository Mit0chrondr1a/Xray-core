//go:build linux

package ebpf

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// enableXDP loads the blacklist XDP program and attaches it to the interface.
func (m *BlacklistManager) enableXDP(ifname string) error {
	caps := GetCapabilities()
	if !caps.XDPSupported {
		return ErrXDPNotSupported
	}

	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return fmt.Errorf("interface %s not found: %w", ifname, err)
	}

	maxEntries := m.config.MaxEntries
	if maxEntries == 0 {
		maxEntries = 4096
	}

	// Create LRU hash map: key=[16]byte (IP), value=uint64 (placeholder).
	mapFD, err := createBPFMap(
		bpfMapTypeLRUHash,
		16, // key size: [16]byte
		8,  // value size: uint64
		maxEntries,
	)
	if err != nil {
		return fmt.Errorf("failed to create blacklist map: %w", err)
	}

	// Build and load XDP program.
	xdpInsns := buildBlacklistXDPProgram()
	xdpBytecode := encodeBPFInsns(xdpInsns)
	progFD, err := loadBlacklistXDPProgram(xdpBytecode, mapFD)
	if err != nil {
		syscall.Close(mapFD)
		return fmt.Errorf("failed to load blacklist XDP program: %w", err)
	}

	// Attach to interface.
	mode := selectXDPMode(XDPModeAuto, ifname)
	linkFD, err := attachBlacklistXDP(iface.Index, progFD, mode)
	if err != nil {
		syscall.Close(progFD)
		syscall.Close(mapFD)
		return fmt.Errorf("failed to attach blacklist XDP to %s: %w", ifname, err)
	}

	m.mapFD = mapFD
	m.progFD = progFD
	m.linkFD = linkFD
	m.ifindex = iface.Index
	return nil
}

// disableXDP detaches the XDP program and closes BPF fds.
func (m *BlacklistManager) disableXDP() error {
	var firstErr error
	if m.ifindex > 0 {
		if m.linkFD >= 0 {
			if err := syscall.Close(m.linkFD); err != nil && firstErr == nil {
				firstErr = err
			}
			m.linkFD = -1
		} else if m.progFD >= 0 {
			// Detach via netlink for older kernels.
			if err := detachXDPFromInterface(m.ifindex); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}

	if m.progFD >= 0 {
		syscall.Close(m.progFD)
		m.progFD = -1
	}
	if m.mapFD >= 0 {
		syscall.Close(m.mapFD)
		m.mapFD = -1
	}
	m.ifindex = 0
	return firstErr
}

// bpfMapUpdateBlacklist adds an IP key to the blacklist BPF map.
func bpfMapUpdateBlacklist(fd int, key [16]byte) {
	var value uint64 // placeholder value
	_ = bpfMapUpdate(fd, unsafe.Pointer(&key), unsafe.Pointer(&value))
}

// bpfMapDeleteBlacklist removes an IP key from the blacklist BPF map.
func bpfMapDeleteBlacklist(fd int, key [16]byte) {
	_ = bpfMapDelete(fd, unsafe.Pointer(&key))
}

// loadBlacklistXDPProgram loads the blacklist XDP BPF program with map fd relocation.
func loadBlacklistXDPProgram(insns []uint64, blacklistMapFD int) (int, error) {
	patchMapFD(insns, blacklistXDPMapFDPlaceholder, int32(blacklistMapFD))

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
		progFlags   uint32
		progName    [16]byte
	}{
		progType: 6, // BPF_PROG_TYPE_XDP
		insnCnt:  uint32(len(insns)),
		insns:    uint64(uintptr(unsafe.Pointer(&insns[0]))),
		license:  uint64(uintptr(unsafe.Pointer(&license[0]))),
	}

	copy(attr.progName[:], "xray_xdp_bl")

	// Fast path: try without log buffer.
	fd, _, errno := syscall.Syscall(
		unix.SYS_BPF,
		5, // BPF_PROG_LOAD
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
	)

	if errno == 0 {
		return int(fd), nil
	}

	// Retry with log buffer for diagnostics.
	logBuf := make([]byte, 65536)
	attr.logLevel = 1
	attr.logSize = uint32(len(logBuf))
	attr.logBuf = uint64(uintptr(unsafe.Pointer(&logBuf[0])))

	fd, _, errno = syscall.Syscall(
		unix.SYS_BPF,
		5,
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
	)
	if errno != 0 {
		return -1, fmt.Errorf("BPF_PROG_LOAD blacklist: %w", errno)
	}

	return int(fd), nil
}

// attachBlacklistXDP attaches the blacklist XDP program to a network interface.
// Returns link fd when BPF_LINK_CREATE succeeds, otherwise -1 when netlink fallback is used.
func attachBlacklistXDP(ifindex, progFD int, flags uint32) (int, error) {
	attr := struct {
		progFD        uint32
		targetIfindex uint32
		attachType    uint32
		attachFlags   uint32
	}{
		progFD:        uint32(progFD),
		targetIfindex: uint32(ifindex),
		attachType:    37, // BPF_XDP
		attachFlags:   flags,
	}

	linkFD, _, errno := syscall.Syscall(
		unix.SYS_BPF,
		28, // BPF_LINK_CREATE
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
	)

	if errno != 0 {
		// Fall back to netlink for older kernels.
		if err := attachXDPNetlink(ifindex, progFD, flags); err != nil {
			return -1, fmt.Errorf("BPF_LINK_CREATE failed: %w (fallback failed: %v)", errno, err)
		}
		return -1, nil
	}

	return int(linkFD), nil
}

// blacklistXDPMapFDPlaceholder is the placeholder fd in the bytecode.
const blacklistXDPMapFDPlaceholder = 0

// buildBlacklistXDPProgram generates the blacklist XDP BPF program bytecode.
// The program is simpler than the flow XDP: it only extracts the source IP,
// looks it up in the blacklist map, and returns XDP_DROP or XDP_PASS.
//
// Stack layout (key at R10-16):
//
//	[R10-16 .. R10-1]: IP key [16]byte
func buildBlacklistXDPProgram() []bpfInsn {
	const (
		xdpDrop = 1
		xdpPass = 2

		ethHdrLen  = 14
		ipv4HdrLen = 20
		ipv6HdrLen = 40

		// LE byte-swapped ethertype values (same as flow XDP).
		ethTypeIPv4 = 0x0008
		ethTypeIPv6 = 0xDD86

		// Stack offset for the 16-byte IP key.
		stackKey = -16
	)

	insns := []bpfInsn{
		// Save ctx.
		bpfMovReg(bpfRegR6, bpfRegR1), // r6 = ctx (xdp_md)

		// r7 = data, r8 = data_end
		bpfLoadMem(bpfW, bpfRegR7, bpfRegR6, 0),
		bpfLoadMem(bpfW, bpfRegR8, bpfRegR6, 4),

		// Zero the 16-byte key on stack.
		bpfStoreImm(bpfDW, bpfRegR10, int16(stackKey), 0),
		bpfStoreImm(bpfDW, bpfRegR10, int16(stackKey+8), 0),

		// --- Bounds check: Ethernet header (14 bytes) ---
		bpfMovReg(bpfRegR9, bpfRegR7),
		bpfAddImm(bpfRegR9, ethHdrLen),
		bpfJmpReg(bpfJGT, bpfRegR9, bpfRegR8, 0), // -> pass [idx 7, patched]

		// Read ethertype at data+12.
		bpfLoadMem(bpfH, bpfRegR2, bpfRegR7, 12),

		// Check IPv4.
		bpfJmpImm(bpfJEQ, bpfRegR2, ethTypeIPv4, 2), // -> ipv4 (skip 2)
		// Check IPv6.
		bpfJmpImm(bpfJEQ, bpfRegR2, ethTypeIPv6, 0), // -> ipv6 [idx 10, patched]
		// Neither: pass.
		bpfJmpA(0), // -> pass [idx 11, patched]

		// ==================== IPv4 path ====================
		// Bounds check: need at least ETH+IPv4 (34 bytes).
		bpfMovReg(bpfRegR9, bpfRegR7), // idx 12
		bpfAddImm(bpfRegR9, ethHdrLen+ipv4HdrLen),
		bpfJmpReg(bpfJGT, bpfRegR9, bpfRegR8, 0), // -> pass [idx 14, patched]

		// r3 = pointer to IPv4 header.
		bpfMovReg(bpfRegR3, bpfRegR7),
		bpfAddImm(bpfRegR3, ethHdrLen),

		// Extract src IP (4 bytes at IPv4+12), store as IPv4-mapped IPv6.
		bpfLoadMem(bpfW, bpfRegR2, bpfRegR3, 12),
		bpfStoreImm(bpfH, bpfRegR10, int16(stackKey+10), -1), // 0xffff
		bpfStoreMem(bpfW, bpfRegR10, bpfRegR2, int16(stackKey+12)),

		// goto map_lookup
		bpfJmpA(0), // [idx 20, patched]
	}
	ipv4JmpToLookup := len(insns) - 1

	// ==================== IPv6 path ====================
	ipv6Start := len(insns)
	insns = append(insns,
		// Bounds check: need at least ETH+IPv6 (54 bytes).
		bpfMovReg(bpfRegR9, bpfRegR7),
		bpfAddImm(bpfRegR9, ethHdrLen+ipv6HdrLen),
		bpfJmpReg(bpfJGT, bpfRegR9, bpfRegR8, 0), // -> pass [patched]

		// r3 = pointer to IPv6 header.
		bpfMovReg(bpfRegR3, bpfRegR7),
		bpfAddImm(bpfRegR3, ethHdrLen),

		// Copy src IP (16 bytes at IPv6+8) directly as key.
		bpfLoadMem(bpfDW, bpfRegR2, bpfRegR3, 8),
		bpfStoreMem(bpfDW, bpfRegR10, bpfRegR2, int16(stackKey)),
		bpfLoadMem(bpfDW, bpfRegR2, bpfRegR3, 16),
		bpfStoreMem(bpfDW, bpfRegR10, bpfRegR2, int16(stackKey+8)),
	)

	// ==================== Map lookup ====================
	mapLookup := len(insns)
	mapFDInsns := bpfLoadMapFD(bpfRegR1, blacklistXDPMapFDPlaceholder)
	insns = append(insns,
		// r1 = map fd (LD_IMM64, 2 instructions).
		mapFDInsns[0],
		mapFDInsns[1],
		// r2 = &key
		bpfMovReg(bpfRegR2, bpfRegR10),
		bpfAddImm(bpfRegR2, int32(stackKey)),
		// call bpf_map_lookup_elem
		bpfCallHelper(bpfFuncMapLookupElem),
		// if r0 == NULL: goto pass (skip 2: MOV+EXIT)
		bpfJmpImm(bpfJEQ, bpfRegR0, 0, 2),
		// Found: return XDP_DROP
		bpfMovImm(bpfRegR0, xdpDrop),
		bpfExitInsn(),
	)

	// ==================== XDP_PASS exit ====================
	passIdx := len(insns)
	insns = append(insns,
		bpfMovImm(bpfRegR0, xdpPass),
		bpfExitInsn(),
	)

	// --- Patch jump offsets ---
	// [idx 7] eth bounds check -> pass
	insns[7].off = int16(passIdx - 7 - 1)
	// [idx 10] ethertype == IPv6 -> ipv6Start
	insns[10].off = int16(ipv6Start - 10 - 1)
	// [idx 11] neither -> pass
	insns[11].off = int16(passIdx - 11 - 1)
	// [idx 14] IPv4 bounds check -> pass
	insns[14].off = int16(passIdx - 14 - 1)
	// [ipv4JmpToLookup] -> mapLookup
	insns[ipv4JmpToLookup].off = int16(mapLookup - ipv4JmpToLookup - 1)
	// [ipv6Start+2] IPv6 bounds check -> pass
	insns[ipv6Start+2].off = int16(passIdx - (ipv6Start + 2) - 1)

	return insns
}
