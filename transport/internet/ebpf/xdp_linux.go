//go:build linux

package ebpf

import (
	"fmt"
	"net"
	"os"
	"syscall"
	"unsafe"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

var (
	xdpProgFD  int = -1
	xdpLinkFD  int = -1
	xdpFlowMap int = -1
	xdpIfindex int
)

// buildXDPProgram generates the XDP BPF program bytecode.
// The program parses Ethernet/IPv4/IPv6 + UDP headers, builds a
// flow key from the 5-tuple, and looks it up in the flow map.
// If found, it returns XDP_TX to bounce the packet; otherwise XDP_PASS.
//
// The mapFD placeholder (0) is replaced with the actual map fd at load time
// via patchMapFD.
//
// Stack layout (key at R10-48):
//
//	[R10-48 .. R10-33]: SrcIP  [16]byte  (offset 0)
//	[R10-32 .. R10-17]: DstIP  [16]byte  (offset 16)
//	[R10-16 .. R10-15]: SrcPort uint16   (offset 32)
//	[R10-14 .. R10-13]: DstPort uint16   (offset 34)
//	[R10-12]:           Proto   uint8    (offset 36)
//	[R10-11]:           padding          (offset 37)
//	[R10-10 .. R10-1]:  scratch / alignment padding
func buildXDPProgram() []bpfInsn {
	const (
		xdpPass = 2
		xdpTx   = 3

		ethHdrLen  = 14
		ipv4HdrLen = 20
		ipv6HdrLen = 40
		udpHdrLen  = 8

		// Ethertype values after BPF_LDX_MEM(BPF_H) on little-endian hosts.
		// BPF loads packet bytes in host byte order, so big-endian wire
		// values appear byte-swapped in registers on LE architectures.
		// All supported Go/Linux targets (amd64, arm64, riscv64, loong64)
		// are little-endian, so this is safe without runtime conversion.
		ethTypeIPv4 = 0x0008 // LE representation of 0x0800 (IPv4)
		ethTypeIPv6 = 0xDD86 // LE representation of 0x86DD (IPv6)
		protoUDP    = 17

		// Stack offsets for flow key (base = R10-48)
		stackKey     = -48
		stackSrcIP   = -48 // key+0
		stackDstIP   = -32 // key+16
		stackSrcPort = -16 // key+32
		stackDstPort = -14 // key+34
		stackProto   = -12 // key+36
	)

	// R6 = xdp_md ctx, R7 = data, R8 = data_end
	// R9 = current parse position

	insns := []bpfInsn{
		// Save ctx
		bpfMovReg(bpfRegR6, bpfRegR1), // r6 = ctx (xdp_md)

		// r7 = data (xdp_md->data at offset 0)
		bpfLoadMem(bpfW, bpfRegR7, bpfRegR6, 0),
		// r8 = data_end (xdp_md->data_end at offset 4)
		bpfLoadMem(bpfW, bpfRegR8, bpfRegR6, 4),

		// Zero the stack key area (48 bytes = 6 x 8-byte stores)
		bpfStoreImm(bpfDW, bpfRegR10, int16(stackKey), 0),
		bpfStoreImm(bpfDW, bpfRegR10, int16(stackKey+8), 0),
		bpfStoreImm(bpfDW, bpfRegR10, int16(stackKey+16), 0),
		bpfStoreImm(bpfDW, bpfRegR10, int16(stackKey+24), 0),
		bpfStoreImm(bpfDW, bpfRegR10, int16(stackKey+32), 0),
		bpfStoreImm(bpfDW, bpfRegR10, int16(stackKey+40), 0),

		// --- Bounds check: Ethernet header (14 bytes) ---
		// r9 = data + ETH_HLEN
		bpfMovReg(bpfRegR9, bpfRegR7),
		bpfAddImm(bpfRegR9, ethHdrLen),
		// if r9 > data_end: goto pass
		bpfJmpReg(bpfJGT, bpfRegR9, bpfRegR8, 0), // offset patched below [idx 11]

		// --- Read ethertype at data+12 (2 bytes, network byte order) ---
		bpfLoadMem(bpfH, bpfRegR2, bpfRegR7, 12), // r2 = ethertype (already in host order from memory)

		// Check IPv4
		bpfJmpImm(bpfJEQ, bpfRegR2, ethTypeIPv4, 2), // if ethertype == 0x0800: goto ipv4_parse (skip 2)
		// Check IPv6
		bpfJmpImm(bpfJEQ, bpfRegR2, ethTypeIPv6, 0), // if ethertype == 0x86DD: goto ipv6_parse [patched]
		// Neither: goto pass
		bpfJmpA(0), // goto pass [patched]

		// ==================== IPv4 path ====================
		// --- Bounds check: IPv4 header (20 bytes after Ethernet) ---
		// r9 = data + ETH_HLEN + IPv4_HLEN
		bpfMovReg(bpfRegR9, bpfRegR7), // idx 16
		bpfAddImm(bpfRegR9, ethHdrLen+ipv4HdrLen),
		// if r9 > data_end: goto pass
		bpfJmpReg(bpfJGT, bpfRegR9, bpfRegR8, 0), // goto pass [patched]

		// r3 = pointer to IPv4 header (data + 14)
		bpfMovReg(bpfRegR3, bpfRegR7),
		bpfAddImm(bpfRegR3, ethHdrLen),

		// Read protocol (byte at IPv4 header + 9)
		bpfLoadMem(bpfB, bpfRegR2, bpfRegR3, 9), // r2 = protocol
		// if protocol != UDP: goto pass
		bpfJmpImm(bpfJNE, bpfRegR2, protoUDP, 0), // goto pass [patched]

		// Store protocol in key
		bpfStoreMem(bpfB, bpfRegR10, bpfRegR2, int16(stackProto)),

		// --- Copy SrcIP (4 bytes from IPv4+12, stored in key as IPv4-mapped) ---
		// IPv4 src addr is at IPv4 header + 12
		bpfLoadMem(bpfW, bpfRegR2, bpfRegR3, 12), // r2 = src IPv4
		// Store at key SrcIP[12..15] (IPv4-mapped: ::ffff:x.x.x.x)
		// First set the ffff prefix at SrcIP[10..11]
		bpfStoreImm(bpfH, bpfRegR10, int16(stackSrcIP+10), -1), // 0xffff
		bpfStoreMem(bpfW, bpfRegR10, bpfRegR2, int16(stackSrcIP+12)),

		// --- Copy DstIP (4 bytes from IPv4+16) ---
		bpfLoadMem(bpfW, bpfRegR2, bpfRegR3, 16),               // r2 = dst IPv4
		bpfStoreImm(bpfH, bpfRegR10, int16(stackDstIP+10), -1), // 0xffff
		bpfStoreMem(bpfW, bpfRegR10, bpfRegR2, int16(stackDstIP+12)),

		// --- Bounds check: UDP header (8 bytes after IP) ---
		// r9 = data + ETH_HLEN + IPv4_HLEN + UDP_HLEN
		bpfMovReg(bpfRegR9, bpfRegR7),
		bpfAddImm(bpfRegR9, ethHdrLen+ipv4HdrLen+udpHdrLen),
		bpfJmpReg(bpfJGT, bpfRegR9, bpfRegR8, 0), // goto pass [patched]

		// r4 = pointer to UDP header
		bpfMovReg(bpfRegR4, bpfRegR7),
		bpfAddImm(bpfRegR4, ethHdrLen+ipv4HdrLen),

		// Read src port (UDP+0, 2 bytes, network order) and convert to host order
		bpfLoadMem(bpfH, bpfRegR2, bpfRegR4, 0),
		bpfEndianBE(bpfRegR2, 16), // ntohs: network -> host byte order
		bpfStoreMem(bpfH, bpfRegR10, bpfRegR2, int16(stackSrcPort)),

		// Read dst port (UDP+2, 2 bytes, network order) and convert to host order
		bpfLoadMem(bpfH, bpfRegR2, bpfRegR4, 2),
		bpfEndianBE(bpfRegR2, 16), // ntohs
		bpfStoreMem(bpfH, bpfRegR10, bpfRegR2, int16(stackDstPort)),

		// goto map_lookup
		bpfJmpA(0), // [patched]
	}
	ipv4JmpToLookup := len(insns) - 1

	// ==================== IPv6 path ====================
	ipv6Start := len(insns)
	insns = append(insns,
		// --- Bounds check: IPv6 header (40 bytes after Ethernet) ---
		bpfMovReg(bpfRegR9, bpfRegR7),
		bpfAddImm(bpfRegR9, ethHdrLen+ipv6HdrLen),
		bpfJmpReg(bpfJGT, bpfRegR9, bpfRegR8, 0), // goto pass [patched]

		// r3 = pointer to IPv6 header (data + 14)
		bpfMovReg(bpfRegR3, bpfRegR7),
		bpfAddImm(bpfRegR3, ethHdrLen),

		// Read next header (byte at IPv6 header + 6)
		bpfLoadMem(bpfB, bpfRegR2, bpfRegR3, 6),  // r2 = next_header
		bpfJmpImm(bpfJNE, bpfRegR2, protoUDP, 0), // if not UDP: goto pass [patched]

		// Store protocol
		bpfStoreMem(bpfB, bpfRegR10, bpfRegR2, int16(stackProto)),

		// Copy SrcIP (16 bytes from IPv6+8)
		bpfLoadMem(bpfDW, bpfRegR2, bpfRegR3, 8),
		bpfStoreMem(bpfDW, bpfRegR10, bpfRegR2, int16(stackSrcIP)),
		bpfLoadMem(bpfDW, bpfRegR2, bpfRegR3, 16),
		bpfStoreMem(bpfDW, bpfRegR10, bpfRegR2, int16(stackSrcIP+8)),

		// Copy DstIP (16 bytes from IPv6+24)
		bpfLoadMem(bpfDW, bpfRegR2, bpfRegR3, 24),
		bpfStoreMem(bpfDW, bpfRegR10, bpfRegR2, int16(stackDstIP)),
		bpfLoadMem(bpfDW, bpfRegR2, bpfRegR3, 32),
		bpfStoreMem(bpfDW, bpfRegR10, bpfRegR2, int16(stackDstIP+8)),

		// --- Bounds check: UDP header ---
		bpfMovReg(bpfRegR9, bpfRegR7),
		bpfAddImm(bpfRegR9, ethHdrLen+ipv6HdrLen+udpHdrLen),
		bpfJmpReg(bpfJGT, bpfRegR9, bpfRegR8, 0), // goto pass [patched]

		// r4 = pointer to UDP header
		bpfMovReg(bpfRegR4, bpfRegR7),
		bpfAddImm(bpfRegR4, ethHdrLen+ipv6HdrLen),

		// Read ports and convert to host order
		bpfLoadMem(bpfH, bpfRegR2, bpfRegR4, 0),
		bpfEndianBE(bpfRegR2, 16), // ntohs
		bpfStoreMem(bpfH, bpfRegR10, bpfRegR2, int16(stackSrcPort)),
		bpfLoadMem(bpfH, bpfRegR2, bpfRegR4, 2),
		bpfEndianBE(bpfRegR2, 16), // ntohs
		bpfStoreMem(bpfH, bpfRegR10, bpfRegR2, int16(stackDstPort)),
	)

	// ==================== Map lookup ====================
	mapLookup := len(insns)
	mapFDInsns := bpfLoadMapFD(bpfRegR1, 0) // fd=0 placeholder, patched at load time
	insns = append(insns,
		// r1 = map fd (LD_IMM64, 2 instructions)
		mapFDInsns[0],
		mapFDInsns[1],
		// r2 = &key
		bpfMovReg(bpfRegR2, bpfRegR10),
		bpfAddImm(bpfRegR2, int32(stackKey)),
		// call bpf_map_lookup_elem
		bpfCallHelper(bpfFuncMapLookupElem),
		// if r0 == NULL: goto pass (skip MOV+EXIT = 2 insns)
		bpfJmpImm(bpfJEQ, bpfRegR0, 0, 2),
		// Found: return XDP_TX
		bpfMovImm(bpfRegR0, xdpTx),
		bpfExitInsn(),
	)

	// ==================== XDP_PASS exit ====================
	passIdx := len(insns)
	insns = append(insns,
		bpfMovImm(bpfRegR0, xdpPass),
		bpfExitInsn(),
	)

	// --- Patch jump offsets ---
	// All "goto pass" jumps and the IPv6/lookup branches.
	// BPF jump offset = (target instruction index) - (current instruction index) - 1

	// [idx 11] eth bounds check fail -> pass
	insns[11].off = int16(passIdx - 11 - 1)

	// [idx 13] ethertype == IPv4 -> ipv4 (skip 2 insns: idx 14, 15)
	// Already set to 2 in the literal, no patch needed.

	// [idx 14] ethertype == IPv6 -> ipv6Start
	insns[14].off = int16(ipv6Start - 14 - 1)
	// [idx 15] neither IPv4 nor IPv6 -> pass
	insns[15].off = int16(passIdx - 15 - 1)

	// [idx 18] IPv4 IP header bounds check fail -> pass
	insns[18].off = int16(passIdx - 18 - 1)
	// [idx 22] protocol != UDP -> pass
	insns[22].off = int16(passIdx - 22 - 1)
	// [idx 32] IPv4 UDP bounds check fail -> pass
	insns[32].off = int16(passIdx - 32 - 1)
	// [ipv4JmpToLookup] -> mapLookup
	insns[ipv4JmpToLookup].off = int16(mapLookup - ipv4JmpToLookup - 1)

	// IPv6 path patches (relative to ipv6Start)
	// [ipv6Start+2] IPv6 header bounds check fail -> pass
	insns[ipv6Start+2].off = int16(passIdx - (ipv6Start + 2) - 1)
	// [ipv6Start+6] next_header != UDP -> pass
	insns[ipv6Start+6].off = int16(passIdx - (ipv6Start + 6) - 1)
	// [ipv6Start+18] IPv6 UDP bounds check fail -> pass
	insns[ipv6Start+18].off = int16(passIdx - (ipv6Start + 18) - 1)

	return insns
}

// xdpMapFDPlaceholder is the map fd value in the bytecode that gets replaced.
const xdpMapFDPlaceholder = 0

// patchMapFD patches LD_IMM64 instructions that load map fd placeholders
// with the actual map file descriptor. It looks for LD_IMM64 with
// src_reg == BPF_PSEUDO_MAP_FD and imm == placeholder.
func patchMapFD(insns []uint64, placeholder, actualFD int32) {
	for i := 0; i < len(insns); i++ {
		code := uint8(insns[i])
		srcReg := uint8((insns[i] >> 12) & 0xf)
		imm := int32(insns[i] >> 32)
		// LD_IMM64 with BPF_PSEUDO_MAP_FD
		if code == (bpfClassLD|bpfDW|bpfIMM) && srcReg == bpfPseudoMapFD && imm == placeholder {
			// Replace imm with actual fd
			insns[i] = (insns[i] & 0x00000000FFFFFFFF) | (uint64(uint32(actualFD)) << 32)
		}
	}
}

// attachXDPImpl attaches the XDP program to an interface.
func attachXDPImpl(ifname string, config XDPConfig) error {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return fmt.Errorf("interface %s not found: %w", ifname, err)
	}

	// Create flow map (LRU hash for flow entries)
	flowMapFD, err := createBPFMap(
		21, // BPF_MAP_TYPE_LRU_HASH
		uint32(unsafe.Sizeof(FlowKey{})),
		uint32(unsafe.Sizeof(flowValue{})),
		config.FlowTableSize,
	)
	if err != nil {
		return fmt.Errorf("failed to create flow map: %w", err)
	}

	// Build and load XDP program
	xdpInsns := buildXDPProgram()
	xdpBytecode := encodeBPFInsns(xdpInsns)
	progFD, err := loadXDPProgram(xdpBytecode, flowMapFD)
	if err != nil {
		syscall.Close(flowMapFD)
		return fmt.Errorf("failed to load XDP program: %w", err)
	}

	// Attach to interface
	mode := selectXDPMode(config.Mode, ifname)
	if err := attachXDPToInterface(iface.Index, progFD, mode); err != nil {
		syscall.Close(progFD)
		syscall.Close(flowMapFD)
		return fmt.Errorf("failed to attach XDP to %s: %w", ifname, err)
	}

	// Commit to global state only after all operations succeed.
	// This prevents double-close if a later detachXDPImpl runs against
	// FDs that were already closed in the error paths above.
	xdpFlowMap = flowMapFD
	xdpProgFD = progFD
	xdpIfindex = iface.Index
	return nil
}

// detachXDPImpl detaches XDP from all interfaces.
// Uses best-effort cleanup: closes all FDs even if an earlier step fails.
func detachXDPImpl() error {
	var firstErr error
	if xdpIfindex > 0 && xdpProgFD >= 0 {
		if err := detachXDPFromInterface(xdpIfindex); err != nil {
			firstErr = err
		}
	}

	if xdpProgFD >= 0 {
		syscall.Close(xdpProgFD)
		xdpProgFD = -1
	}
	if xdpFlowMap >= 0 {
		syscall.Close(xdpFlowMap)
		xdpFlowMap = -1
	}
	xdpIfindex = 0

	return firstErr
}

// flowValue is the value stored in the flow map.
type flowValue struct {
	RewriteSrcIP   [16]byte
	RewriteDstIP   [16]byte
	RewriteSrcPort uint16
	RewriteDstPort uint16
	Flags          uint32
}

// flowStats stores per-flow statistics.
type flowStats struct {
	Packets  uint64
	Bytes    uint64
	LastSeen uint64
}

// createBPFMap creates a BPF map.
func createBPFMap(mapType, keySize, valueSize, maxEntries uint32) (int, error) {
	attr := struct {
		mapType    uint32
		keySize    uint32
		valueSize  uint32
		maxEntries uint32
		mapFlags   uint32
	}{
		mapType:    mapType,
		keySize:    keySize,
		valueSize:  valueSize,
		maxEntries: maxEntries,
	}

	fd, _, errno := syscall.Syscall(
		unix.SYS_BPF,
		0, // BPF_MAP_CREATE
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
	)

	if errno != 0 {
		return -1, errno
	}

	return int(fd), nil
}

// loadXDPProgram loads an XDP BPF program with map fd relocation.
// Only the flow map fd is patched into the bytecode; the stats map is
// managed separately from Go userspace via bpfMapLookup/bpfMapUpdate.
func loadXDPProgram(insns []uint64, flowMapFD int) (int, error) {
	// Patch map fd placeholder with actual flow map fd
	patchMapFD(insns, xdpMapFDPlaceholder, int32(flowMapFD))

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

	copy(attr.progName[:], "xray_xdp_udp")

	// Fast path: try without log buffer to avoid 64KB allocation.
	fd, _, errno := syscall.Syscall(
		unix.SYS_BPF,
		5, // BPF_PROG_LOAD
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
	)

	if errno == 0 {
		return int(fd), nil
	}

	// Retry with log buffer for diagnostic info on verifier rejection.
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
		return -1, fmt.Errorf("BPF_PROG_LOAD: %w", errno)
	}

	return int(fd), nil
}

// selectXDPMode selects the appropriate XDP attachment mode.
func selectXDPMode(mode XDPMode, ifname string) uint32 {
	switch mode {
	case XDPModeNative:
		return uint32(unix.XDP_FLAGS_DRV_MODE)
	case XDPModeOffload:
		return uint32(unix.XDP_FLAGS_HW_MODE)
	case XDPModeGeneric:
		return uint32(unix.XDP_FLAGS_SKB_MODE)
	default:
		// Auto mode: try native first, fall back to generic
		// Could probe driver support here
		return 0 // Will try native, then generic
	}
}

// attachXDPToInterface attaches an XDP program to a network interface.
func attachXDPToInterface(ifindex, progFD int, flags uint32) error {
	// Preferred path: BPF_LINK_CREATE.
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
		// Fall back to older interface.
		if err := attachXDPNetlink(ifindex, progFD, flags); err != nil {
			return fmt.Errorf("BPF_LINK_CREATE failed: %w (fallback failed: %v)", errno, err)
		}
		return nil
	}

	if xdpLinkFD >= 0 {
		syscall.Close(xdpLinkFD)
		xdpLinkFD = -1
	}
	xdpLinkFD = int(linkFD)

	return nil
}

// attachXDPNetlink attaches XDP using netlink (for older kernels).
func attachXDPNetlink(ifindex, progFD int, flags uint32) error {
	link, err := netlink.LinkByIndex(ifindex)
	if err != nil {
		return fmt.Errorf("netlink LinkByIndex(%d): %w", ifindex, err)
	}

	if err := netlink.LinkSetXdpFdWithFlags(link, progFD, int(flags)); err != nil {
		return fmt.Errorf("netlink LinkSetXdpFdWithFlags(ifindex=%d progFD=%d flags=%d): %w", ifindex, progFD, flags, err)
	}
	return nil
}

// detachXDPFromInterface detaches XDP from an interface.
func detachXDPFromInterface(ifindex int) error {
	if xdpLinkFD >= 0 {
		err := syscall.Close(xdpLinkFD)
		xdpLinkFD = -1 // Always reset to prevent double-close on retry.
		return err
	}
	return attachXDPNetlink(ifindex, -1, 0)
}

// updateFlowMapImpl updates a flow entry in the BPF map.
func updateFlowMapImpl(key FlowKey, entry *FlowEntry) error {
	if xdpFlowMap < 0 {
		return ErrXDPNotEnabled
	}

	value := flowValue{
		RewriteSrcPort: entry.RewriteSrcPort,
		RewriteDstPort: entry.RewriteDstPort,
	}

	if entry.RewriteSrcIP != nil {
		copy(value.RewriteSrcIP[:], entry.RewriteSrcIP.To16())
	}
	if entry.RewriteDstIP != nil {
		copy(value.RewriteDstIP[:], entry.RewriteDstIP.To16())
	}

	return bpfMapUpdate(xdpFlowMap, unsafe.Pointer(&key), unsafe.Pointer(&value))
}

// deleteFlowMapImpl removes a flow entry from the BPF map.
func deleteFlowMapImpl(key FlowKey) error {
	if xdpFlowMap < 0 {
		return nil
	}

	return bpfMapDelete(xdpFlowMap, unsafe.Pointer(&key))
}

// readFlowStatsImpl reads flow statistics from the BPF map.
func readFlowStatsImpl(key FlowKey, entry *FlowEntry) error {
	// Stats are currently tracked in userspace only; no kernel-side map updates
	// are emitted by the XDP program yet.
	_ = key
	_ = entry
	return nil
}

// bpfMapUpdate updates an entry in a BPF map.
func bpfMapUpdate(fd int, key, value unsafe.Pointer) error {
	attr := struct {
		mapFD uint32
		key   uint64
		value uint64
		flags uint64
	}{
		mapFD: uint32(fd),
		key:   uint64(uintptr(key)),
		value: uint64(uintptr(value)),
		flags: 0, // BPF_ANY
	}

	_, _, errno := syscall.Syscall(
		unix.SYS_BPF,
		2, // BPF_MAP_UPDATE_ELEM
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
	)

	if errno != 0 {
		return errno
	}

	return nil
}

// bpfMapLookup looks up an entry in a BPF map.
func bpfMapLookup(fd int, key, value unsafe.Pointer) error {
	attr := struct {
		mapFD uint32
		key   uint64
		value uint64
	}{
		mapFD: uint32(fd),
		key:   uint64(uintptr(key)),
		value: uint64(uintptr(value)),
	}

	_, _, errno := syscall.Syscall(
		unix.SYS_BPF,
		1, // BPF_MAP_LOOKUP_ELEM
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
	)

	if errno != 0 {
		return errno
	}

	return nil
}

// bpfMapDelete deletes an entry from a BPF map.
func bpfMapDelete(fd int, key unsafe.Pointer) error {
	attr := struct {
		mapFD uint32
		key   uint64
	}{
		mapFD: uint32(fd),
		key:   uint64(uintptr(key)),
	}

	_, _, errno := syscall.Syscall(
		unix.SYS_BPF,
		3, // BPF_MAP_DELETE_ELEM
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
	)

	if errno != 0 && errno != syscall.ENOENT {
		return errno
	}

	return nil
}

// checkXDPDriverSupport checks if the driver supports native XDP.
func checkXDPDriverSupport(ifname string) bool {
	// Check /sys/class/net/<ifname>/device/driver for known XDP-capable drivers
	driverPath := fmt.Sprintf("/sys/class/net/%s/device/driver", ifname)
	link, err := os.Readlink(driverPath)
	if err != nil {
		return false
	}

	// Known XDP-capable drivers
	xdpDrivers := map[string]bool{
		"i40e":       true,
		"ixgbe":      true,
		"mlx5_core":  true,
		"mlx4_en":    true,
		"nfp":        true,
		"bnxt_en":    true,
		"thunder":    true,
		"virtio_net": true,
		"veth":       true,
	}

	// Extract driver name from last path component
	driver := link
	for i := len(link) - 1; i >= 0; i-- {
		if link[i] == '/' {
			driver = link[i+1:]
			break
		}
	}

	return xdpDrivers[driver]
}
