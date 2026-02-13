//go:build linux

package ebpf

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

var (
	sockmapFD         int = -1
	sockhashFD        int = -1
	skSkbParserFD     int = -1
	skSkbVerdictFD    int = -1
	sockmapMaxEntries uint32

	sockmapSlotMu sync.Mutex
	sockmapSlots  map[int]uint32
	sockmapFree   []uint32
	sockmapNext   atomic.Uint32
)

// buildSKSkbParserProgram generates a minimal sk_skb stream parser that
// accepts all available data by returning skb->len.
//
// Context: struct __sk_buff * (R1)
// Return:  message length to process
func buildSKSkbParserProgram() []bpfInsn {
	return []bpfInsn{
		// r0 = skb->len (__sk_buff.len is at offset 0)
		bpfLoadMem(bpfW, bpfRegR0, bpfRegR1, 0),
		bpfExitInsn(),
	}
}

// buildSKSkbVerdictProgram generates the sk_skb stream verdict BPF program.
// When data arrives on a socket in the SOCKMAP, this program fires:
//  1. Gets the receiving socket's cookie via bpf_get_socket_cookie
//  2. Looks up the cookie in the SOCKHASH to find the paired socket
//  3. Redirects the data to the paired socket's egress (send) path
//
// This achieves true zero-copy TCP proxying — data arriving from the
// network on one socket is forwarded directly to the paired socket
// without ever entering userspace.
//
// Context: struct __sk_buff * (R1)
// Return:  SK_PASS (1) always — on redirect failure, data proceeds normally
//
// Stack layout:
//
//	[R10-8 .. R10-1]: key (uint64 socket cookie)
func buildSKSkbVerdictProgram() []bpfInsn {
	const (
		skPass   = 1
		stackKey = -8
	)

	insns := []bpfInsn{
		// r6 = skb (callee-saved)
		bpfMovReg(bpfRegR6, bpfRegR1),

		// Zero the key area on the stack
		bpfStoreImm(bpfDW, bpfRegR10, int16(stackKey), 0),

		// r1 = skb for bpf_get_socket_cookie
		bpfMovReg(bpfRegR1, bpfRegR6),
		// r0 = bpf_get_socket_cookie(skb) — helper #46
		bpfCallHelper(bpfFuncGetSocketCookie),

		// Store full 64-bit cookie as key (map uses uint64 keys)
		bpfStoreMem(bpfDW, bpfRegR10, bpfRegR0, int16(stackKey)),

		// Set up args for bpf_sk_redirect_hash(skb, map, key, flags)
		// r1 = skb
		bpfMovReg(bpfRegR1, bpfRegR6),
	}

	// r2 = sockhash map fd (LD_IMM64, 2 instructions, patched at load time)
	mapFDInsns := bpfLoadMapFD(bpfRegR2, 0) // placeholder fd=0
	insns = append(insns,
		mapFDInsns[0],
		mapFDInsns[1],
		// r3 = &key (pointer to stack)
		bpfMovReg(bpfRegR3, bpfRegR10),
		bpfAddImm(bpfRegR3, int32(stackKey)),
		// r4 = flags (0 = redirect to egress path of target socket)
		bpfMovImm(bpfRegR4, 0),
		// call bpf_sk_redirect_hash — helper #72
		bpfCallHelper(bpfFuncSKRedirectHash),

		// Always return SK_PASS.
		// If redirect succeeded (r0 == SK_PASS), the data was forwarded
		// to the paired socket's egress (send) path.
		// If redirect failed (r0 == SK_DROP), we return SK_PASS so the
		// data proceeds to the original socket (userspace fallback).
		bpfMovImm(bpfRegR0, skPass),
		bpfExitInsn(),
	)

	return insns
}

// skSkbMapFDPlaceholder is the map fd value in the bytecode that gets replaced.
const skSkbMapFDPlaceholder = 0

// setupSockmapImpl creates the sockmap, sockhash, and sk_skb programs.
func setupSockmapImpl(config SockmapConfig) error {
	// Create SOCKHASH map for socket cookie → socket lookup (used by verdict program)
	hashFD, err := createBPFMap(
		18, // BPF_MAP_TYPE_SOCKHASH
		8,  // key size (uint64 cookie)
		4,  // value size (socket fd, resolved to socket by kernel)
		config.MaxEntries,
	)
	if err != nil {
		return fmt.Errorf("failed to create sockhash map: %w", err)
	}

	// Create SOCKMAP for storing sockets (sk_skb programs attach here;
	// incoming data on any socket in this map triggers the programs)
	mapFD, err := createBPFMap(
		15, // BPF_MAP_TYPE_SOCKMAP
		4,
		4,
		config.MaxEntries,
	)
	if err != nil {
		syscall.Close(hashFD)
		return fmt.Errorf("failed to create sockmap: %w", err)
	}

	// Build and load sk_skb stream parser
	parserInsns := buildSKSkbParserProgram()
	parserBytecode := encodeBPFInsns(parserInsns)
	parserFD, err := loadSKSkbProgram(parserBytecode, 0, "xray_skb_parse")
	if err != nil {
		syscall.Close(hashFD)
		syscall.Close(mapFD)
		return fmt.Errorf("failed to load sk_skb parser: %w", err)
	}

	// Build and load sk_skb stream verdict
	verdictInsns := buildSKSkbVerdictProgram()
	verdictBytecode := encodeBPFInsns(verdictInsns)
	verdictFD, err := loadSKSkbProgram(verdictBytecode, hashFD, "xray_skb_vrdt")
	if err != nil {
		syscall.Close(parserFD)
		syscall.Close(hashFD)
		syscall.Close(mapFD)
		return fmt.Errorf("failed to load sk_skb verdict: %w", err)
	}

	// Attach both programs to sockmap
	if err := attachSKSkbToSockmap(parserFD, verdictFD, mapFD); err != nil {
		syscall.Close(verdictFD)
		syscall.Close(parserFD)
		syscall.Close(hashFD)
		syscall.Close(mapFD)
		return fmt.Errorf("failed to attach sk_skb programs: %w", err)
	}

	// Commit to global state only after all operations succeed.
	// This prevents double-close if teardownSockmapImpl runs after a
	// partial setup failure that already closed the local FDs above.
	sockhashFD = hashFD
	sockmapFD = mapFD
	skSkbParserFD = parserFD
	skSkbVerdictFD = verdictFD
	sockmapSlotMu.Lock()
	sockmapMaxEntries = config.MaxEntries
	sockmapSlots = make(map[int]uint32)
	sockmapFree = nil
	sockmapNext.Store(0)
	sockmapSlotMu.Unlock()

	return nil
}

// teardownSockmapImpl cleans up sockmap resources.
// Closing the SOCKMAP fd implicitly detaches all attached programs.
func teardownSockmapImpl() error {
	if skSkbVerdictFD >= 0 {
		syscall.Close(skSkbVerdictFD)
		skSkbVerdictFD = -1
	}
	if skSkbParserFD >= 0 {
		syscall.Close(skSkbParserFD)
		skSkbParserFD = -1
	}
	if sockhashFD >= 0 {
		syscall.Close(sockhashFD)
		sockhashFD = -1
	}
	if sockmapFD >= 0 {
		syscall.Close(sockmapFD)
		sockmapFD = -1
	}
	sockmapSlotMu.Lock()
	sockmapMaxEntries = 0
	sockmapSlots = nil
	sockmapFree = nil
	sockmapNext.Store(0)
	sockmapSlotMu.Unlock()
	return nil
}

// addToSockmapImpl adds a socket to the sockmap.
func addToSockmapImpl(fd int) error {
	if sockmapFD < 0 {
		return ErrSockmapNotEnabled
	}

	slot, created, err := assignSockmapSlot(fd)
	if err != nil {
		return err
	}

	key := slot
	value := uint32(fd)

	if err := bpfMapUpdate(sockmapFD, unsafe.Pointer(&key), unsafe.Pointer(&value)); err != nil {
		if created {
			releaseSockmapSlot(fd)
		}
		return err
	}

	return nil
}

// removeFromSockmapImpl removes a socket from the sockmap.
func removeFromSockmapImpl(fd int) error {
	if sockmapFD < 0 {
		return nil
	}

	key, ok := releaseSockmapSlot(fd)
	if !ok {
		return nil
	}

	return bpfMapDelete(sockmapFD, unsafe.Pointer(&key))
}

// setupForwardingImpl configures bidirectional forwarding between sockets.
// Cookies are passed from the caller to avoid redundant getsockopt(SO_COOKIE) calls.
func setupForwardingImpl(inboundFD, outboundFD int, inboundCookie, outboundCookie uint64) error {
	if sockhashFD < 0 {
		return ErrSockmapNotEnabled
	}

	// Map inbound socket to outbound using full SO_COOKIE keys.
	inboundKey := inboundCookie
	key := inboundKey
	value := uint32(outboundFD)
	if err := bpfMapUpdate(sockhashFD, unsafe.Pointer(&key), unsafe.Pointer(&value)); err != nil {
		return err
	}

	// Map outbound socket to inbound
	key = outboundCookie
	value = uint32(inboundFD)
	if err := bpfMapUpdate(sockhashFD, unsafe.Pointer(&key), unsafe.Pointer(&value)); err != nil {
		_ = bpfMapDelete(sockhashFD, unsafe.Pointer(&inboundKey))
		return err
	}

	return nil
}

// removeForwardingImpl removes bidirectional forwarding entries from sockhash.
func removeForwardingImpl(inboundCookie, outboundCookie uint64) error {
	if sockhashFD < 0 {
		return nil
	}

	var firstErr error
	key := inboundCookie
	if err := bpfMapDelete(sockhashFD, unsafe.Pointer(&key)); err != nil && firstErr == nil {
		firstErr = err
	}
	key = outboundCookie
	if err := bpfMapDelete(sockhashFD, unsafe.Pointer(&key)); err != nil && firstErr == nil {
		firstErr = err
	}

	return firstErr
}

func assignSockmapSlot(fd int) (slot uint32, created bool, err error) {
	// Fast path: reserve a fresh slot with an atomic increment.
	slot = sockmapNext.Add(1) - 1
	if slot < sockmapMaxEntries {
		sockmapSlotMu.Lock()
		if sockmapSlots == nil {
			sockmapSlots = make(map[int]uint32)
		}
		// Check for existing assignment under lock.
		if existing, ok := sockmapSlots[fd]; ok {
			// Reclaim the reserved slot so repeated registration attempts
			// do not consume effective sockmap capacity.
			sockmapFree = append(sockmapFree, slot)
			sockmapSlotMu.Unlock()
			return existing, false, nil
		}
		sockmapSlots[fd] = slot
		sockmapSlotMu.Unlock()
		return slot, true, nil
	}
	// Undo on overflow.
	sockmapNext.Add(^uint32(0))

	// Slow path: acquire mutex to try free list.
	sockmapSlotMu.Lock()
	defer sockmapSlotMu.Unlock()

	if sockmapSlots == nil {
		sockmapSlots = make(map[int]uint32)
	}
	if existing, ok := sockmapSlots[fd]; ok {
		return existing, false, nil
	}

	if len(sockmapFree) > 0 {
		i := len(sockmapFree) - 1
		slot = sockmapFree[i]
		sockmapFree = sockmapFree[:i]
		sockmapSlots[fd] = slot
		return slot, true, nil
	}

	return 0, false, fmt.Errorf("sockmap is full (max entries %d)", sockmapMaxEntries)
}

func releaseSockmapSlot(fd int) (uint32, bool) {
	sockmapSlotMu.Lock()
	defer sockmapSlotMu.Unlock()

	slot, ok := sockmapSlots[fd]
	if !ok {
		return 0, false
	}
	delete(sockmapSlots, fd)
	sockmapFree = append(sockmapFree, slot)
	return slot, true
}

// loadSKSkbProgram loads an sk_skb BPF program with optional map fd relocation.
func loadSKSkbProgram(insns []uint64, sockhashMapFD int, name string) (int, error) {
	// Patch map fd placeholder with actual sockhash map fd (no-op if no LD_IMM64 in insns)
	patchMapFD(insns, skSkbMapFDPlaceholder, int32(sockhashMapFD))

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
		progType: 23, // BPF_PROG_TYPE_SK_SKB
		insnCnt:  uint32(len(insns)),
		insns:    uint64(uintptr(unsafe.Pointer(&insns[0]))),
		license:  uint64(uintptr(unsafe.Pointer(&license[0]))),
	}

	copy(attr.progName[:], name)

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
		return -1, fmt.Errorf("BPF_PROG_LOAD %s: %w", name, errno)
	}

	return int(fd), nil
}

// attachSKSkbToSockmap attaches sk_skb stream parser and verdict to a sockmap.
func attachSKSkbToSockmap(parserFD, verdictFD, mapFD int) error {
	// Attach parser (BPF_SK_SKB_STREAM_PARSER = 4)
	if err := attachBPFProgToMap(mapFD, parserFD, 4); err != nil {
		return fmt.Errorf("parser: %w", err)
	}

	// Attach verdict (BPF_SK_SKB_STREAM_VERDICT = 5)
	if err := attachBPFProgToMap(mapFD, verdictFD, 5); err != nil {
		// Detach parser on partial failure to leave sockmap in clean state.
		detachBPFProgFromMap(mapFD, parserFD, 4)
		return fmt.Errorf("verdict: %w", err)
	}

	return nil
}

// detachBPFProgFromMap detaches a BPF program from a map. Best-effort.
func detachBPFProgFromMap(mapFD, progFD int, attachType uint32) {
	attr := struct {
		targetFD    uint32
		attachBPFFD uint32
		attachType  uint32
		attachFlags uint32
	}{
		targetFD:    uint32(mapFD),
		attachBPFFD: uint32(progFD),
		attachType:  attachType,
	}

	syscall.Syscall(
		unix.SYS_BPF,
		9, // BPF_PROG_DETACH
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
	)
}

// attachBPFProgToMap attaches a BPF program to a map with the given attach type.
func attachBPFProgToMap(mapFD, progFD int, attachType uint32) error {
	attr := struct {
		targetFD    uint32
		attachBPFFD uint32
		attachType  uint32
		attachFlags uint32
	}{
		targetFD:    uint32(mapFD),
		attachBPFFD: uint32(progFD),
		attachType:  attachType,
	}

	_, _, errno := syscall.Syscall(
		unix.SYS_BPF,
		8, // BPF_PROG_ATTACH
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
	)

	if errno != 0 {
		return errno
	}

	return nil
}

// getSocketCookie gets the socket cookie for a file descriptor.
func getSocketCookie(fd int) (uint64, error) {
	var cookie uint64
	cookieLen := uint32(unsafe.Sizeof(cookie))

	_, _, errno := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		uintptr(fd),
		uintptr(syscall.SOL_SOCKET),
		uintptr(unix.SO_COOKIE),
		uintptr(unsafe.Pointer(&cookie)),
		uintptr(unsafe.Pointer(&cookieLen)),
		0,
	)

	if errno != 0 {
		return 0, errno
	}

	return cookie, nil
}

// getConnFDImpl extracts the file descriptor from a net.Conn on Linux.
// Safety: The returned FD is the runtime-managed FD and remains valid as long
// as the caller holds the net.Conn reference (preventing GC finalization).
// Callers must NOT close this FD or use it after the connection is closed.
func getConnFDImpl(conn net.Conn) (int, error) {
	// Try to get the underlying TCPConn
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return -1, fmt.Errorf("connection is not a TCP connection")
	}

	// Get the raw connection
	rawConn, err := tcpConn.SyscallConn()
	if err != nil {
		return -1, err
	}

	var fd int
	err = rawConn.Control(func(f uintptr) {
		fd = int(f)
	})
	if err != nil {
		return -1, err
	}
	if fd < 0 {
		return -1, fmt.Errorf("invalid socket fd: %d", fd)
	}

	return fd, nil
}

// isSocketAlive probes whether a file descriptor is still a valid, open socket.
// It uses getsockopt(SO_ERROR) which returns EBADF for closed/invalid FDs.
func isSocketAlive(fd int) bool {
	var serr int32
	serrLen := uint32(4)
	_, _, errno := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		uintptr(fd),
		uintptr(syscall.SOL_SOCKET),
		uintptr(syscall.SO_ERROR),
		uintptr(unsafe.Pointer(&serr)),
		uintptr(unsafe.Pointer(&serrLen)),
		0,
	)
	return errno == 0
}
