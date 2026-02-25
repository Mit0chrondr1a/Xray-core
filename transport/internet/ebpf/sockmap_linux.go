//go:build linux

package ebpf

import (
	"bytes"
	"context"
	stdErrors "errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	xerrors "github.com/xtls/xray-core/common/errors"
	"golang.org/x/sys/unix"
)

// ebpfState holds all BPF file descriptors and configuration that must be
// read/written atomically. Readers load the pointer once and use a consistent
// snapshot, eliminating the data race where a teardown could leave readers
// with a mix of old and new (closed) FDs.
type ebpfState struct {
	sockhashFD      int
	policyMapFD     int
	skSkbParserFD   int
	skSkbVerdictFD  int
	sockmapAttachFD int
	sockmapPinPath  string

	sockmapAttachMaxEntries uint32
}

var currentState atomic.Pointer[ebpfState]

func init() {
	currentState.Store(&ebpfState{
		sockhashFD:      -1,
		policyMapFD:     -1,
		skSkbParserFD:   -1,
		skSkbVerdictFD:  -1,
		sockmapAttachFD: -1,
	})
}

// Slot management globals have their own mutex and don't need atomic state.
var (
	sockmapAttachSlotMu sync.Mutex
	sockmapAttachSlots  map[int]uint32
	sockmapAttachFree   []uint32
	sockmapAttachNext   atomic.Uint32
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
// When data arrives on a socket in the sk_skb attach map, this program fires:
//  1. Gets the receiving socket's cookie via bpf_get_socket_cookie
//  2. Looks up the cookie in the policy map to check redirect permission
//  3. If denied (flags & 1 == 0), returns SK_PASS (data to userspace)
//  4. If allowed (or no policy entry), redirects via SOCKHASH (egress by default)
//  5. If policy sets PolicyUseIngress, redirect into target ingress queue
//
// This achieves true zero-copy TCP proxying — data arriving from the
// network on one socket is forwarded directly to the paired socket
// without ever entering userspace. The policy lookup enables kTLS-aware
// sockmap: when both sockets have kTLS, the kernel handles encrypt/decrypt
// transparently.
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
		bpfMovReg(bpfRegR6, bpfRegR1), // 0

		// Zero the key area on the stack
		bpfStoreImm(bpfDW, bpfRegR10, int16(stackKey), 0), // 1

		// r1 = skb for bpf_get_socket_cookie
		bpfMovReg(bpfRegR1, bpfRegR6), // 2
		// r0 = bpf_get_socket_cookie(skb) — helper #46
		bpfCallHelper(bpfFuncGetSocketCookie), // 3

		// r7 = cookie (callee-saved)
		bpfMovReg(bpfRegR7, bpfRegR0), // 4

		// Store cookie as key on stack
		bpfStoreMem(bpfDW, bpfRegR10, bpfRegR7, int16(stackKey)), // 5

		// Default policy for missing entries: allow redirect, egress direction.
		bpfMovImm32(bpfRegR8, int32(PolicyAllowRedirect)), // 6
	}

	// --- Policy map lookup ---
	// r1 = policy map fd (LD_IMM64, 2 instructions, patched at load time)
	policyMapInsns := bpfLoadMapFD(bpfRegR1, skSkbPolicyFDPlaceholder) // 7, 8
	insns = append(insns,
		policyMapInsns[0],
		policyMapInsns[1],
		// r2 = &key
		bpfMovReg(bpfRegR2, bpfRegR10),       // 9
		bpfAddImm(bpfRegR2, int32(stackKey)), // 10
		// r0 = bpf_map_lookup_elem(policy_map, &key)
		bpfCallHelper(bpfFuncMapLookupElem), // 11

		// If a policy entry exists, load flags into r8.
		bpfJmpImm(bpfJEQ, bpfRegR0, 0, 1),       // 12: if NULL, skip load
		bpfLoadMem(bpfW, bpfRegR8, bpfRegR0, 0), // 13: r8 = *(u32*)(r0+0)

		// Check allow bit.
		bpfMovReg(bpfRegR0, bpfRegR8),                     // 14
		bpfAndImm32(bpfRegR0, int32(PolicyAllowRedirect)), // 15: r0 &= 1
		// Deny path must bypass redirect helper setup and jump to SK_PASS epilogue.
		bpfJmpImm(bpfJEQ, bpfRegR0, 0, 12), // 16: if zero → SK_PASS exit (+12 to insn 29)
	)

	// --- Redirect section ---
	insns = append(insns,
		// Restore cookie to stack key (may have been clobbered by helper)
		bpfStoreMem(bpfDW, bpfRegR10, bpfRegR7, int16(stackKey)), // 17

		// r1 = skb
		bpfMovReg(bpfRegR1, bpfRegR6), // 18
	)

	// r2 = sockhash map fd (LD_IMM64, 2 instructions, patched at load time)
	sockhashInsns := bpfLoadMapFD(bpfRegR2, skSkbMapFDPlaceholder) // 19, 20
	insns = append(insns,
		sockhashInsns[0],
		sockhashInsns[1],
		// r3 = &key
		bpfMovReg(bpfRegR3, bpfRegR10),       // 21
		bpfAddImm(bpfRegR3, int32(stackKey)), // 22
		// r4 = flags, default egress (0)
		bpfMovImm(bpfRegR4, 0), // 23
		// If policy requests ingress, set r4=1.
		bpfMovReg(bpfRegR0, bpfRegR8),                  // 24
		bpfAndImm32(bpfRegR0, int32(PolicyUseIngress)), // 25
		bpfJmpImm(bpfJEQ, bpfRegR0, 0, 1),              // 26
		bpfMovImm(bpfRegR4, 1),                         // 27
		// call bpf_sk_redirect_hash — helper #72
		bpfCallHelper(bpfFuncSKRedirectHash), // 28
	)

	// --- SK_PASS exit ---
	insns = append(insns,
		bpfMovImm(bpfRegR0, skPass), // 29
		bpfExitInsn(),               // 30
	)

	return insns
}

// skSkbMapFDPlaceholder is the sockhash map fd placeholder in the verdict bytecode.
const skSkbMapFDPlaceholder = 0

// skSkbPolicyFDPlaceholder is the policy map fd placeholder in the verdict bytecode.
const skSkbPolicyFDPlaceholder = 1

// readSysctl reads an integer value from a /proc/sys sysctl path.
func readSysctl(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(data)))
}

// checkBPFSysctls logs advisory warnings about kernel BPF security settings.
// Called once per sockmap lifecycle; never blocks setup.
func checkBPFSysctls() {
	ctx := context.Background()

	if val, err := readSysctl("/proc/sys/kernel/unprivileged_bpf_disabled"); err == nil {
		if val < 1 {
			xerrors.LogWarning(ctx, "kernel.unprivileged_bpf_disabled=", val,
				" — unprivileged users can load BPF programs; consider setting to 1 or 2")
		}
	}

	if val, err := readSysctl("/proc/sys/net/core/bpf_jit_harden"); err == nil {
		if val < 1 {
			xerrors.LogInfo(ctx, "net.core.bpf_jit_harden=", val,
				" — BPF JIT hardening is disabled; consider setting to 1 or 2")
		}
	}
}

// setupSockmapImpl creates the SOCKHASH, LRU policy map, and sk_skb programs.
// Preferred attach is SOCKHASH; kernels that do not support sk_skb-on-SOCKHASH
// fall back to a dedicated SOCKMAP attach map while still redirecting via SOCKHASH.
//
// Dual-path lifecycle: When CGO is enabled and the Rust staticlib includes eBPF
// bytecode (native.EbpfAvailable() == true), the Rust/Aya loader in
// common/native/cgo.go → rust/xray-rust/src/ebpf.rs is the primary path. It
// handles program loading, Aya-managed map pinning, and SK_MSG attachment.
// This Go-native path serves as the fallback for non-CGO builds or when the
// Rust crate is compiled without the ebpf-bytecode feature. Both paths share
// the same pin directory layout (/sys/fs/bpf/xray/) and policy map schema,
// but only one should be active per process at a time.
func setupSockmapImpl(config SockmapConfig) error {
	// Create SOCKHASH map for cookie→socket redirect.
	hashFD, err := createBPFMap(
		bpfMapTypeSockhash,
		8, // key size (uint64 cookie)
		4, // value size (socket fd, resolved to socket by kernel)
		config.MaxEntries,
	)
	if err != nil {
		return fmt.Errorf("failed to create sockhash map: %w", err)
	}
	attachFD := hashFD
	usingSockmapFallback := false
	fallbackAttachFD := -1

	// Create LRU policy map for redirect policy (cookie → flags).
	// LRU_HASH provides automatic kernel-side eviction under pressure.
	policyFD, err := createBPFMap(
		bpfMapTypeLRUHash,
		8, // key size (uint64 cookie)
		4, // value size (uint32 flags)
		config.MaxEntries,
	)
	if err != nil {
		syscall.Close(hashFD)
		return fmt.Errorf("failed to create policy map: %w", err)
	}

	// Build and load sk_skb stream parser
	parserInsns := buildSKSkbParserProgram()
	parserBytecode := encodeBPFInsns(parserInsns)
	parserFD, err := loadSKSkbProgram(parserBytecode, 0, 0, "xray_skb_parse", bpfSkSkbStreamParser)
	if err != nil {
		syscall.Close(hashFD)
		syscall.Close(policyFD)
		return fmt.Errorf("failed to load sk_skb parser: %w", err)
	}

	// Build and load sk_skb stream verdict
	verdictInsns := buildSKSkbVerdictProgram()
	verdictBytecode := encodeBPFInsns(verdictInsns)
	verdictFD, err := loadSKSkbProgram(verdictBytecode, hashFD, policyFD, "xray_skb_vrdt", bpfSkSkbStreamVerdict)
	if err != nil {
		syscall.Close(parserFD)
		syscall.Close(hashFD)
		syscall.Close(policyFD)
		return fmt.Errorf("failed to load sk_skb verdict: %w", err)
	}

	// Preferred attach target is SOCKHASH (kernel 4.20+).
	if err := attachSKSkbToMap(parserFD, verdictFD, hashFD); err != nil {
		if !shouldFallbackToSockmapAttach(err) {
			syscall.Close(verdictFD)
			syscall.Close(parserFD)
			syscall.Close(hashFD)
			syscall.Close(policyFD)
			return fmt.Errorf("failed to attach sk_skb programs to sockhash: %w", err)
		}
		xerrors.LogInfo(context.Background(), "sockmap: SOCKHASH sk_skb attach failed (", err, "), falling back to SOCKMAP attach (kTLS+sockmap may not work)")

		// Compatibility fallback for older kernels:
		// attach sk_skb to SOCKMAP, but keep redirect lookups in SOCKHASH.
		fallbackAttachFD, err = createBPFMap(
			bpfMapTypeSockmap,
			4, // key size (uint32 slot)
			4, // value size (socket fd)
			config.MaxEntries,
		)
		if err != nil {
			syscall.Close(verdictFD)
			syscall.Close(parserFD)
			syscall.Close(hashFD)
			syscall.Close(policyFD)
			return fmt.Errorf("failed to create sockmap attach fallback: %w", err)
		}
		if err := attachSKSkbToMap(parserFD, verdictFD, fallbackAttachFD); err != nil {
			syscall.Close(fallbackAttachFD)
			syscall.Close(verdictFD)
			syscall.Close(parserFD)
			syscall.Close(hashFD)
			syscall.Close(policyFD)
			return fmt.Errorf("failed to attach sk_skb programs to sockhash and fallback sockmap: %w", err)
		}
		attachFD = fallbackAttachFD
		usingSockmapFallback = true
	}

	// Pin maps to BPF filesystem with 0600 permissions
	pinDir := ""
	if config.PinPath != "" {
		pinDir = filepath.Clean(config.PinPath)
		if err := pinMaps(pinDir, hashFD, policyFD); err != nil {
			if fallbackAttachFD >= 0 {
				syscall.Close(fallbackAttachFD)
			}
			syscall.Close(verdictFD)
			syscall.Close(parserFD)
			syscall.Close(hashFD)
			syscall.Close(policyFD)
			return fmt.Errorf("failed to pin BPF maps: %w", err)
		}
	}

	// Commit to global state only after all operations succeed.
	// Build the new state struct and store it atomically so readers
	// always see a fully-consistent snapshot.
	newState := &ebpfState{
		sockhashFD:     hashFD,
		policyMapFD:    policyFD,
		skSkbParserFD:  parserFD,
		skSkbVerdictFD: verdictFD,
		sockmapPinPath: pinDir,
	}
	if usingSockmapFallback {
		newState.sockmapAttachFD = attachFD
		newState.sockmapAttachMaxEntries = config.MaxEntries
		sockmapAttachSlotMu.Lock()
		sockmapAttachSlots = make(map[int]uint32)
		sockmapAttachFree = nil
		sockmapAttachSlotMu.Unlock()
		sockmapAttachNext.Store(0)
	} else {
		newState.sockmapAttachFD = -1
		sockmapAttachSlotMu.Lock()
		sockmapAttachSlots = nil
		sockmapAttachFree = nil
		sockmapAttachSlotMu.Unlock()
		sockmapAttachNext.Store(0)
	}
	currentState.Store(newState)

	// Advisory sysctl checks (runs once per sockmap lifecycle, never blocks setup)
	checkBPFSysctls()

	// Drop excess capabilities (defense-in-depth, non-fatal)
	if config.DropCapabilities {
		if err := dropExcessCapabilities(); err != nil {
			ctx := context.Background()
			xerrors.LogWarning(ctx, "failed to drop excess capabilities: ", err)
		}
	}

	return nil
}

// teardownSockmapImpl cleans up sockmap resources.
// Closing the active attach map FD detaches attached sk_skb programs.
//
// The closed state is published atomically BEFORE closing old FDs so that
// concurrent readers (setupForwardingImpl, removeForwardingImpl) never
// observe a half-torn-down state.
func teardownSockmapImpl() error {
	// Capture old state before swapping.
	oldState := currentState.Load()

	// Unpin maps before closing FDs (best-effort)
	if oldState.sockmapPinPath != "" {
		unpinBPFMap(sockhashPinPath(oldState.sockmapPinPath))
		unpinBPFMap(policyPinPath(oldState.sockmapPinPath))
		os.Remove(oldState.sockmapPinPath)
	}

	// Publish closed state atomically so readers immediately see all FDs as -1.
	closedState := &ebpfState{
		sockhashFD:      -1,
		policyMapFD:     -1,
		skSkbParserFD:   -1,
		skSkbVerdictFD:  -1,
		sockmapAttachFD: -1,
	}
	currentState.Store(closedState)

	// Reset slot management globals.
	sockmapAttachSlotMu.Lock()
	sockmapAttachSlots = nil
	sockmapAttachFree = nil
	sockmapAttachSlotMu.Unlock()
	sockmapAttachNext.Store(0)

	// Now close old FDs. Readers that loaded oldState before the swap may
	// still have in-flight syscalls, but the kernel refcounts BPF map FDs
	// so those syscalls complete safely.
	if oldState.sockmapAttachFD >= 0 {
		syscall.Close(oldState.sockmapAttachFD)
	}
	if oldState.skSkbVerdictFD >= 0 {
		syscall.Close(oldState.skSkbVerdictFD)
	}
	if oldState.skSkbParserFD >= 0 {
		syscall.Close(oldState.skSkbParserFD)
	}
	if oldState.sockhashFD >= 0 {
		syscall.Close(oldState.sockhashFD)
	}
	if oldState.policyMapFD >= 0 {
		syscall.Close(oldState.policyMapFD)
	}
	return nil
}

// setupForwardingImpl configures bidirectional forwarding between sockets.
// Cookies are passed from the caller to avoid redundant getsockopt(SO_COOKIE) calls.
func setupForwardingImpl(inboundFD, outboundFD int, inboundCookie, outboundCookie uint64) error {
	st := currentState.Load()
	if st.sockhashFD < 0 {
		return ErrSockmapNotEnabled
	}

	// Map inbound socket to outbound using full SO_COOKIE keys.
	inboundKey := inboundCookie
	key := inboundKey
	value := uint32(outboundFD)
	if err := bpfMapUpdate(st.sockhashFD, unsafe.Pointer(&key), unsafe.Pointer(&value)); err != nil {
		return fmt.Errorf("sockhash insert outbound fd=%d cookie=%d: %w", outboundFD, inboundCookie, err)
	}

	// Map outbound socket to inbound
	key = outboundCookie
	value = uint32(inboundFD)
	if err := bpfMapUpdate(st.sockhashFD, unsafe.Pointer(&key), unsafe.Pointer(&value)); err != nil {
		_ = bpfMapDelete(st.sockhashFD, unsafe.Pointer(&inboundKey))
		return fmt.Errorf("sockhash insert inbound fd=%d cookie=%d: %w", inboundFD, outboundCookie, err)
	}

	// Older kernels attach sk_skb to SOCKMAP only; mirror sockets into the
	// fallback attach map so packets trigger parser/verdict programs.
	if st.sockmapAttachFD >= 0 {
		inboundSlot, inboundCreated, err := assignSockmapAttachSlot(inboundFD, st.sockmapAttachMaxEntries)
		if err != nil {
			_ = bpfMapDelete(st.sockhashFD, unsafe.Pointer(&key))
			_ = bpfMapDelete(st.sockhashFD, unsafe.Pointer(&inboundKey))
			return err
		}
		attachKey := inboundSlot
		attachValue := uint32(inboundFD)
		if err := bpfMapUpdate(st.sockmapAttachFD, unsafe.Pointer(&attachKey), unsafe.Pointer(&attachValue)); err != nil {
			if inboundCreated {
				releaseSockmapAttachSlot(inboundFD)
			}
			_ = bpfMapDelete(st.sockhashFD, unsafe.Pointer(&key))
			_ = bpfMapDelete(st.sockhashFD, unsafe.Pointer(&inboundKey))
			return fmt.Errorf("sockmap-attach insert inbound fd=%d slot=%d: %w", inboundFD, inboundSlot, err)
		}

		outboundSlot, outboundCreated, err := assignSockmapAttachSlot(outboundFD, st.sockmapAttachMaxEntries)
		if err != nil {
			if inboundCreated {
				if attachInboundKey, ok := releaseSockmapAttachSlot(inboundFD); ok {
					_ = bpfMapDelete(st.sockmapAttachFD, unsafe.Pointer(&attachInboundKey))
				}
			}
			_ = bpfMapDelete(st.sockhashFD, unsafe.Pointer(&key))
			_ = bpfMapDelete(st.sockhashFD, unsafe.Pointer(&inboundKey))
			return err
		}
		attachKey = outboundSlot
		attachValue = uint32(outboundFD)
		if err := bpfMapUpdate(st.sockmapAttachFD, unsafe.Pointer(&attachKey), unsafe.Pointer(&attachValue)); err != nil {
			if outboundCreated {
				releaseSockmapAttachSlot(outboundFD)
			}
			if inboundCreated {
				if attachInboundKey, ok := releaseSockmapAttachSlot(inboundFD); ok {
					_ = bpfMapDelete(st.sockmapAttachFD, unsafe.Pointer(&attachInboundKey))
				}
			}
			_ = bpfMapDelete(st.sockhashFD, unsafe.Pointer(&key))
			_ = bpfMapDelete(st.sockhashFD, unsafe.Pointer(&inboundKey))
			return fmt.Errorf("sockmap-attach insert outbound fd=%d slot=%d: %w", outboundFD, outboundSlot, err)
		}
	}

	return nil
}

// removeForwardingImpl removes bidirectional forwarding entries from sockhash
// and from the fallback attach map when enabled.
func removeForwardingImpl(inboundFD, outboundFD int, inboundCookie, outboundCookie uint64) error {
	st := currentState.Load()
	if st.sockhashFD < 0 {
		return nil
	}

	var firstErr error
	key := inboundCookie
	if err := bpfMapDelete(st.sockhashFD, unsafe.Pointer(&key)); err != nil && firstErr == nil {
		firstErr = err
	}
	key = outboundCookie
	if err := bpfMapDelete(st.sockhashFD, unsafe.Pointer(&key)); err != nil && firstErr == nil {
		firstErr = err
	}

	if st.sockmapAttachFD >= 0 {
		attachKey, ok := releaseSockmapAttachSlot(inboundFD)
		if ok {
			if err := bpfMapDelete(st.sockmapAttachFD, unsafe.Pointer(&attachKey)); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		attachKey, ok = releaseSockmapAttachSlot(outboundFD)
		if ok {
			if err := bpfMapDelete(st.sockmapAttachFD, unsafe.Pointer(&attachKey)); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}

	return firstErr
}

func assignSockmapAttachSlot(fd int, maxEntries uint32) (slot uint32, created bool, err error) {
	slot = sockmapAttachNext.Add(1) - 1
	if slot < maxEntries {
		sockmapAttachSlotMu.Lock()
		if sockmapAttachSlots == nil {
			sockmapAttachSlots = make(map[int]uint32)
		}
		if existing, ok := sockmapAttachSlots[fd]; ok {
			sockmapAttachFree = append(sockmapAttachFree, slot)
			sockmapAttachSlotMu.Unlock()
			return existing, false, nil
		}
		sockmapAttachSlots[fd] = slot
		sockmapAttachSlotMu.Unlock()
		return slot, true, nil
	}
	sockmapAttachNext.Add(^uint32(0))

	sockmapAttachSlotMu.Lock()
	defer sockmapAttachSlotMu.Unlock()

	if sockmapAttachSlots == nil {
		sockmapAttachSlots = make(map[int]uint32)
	}
	if existing, ok := sockmapAttachSlots[fd]; ok {
		return existing, false, nil
	}

	if len(sockmapAttachFree) > 0 {
		i := len(sockmapAttachFree) - 1
		slot = sockmapAttachFree[i]
		sockmapAttachFree = sockmapAttachFree[:i]
		sockmapAttachSlots[fd] = slot
		return slot, true, nil
	}

	return 0, false, fmt.Errorf("sockmap attach map is full (max entries %d)", maxEntries)
}

func releaseSockmapAttachSlot(fd int) (uint32, bool) {
	sockmapAttachSlotMu.Lock()
	defer sockmapAttachSlotMu.Unlock()

	slot, ok := sockmapAttachSlots[fd]
	if !ok {
		return 0, false
	}
	delete(sockmapAttachSlots, fd)
	sockmapAttachFree = append(sockmapAttachFree, slot)
	return slot, true
}

// loadSKSkbProgram loads an sk_skb BPF program with optional map fd relocation.
const (
	bpfSkSkbStreamParser  = 4
	bpfSkSkbStreamVerdict = 5
)

func loadSKSkbProgram(insns []uint64, sockhashMapFD, polMapFD int, name string, expectedAttachType uint32) (int, error) {
	// Patch map fd placeholders with actual map fds (no-op if no matching LD_IMM64 in insns)
	patchMapFD(insns, skSkbMapFDPlaceholder, int32(sockhashMapFD))
	patchMapFD(insns, skSkbPolicyFDPlaceholder, int32(polMapFD))

	license := []byte("GPL\x00")

	attr := struct {
		progType           uint32
		insnCnt            uint32
		insns              uint64
		license            uint64
		logLevel           uint32
		logSize            uint32
		logBuf             uint64
		kernVersion        uint32
		progFlags          uint32
		progName           [16]byte
		progIfIndex        uint32
		expectedAttachType uint32
	}{
		progType:           bpfProgTypeSKSkb,
		insnCnt:            uint32(len(insns)),
		insns:              uint64(uintptr(unsafe.Pointer(&insns[0]))),
		license:            uint64(uintptr(unsafe.Pointer(&license[0]))),
		expectedAttachType: expectedAttachType,
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
		if idx := bytes.IndexByte(logBuf, 0); idx >= 0 {
			logBuf = logBuf[:idx]
		}
		verifier := strings.TrimSpace(string(logBuf))
		// Truncate verifier output to avoid leaking excessive kernel internals.
		const maxVerifierLen = 512
		if len(verifier) > maxVerifierLen {
			verifier = verifier[:maxVerifierLen] + "...(truncated)"
		}
		if verifier != "" {
			return -1, fmt.Errorf("BPF_PROG_LOAD %s (expected_attach_type=%d): %w (verifier: %s)", name, expectedAttachType, errno, verifier)
		}
		return -1, fmt.Errorf("BPF_PROG_LOAD %s (expected_attach_type=%d): %w", name, expectedAttachType, errno)
	}

	return int(fd), nil
}

// attachSKSkbToMap attaches sk_skb stream parser and verdict to a map.
func attachSKSkbToMap(parserFD, verdictFD, mapFD int) error {
	if err := attachBPFProgToMap(mapFD, parserFD, bpfSkSkbStreamParser); err != nil {
		return fmt.Errorf("parser: %w", err)
	}

	if err := attachBPFProgToMap(mapFD, verdictFD, bpfSkSkbStreamVerdict); err != nil {
		// Detach parser on partial failure to leave map in clean state.
		detachBPFProgFromMap(mapFD, parserFD, bpfSkSkbStreamParser)
		return fmt.Errorf("verdict: %w", err)
	}

	return nil
}

func shouldFallbackToSockmapAttach(err error) bool {
	return stdErrors.Is(err, syscall.EINVAL) ||
		stdErrors.Is(err, syscall.EOPNOTSUPP) ||
		stdErrors.Is(err, syscall.ENOTSUP)
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

// pinBPFMap pins a BPF map fd to the BPF filesystem via BPF_OBJ_PIN (cmd 6).
func pinBPFMap(fd int, path string) error {
	if err := pinBPFMapOnce(fd, path); err != nil {
		// Recover from stale pin files and from races with prior unclean exits.
		if !stdErrors.Is(err, syscall.EEXIST) {
			return err
		}
		if err := removeExistingPin(path); err != nil {
			return err
		}
		return pinBPFMapOnce(fd, path)
	}
	return nil
}

func pinBPFMapOnce(fd int, path string) error {
	pathBytes := append([]byte(path), 0)
	attr := struct {
		pathname  uint64
		bpfFD     uint32
		fileFlags uint32
	}{
		pathname: uint64(uintptr(unsafe.Pointer(&pathBytes[0]))),
		bpfFD:    uint32(fd),
	}

	_, _, errno := syscall.Syscall(
		unix.SYS_BPF,
		6, // BPF_OBJ_PIN
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
	)
	if errno != 0 {
		return fmt.Errorf("BPF_OBJ_PIN %s: %w", path, errno)
	}
	return nil
}

// unpinBPFMap removes a pinned BPF map from the filesystem. Best-effort.
func unpinBPFMap(path string) {
	os.Remove(path)
}

// ensureBPFPinDir creates the BPF pin directory with root-only access.
func ensureBPFPinDir(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if err := os.Chown(dir, 0, 0); err != nil {
		return err
	}
	return os.Chmod(dir, 0700)
}

func sockhashPinPath(pinDir string) string {
	return filepath.Join(pinDir, "sockhash")
}

func policyPinPath(pinDir string) string {
	return filepath.Join(pinDir, "policy")
}

func removeExistingPin(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove existing pin %s: %w", path, err)
	}
	return nil
}

// pinMaps pins SOCKHASH and policy maps to the BPF filesystem with 0600 root-only permissions.
func pinMaps(pinPath string, hashFD, policyFD int) error {
	if err := ensureBPFPinDir(pinPath); err != nil {
		return fmt.Errorf("ensure pin dir: %w", err)
	}

	sockhashPath := sockhashPinPath(pinPath)
	policyPath := policyPinPath(pinPath)
	if err := removeExistingPin(sockhashPath); err != nil {
		return err
	}
	if err := removeExistingPin(policyPath); err != nil {
		return err
	}

	if err := pinBPFMap(hashFD, sockhashPath); err != nil {
		return err
	}
	if err := os.Chown(sockhashPath, 0, 0); err != nil {
		unpinBPFMap(sockhashPath)
		return err
	}
	if err := os.Chmod(sockhashPath, 0600); err != nil {
		unpinBPFMap(sockhashPath)
		return err
	}

	if err := pinBPFMap(policyFD, policyPath); err != nil {
		unpinBPFMap(sockhashPath)
		return err
	}
	if err := os.Chown(policyPath, 0, 0); err != nil {
		unpinBPFMap(policyPath)
		unpinBPFMap(sockhashPath)
		return err
	}
	if err := os.Chmod(policyPath, 0600); err != nil {
		unpinBPFMap(policyPath)
		unpinBPFMap(sockhashPath)
		return err
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

// probeKTLSSockhashCompat tests whether a kTLS socket can be inserted into a
// SOCKHASH map on this kernel. Returns true if compatible. This runs once at
// startup when both kTLS and sockmap are available, and gates whether kTLS
// sockets are eligible for sockmap redirect.
func probeKTLSSockhashCompat() bool {
	st := currentState.Load()
	if st.sockhashFD < 0 {
		return false
	}

	// Create a loopback TCP pair in ESTABLISHED state.
	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return false
	}
	defer ln.Close()

	serverCh := make(chan *net.TCPConn, 1)
	go func() {
		c, err := ln.AcceptTCP()
		if err != nil {
			serverCh <- nil
			return
		}
		serverCh <- c
	}()

	client, err := net.DialTCP("tcp4", nil, ln.Addr().(*net.TCPAddr))
	if err != nil {
		return false
	}
	defer client.Close()

	server := <-serverCh
	if server == nil {
		return false
	}
	defer server.Close()

	// Set up kTLS ULP + TX on the client socket.
	rawConn, err := client.SyscallConn()
	if err != nil {
		return false
	}

	var ktlsOK bool
	rawConn.Control(func(fd uintptr) {
		intFD := int(fd)
		// TCP_ULP = "tls"
		if err := syscall.SetsockoptString(intFD, syscall.SOL_TCP, unix.TCP_ULP, "tls"); err != nil {
			return
		}
		// Install minimal TLS 1.3 AES-128-GCM-SHA256 TX crypto info.
		// We don't need real keys — just enough for the kernel to accept the ULP setup.
		const (
			solTLS = 282
			tlsTX  = 1
		)
		// struct tls12_crypto_info_aes_gcm_128:
		//   tls_crypto_info (4 bytes: version u16, cipher_type u16)
		//   iv       [8]byte
		//   key      [16]byte
		//   salt     [4]byte
		//   rec_seq  [8]byte
		var info [40]byte
		// version = TLS 1.3 (0x0304), little-endian u16
		info[0] = 0x04
		info[1] = 0x03
		// cipher_type = TLS_CIPHER_AES_GCM_128 (51), little-endian u16
		info[2] = 51
		info[3] = 0
		// rest is zeroed (dummy keys — this is a probe socket, never used for data)

		_, _, errno := syscall.Syscall6(
			syscall.SYS_SETSOCKOPT,
			fd,
			uintptr(solTLS),
			uintptr(tlsTX),
			uintptr(unsafe.Pointer(&info)),
			uintptr(unsafe.Sizeof(info)),
			0,
		)
		if errno != 0 {
			return
		}

		// Try inserting this kTLS socket into the SOCKHASH.
		cookie, err := getSocketCookie(intFD)
		if err != nil {
			return
		}
		key := cookie
		value := uint32(intFD)
		if err := bpfMapUpdate(st.sockhashFD, unsafe.Pointer(&key), unsafe.Pointer(&value)); err != nil {
			return
		}
		// Clean up — remove probe entry.
		_ = bpfMapDelete(st.sockhashFD, unsafe.Pointer(&key))
		ktlsOK = true
	})

	return ktlsOK
}

// setPolicyEntry writes a redirect policy entry for the given socket cookie.
func setPolicyEntry(cookie uint64, flags uint32) error {
	st := currentState.Load()
	if st.policyMapFD < 0 {
		return nil // policy map not created — no-op (backward compat)
	}
	key := cookie
	value := flags
	return bpfMapUpdate(st.policyMapFD, unsafe.Pointer(&key), unsafe.Pointer(&value))
}

// deletePolicyEntry removes the redirect policy entry for the given socket cookie.
func deletePolicyEntry(cookie uint64) error {
	st := currentState.Load()
	if st.policyMapFD < 0 {
		return nil
	}
	key := cookie
	return bpfMapDelete(st.policyMapFD, unsafe.Pointer(&key))
}

// unameRelease returns the kernel release string (e.g. "6.18.13") from uname(2).
// Returns "unknown" on any failure.
func unameRelease() string {
	var buf syscall.Utsname
	if err := syscall.Uname(&buf); err != nil {
		return "unknown"
	}
	// buf.Release is [65]int8 on linux/amd64.
	// Convert to string by finding the NUL terminator.
	var release []byte
	for _, b := range buf.Release {
		if b == 0 {
			break
		}
		release = append(release, byte(b))
	}
	if len(release) == 0 {
		return "unknown"
	}
	return string(release)
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
