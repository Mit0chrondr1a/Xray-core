//go:build linux

package ebpf

import (
	"fmt"
	"net"
	"reflect"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

var (
	sockmapFD      int = -1
	sockhashFD     int = -1
	skMsgProgFD    int = -1
	skMsgLinkFD    int = -1
)

// buildSKMsgProgram generates the sk_msg BPF program bytecode.
// The program gets the socket cookie of the current message, looks it up
// in the sockhash map, and redirects to the paired socket if found.
//
// Stack layout:
//
//	[R10-4 .. R10-1]: key (uint32 socket cookie, truncated)
func buildSKMsgProgram() []bpfInsn {
	const (
		skPass = 1
		// Stack offset for the lookup key
		stackKey = -4
	)

	insns := []bpfInsn{
		// r6 = ctx (sk_msg_md)
		bpfMovReg(bpfRegR6, bpfRegR1),

		// Zero the key area on the stack
		bpfStoreImm(bpfW, bpfRegR10, int16(stackKey), 0),

		// r1 = ctx for bpf_get_socket_cookie
		bpfMovReg(bpfRegR1, bpfRegR6),
		// r0 = bpf_get_socket_cookie(ctx) -- helper #46
		bpfCallHelper(bpfFuncGetSocketCookie),

		// Store lower 32 bits of cookie as key (map uses uint32 keys)
		bpfStoreMem(bpfW, bpfRegR10, bpfRegR0, int16(stackKey)),

		// Set up args for bpf_msg_redirect_hash(ctx, map, key, flags)
		// r1 = ctx
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
		// r4 = flags (0 = send to egress path of target socket)
		bpfMovImm(bpfRegR4, 0),
		// call bpf_msg_redirect_hash -- helper #71
		bpfCallHelper(bpfFuncMsgRedirectHash),

		// Always return SK_PASS.
		// If redirect succeeded (r0 == SK_PASS), the message was forwarded.
		// If redirect failed (r0 == SK_DROP), we still return SK_PASS to
		// let the message proceed through the normal path.
		bpfMovImm(bpfRegR0, skPass),
		bpfExitInsn(),
	)

	return insns
}

// skMsgMapFDPlaceholder is the map fd value in the bytecode that gets replaced.
const skMsgMapFDPlaceholder = 0

// setupSockmapImpl creates the sockmap and sk_msg program.
func setupSockmapImpl(config SockmapConfig) error {
	// Create SOCKHASH map for socket lookup
	hashFD, err := createBPFMap(
		18, // BPF_MAP_TYPE_SOCKHASH
		4,  // key size (socket cookie or similar)
		4,  // value size (socket fd)
		config.MaxEntries,
	)
	if err != nil {
		return fmt.Errorf("failed to create sockhash map: %w", err)
	}
	sockhashFD = hashFD

	// Create SOCKMAP for storing sockets
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
	sockmapFD = mapFD

	// Build and load sk_msg program
	skMsgInsns := buildSKMsgProgram()
	skMsgBytecode := encodeBPFInsns(skMsgInsns)
	progFD, err := loadSKMsgProgram(skMsgBytecode, hashFD)
	if err != nil {
		syscall.Close(hashFD)
		syscall.Close(mapFD)
		return fmt.Errorf("failed to load sk_msg program: %w", err)
	}
	skMsgProgFD = progFD

	// Attach sk_msg program to sockmap
	if err := attachSKMsgToSockmap(progFD, mapFD); err != nil {
		syscall.Close(progFD)
		syscall.Close(hashFD)
		syscall.Close(mapFD)
		return fmt.Errorf("failed to attach sk_msg program: %w", err)
	}

	return nil
}

// teardownSockmapImpl cleans up sockmap resources.
func teardownSockmapImpl() error {
	if skMsgLinkFD >= 0 {
		syscall.Close(skMsgLinkFD)
		skMsgLinkFD = -1
	}
	if skMsgProgFD >= 0 {
		syscall.Close(skMsgProgFD)
		skMsgProgFD = -1
	}
	if sockhashFD >= 0 {
		syscall.Close(sockhashFD)
		sockhashFD = -1
	}
	if sockmapFD >= 0 {
		syscall.Close(sockmapFD)
		sockmapFD = -1
	}
	return nil
}

// addToSockmapImpl adds a socket to the sockmap.
func addToSockmapImpl(fd int) error {
	if sockmapFD < 0 {
		return ErrSockmapNotEnabled
	}

	// Use socket cookie as key
	cookie, err := getSocketCookie(fd)
	if err != nil {
		return fmt.Errorf("failed to get socket cookie: %w", err)
	}

	key := uint32(cookie)
	value := uint32(fd)

	return bpfMapUpdate(sockmapFD, unsafe.Pointer(&key), unsafe.Pointer(&value))
}

// removeFromSockmapImpl removes a socket from the sockmap.
func removeFromSockmapImpl(fd int) error {
	if sockmapFD < 0 {
		return nil
	}

	cookie, err := getSocketCookie(fd)
	if err != nil {
		return nil // Socket may already be closed
	}

	key := uint32(cookie)
	return bpfMapDelete(sockmapFD, unsafe.Pointer(&key))
}

// setupForwardingImpl configures bidirectional forwarding between sockets.
func setupForwardingImpl(inboundFD, outboundFD int) error {
	if sockhashFD < 0 {
		return ErrSockmapNotEnabled
	}

	// Add forwarding entries in sockhash
	// inbound -> outbound
	inboundCookie, err := getSocketCookie(inboundFD)
	if err != nil {
		return err
	}
	outboundCookie, err := getSocketCookie(outboundFD)
	if err != nil {
		return err
	}

	// Map inbound socket to outbound
	key := uint32(inboundCookie)
	value := uint32(outboundFD)
	if err := bpfMapUpdate(sockhashFD, unsafe.Pointer(&key), unsafe.Pointer(&value)); err != nil {
		return err
	}

	// Map outbound socket to inbound
	key = uint32(outboundCookie)
	value = uint32(inboundFD)
	return bpfMapUpdate(sockhashFD, unsafe.Pointer(&key), unsafe.Pointer(&value))
}

// loadSKMsgProgram loads an sk_msg BPF program with map fd relocation.
func loadSKMsgProgram(insns []uint64, sockhashMapFD int) (int, error) {
	// Patch map fd placeholder with actual sockhash map fd
	patchMapFD(insns, skMsgMapFDPlaceholder, int32(sockhashMapFD))

	license := []byte("GPL\x00")
	logBuf := make([]byte, 65536)

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
		progType: 25, // BPF_PROG_TYPE_SK_MSG
		insnCnt:  uint32(len(insns)),
		insns:    uint64(uintptr(unsafe.Pointer(&insns[0]))),
		license:  uint64(uintptr(unsafe.Pointer(&license[0]))),
		logLevel: 1,
		logSize:  uint32(len(logBuf)),
		logBuf:   uint64(uintptr(unsafe.Pointer(&logBuf[0]))),
	}

	copy(attr.progName[:], "xray_sk_msg")

	fd, _, errno := syscall.Syscall(
		unix.SYS_BPF,
		5, // BPF_PROG_LOAD
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
	)

	if errno != 0 {
		// Try again without log buffer
		attr.logLevel = 0
		attr.logSize = 0
		attr.logBuf = 0
		fd, _, errno = syscall.Syscall(
			unix.SYS_BPF,
			5,
			uintptr(unsafe.Pointer(&attr)),
			unsafe.Sizeof(attr),
		)
		if errno != 0 {
			return -1, fmt.Errorf("BPF_PROG_LOAD sk_msg: %w", errno)
		}
	}

	return int(fd), nil
}

// attachSKMsgToSockmap attaches an sk_msg program to a sockmap.
func attachSKMsgToSockmap(progFD, mapFD int) error {
	attr := struct {
		targetFD    uint32
		attachBPFFD uint32
		attachType  uint32
		attachFlags uint32
	}{
		targetFD:    uint32(mapFD),
		attachBPFFD: uint32(progFD),
		attachType:  6, // BPF_SK_MSG_VERDICT
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
	var fdErr error
	err = rawConn.Control(func(f uintptr) {
		fd = int(f)
	})
	if err != nil {
		return -1, err
	}
	if fdErr != nil {
		return -1, fdErr
	}

	return fd, nil
}

// getConnFDReflect gets fd using reflection as a fallback.
func getConnFDReflect(conn net.Conn) (int, error) {
	// Use reflection to access private fields
	v := reflect.ValueOf(conn)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}

	// Look for "conn" or "fd" field
	for _, name := range []string{"conn", "fd", "netFD"} {
		f := v.FieldByName(name)
		if f.IsValid() {
			if f.Kind() == reflect.Ptr {
				f = f.Elem()
			}
			// Look for pfd or sysfd
			pfd := f.FieldByName("pfd")
			if pfd.IsValid() {
				sysfd := pfd.FieldByName("Sysfd")
				if sysfd.IsValid() && sysfd.CanInt() {
					return int(sysfd.Int()), nil
				}
			}
		}
	}

	return -1, fmt.Errorf("could not extract file descriptor from connection")
}
