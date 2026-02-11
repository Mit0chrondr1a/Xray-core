//go:build linux && (amd64 || arm64)

package udp

import (
	"net"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	// UDP_SEGMENT is the socket option for GSO (UDP segmentation offload).
	UDP_SEGMENT = 103
	// UDP_GRO is the socket option for GRO (Generic Receive Offload).
	UDP_GRO = 104
)

// EnableGRO enables UDP Generic Receive Offload on a UDP connection.
// This allows the kernel to coalesce multiple UDP datagrams into a single
// larger buffer, reducing per-packet overhead.
// Requires Linux 5.0+.
func EnableGRO(conn *net.UDPConn) error {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return err
	}

	var seterr error
	err = rawConn.Control(func(fd uintptr) {
		seterr = unix.SetsockoptInt(int(fd), unix.IPPROTO_UDP, UDP_GRO, 1)
	})
	if err != nil {
		return err
	}
	return seterr
}

// EnableGSO enables UDP Generic Segmentation Offload on a UDP connection.
// This allows sending large UDP buffers that the kernel/NIC will segment
// into individual datagrams, reducing syscall overhead.
// Requires Linux 4.18+.
func EnableGSO(conn *net.UDPConn) error {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return err
	}

	var seterr error
	err = rawConn.Control(func(fd uintptr) {
		seterr = unix.SetsockoptInt(int(fd), unix.IPPROTO_UDP, UDP_SEGMENT, 1)
	})
	if err != nil {
		return err
	}
	return seterr
}

// GSOSupported checks if UDP GSO is available on this system.
func GSOSupported() bool {
	// Create a temporary socket to test
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return false
	}
	defer unix.Close(fd)

	err = unix.SetsockoptInt(fd, unix.IPPROTO_UDP, UDP_SEGMENT, 1)
	return err == nil
}

// GROSupported checks if UDP GRO is available on this system.
func GROSupported() bool {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return false
	}
	defer unix.Close(fd)

	err = unix.SetsockoptInt(fd, unix.IPPROTO_UDP, UDP_GRO, 1)
	return err == nil
}

// WriteWithGSO sends a large buffer using GSO, specifying the segment size.
// The kernel will split the buffer into segments of gsoSize bytes each.
func WriteWithGSO(conn *net.UDPConn, buf []byte, addr *net.UDPAddr, gsoSize uint16) (int, error) {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}

	var n int
	var operr error
	err = rawConn.Write(func(fd uintptr) bool {
		n, operr = sendmsgGSO(int(fd), buf, addr, gsoSize)
		return operr != unix.EAGAIN
	})
	if err != nil {
		return 0, err
	}
	return n, operr
}

// sendmsgGSO performs a sendmsg with GSO control message.
func sendmsgGSO(fd int, data []byte, addr *net.UDPAddr, gsoSize uint16) (int, error) {
	sa := ipToSockaddr(addr)
	if sa == nil {
		return 0, os.ErrInvalid
	}

	// Build GSO control message
	cmsg := make([]byte, unix.CmsgLen(2))
	hdr := (*unix.Cmsghdr)(unsafe.Pointer(&cmsg[0]))
	hdr.Level = unix.IPPROTO_UDP
	hdr.Type = UDP_SEGMENT
	hdr.SetLen(unix.CmsgLen(2))
	*(*uint16)(unsafe.Pointer(&cmsg[unix.CmsgLen(0)])) = gsoSize

	iov := unix.Iovec{
		Base: &data[0],
		Len:  uint64(len(data)),
	}

	var msg unix.Msghdr
	msg.Iov = &iov
	msg.Iovlen = 1
	msg.Control = &cmsg[0]
	msg.Controllen = uint64(len(cmsg))

	// Set destination address
	setMsgName(&msg, sa)

	n, _, errno := unix.Syscall(
		unix.SYS_SENDMSG,
		uintptr(fd),
		uintptr(unsafe.Pointer(&msg)),
		0,
	)
	if errno != 0 {
		return int(n), errno
	}
	return int(n), nil
}

// ReadWithGRO reads from a GRO-enabled socket. Returns the data and the
// segment size reported by GRO (0 if not a coalesced packet).
func ReadWithGRO(conn *net.UDPConn, p []byte) (n int, gsoSize uint16, addr *net.UDPAddr, err error) {
	oob := make([]byte, 64) // enough for GRO cmsg

	readn, oobn, _, readAddr, operr := conn.ReadMsgUDP(p, oob)
	if operr != nil {
		return 0, 0, nil, operr
	}

	// Parse GRO segment size from control messages
	if oobn > 0 {
		gsoSize = parseGROSegmentSize(oob[:oobn])
	}

	return readn, gsoSize, readAddr, nil
}

// parseGROSegmentSize extracts the GRO segment size from ancillary data.
func parseGROSegmentSize(oob []byte) uint16 {
	cmsgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return 0
	}
	for _, cmsg := range cmsgs {
		if cmsg.Header.Level == unix.IPPROTO_UDP && cmsg.Header.Type == UDP_GRO {
			if len(cmsg.Data) >= 2 {
				return *(*uint16)(unsafe.Pointer(&cmsg.Data[0]))
			}
		}
	}
	return 0
}

// ipToSockaddr converts a UDPAddr to a raw sockaddr.
func ipToSockaddr(addr *net.UDPAddr) unsafe.Pointer {
	if ip4 := addr.IP.To4(); ip4 != nil {
		sa := &unix.RawSockaddrInet4{
			Family: unix.AF_INET,
			Port:   uint16(addr.Port>>8) | uint16(addr.Port&0xff)<<8,
		}
		copy(sa.Addr[:], ip4)
		return unsafe.Pointer(sa)
	}
	sa := &unix.RawSockaddrInet6{
		Family: unix.AF_INET6,
		Port:   uint16(addr.Port>>8) | uint16(addr.Port&0xff)<<8,
	}
	copy(sa.Addr[:], addr.IP.To16())
	return unsafe.Pointer(sa)
}

// setMsgName sets the destination address on a Msghdr.
func setMsgName(msg *unix.Msghdr, sa unsafe.Pointer) {
	msg.Name = (*byte)(sa)
	// Size depends on address family
	family := *(*uint16)(sa)
	if family == unix.AF_INET {
		msg.Namelen = unix.SizeofSockaddrInet4
	} else {
		msg.Namelen = unix.SizeofSockaddrInet6
	}
}
