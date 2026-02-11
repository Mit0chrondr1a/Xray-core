//go:build linux && (amd64 || arm64)

package udp

import (
	"context"
	"unsafe"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/udp"
	"golang.org/x/sys/unix"
)

const (
	batchSize  = 64 // max packets per recvmmsg call
	oobBufSize = 256
)

// mmsghdr matches the Linux kernel struct mmsghdr.
type mmsghdr struct {
	Hdr unix.Msghdr
	Len uint32
	_   [4]byte // padding to match kernel layout on amd64
}

// recvBatch reads multiple UDP packets in a single syscall using recvmmsg.
// Returns the number of messages received.
func (h *Hub) recvBatch(msgs []mmsghdr, iovecs []unix.Iovec, buffers []*buf.Buffer, oobBufs [][]byte) (int, error) {
	if h.udpConn == nil {
		return 0, errors.New("recvmmsg requires UDPConn")
	}

	// Get the raw fd from the UDPConn
	rawConn, err := h.udpConn.SyscallConn()
	if err != nil {
		return 0, err
	}

	var n int
	var operr error
	err = rawConn.Read(func(fd uintptr) bool {
		n, operr = recvmmsg(int(fd), msgs)
		return operr != unix.EAGAIN
	})
	if err != nil {
		return 0, err
	}
	if operr != nil {
		return 0, operr
	}

	return n, nil
}

// recvmmsg wraps the recvmmsg(2) syscall.
func recvmmsg(fd int, msgs []mmsghdr) (int, error) {
	n, _, errno := unix.Syscall6(
		unix.SYS_RECVMMSG,
		uintptr(fd),
		uintptr(unsafe.Pointer(&msgs[0])),
		uintptr(len(msgs)),
		0, // flags
		0, // timeout (NULL = block)
		0,
	)
	if errno != 0 {
		return 0, errno
	}
	return int(n), nil
}

// startBatch is an optimized packet receive loop using recvmmsg.
func (h *Hub) startBatch() {
	c := h.cache
	defer close(c)

	// Pre-allocate batch buffers
	msgs := make([]mmsghdr, batchSize)
	iovecs := make([]unix.Iovec, batchSize)
	buffers := make([]*buf.Buffer, batchSize)
	oobBufs := make([][]byte, batchSize)
	sockaddrs := make([]unix.RawSockaddrInet6, batchSize)

	for i := range msgs {
		oobBufs[i] = make([]byte, oobBufSize)
	}

	for {
		// Prepare buffers for batch receive
		for i := 0; i < batchSize; i++ {
			buffers[i] = buf.New()
			rawBytes := buffers[i].Extend(buf.Size)

			iovecs[i] = unix.Iovec{
				Base: &rawBytes[0],
				Len:  uint64(len(rawBytes)),
			}

			msgs[i] = mmsghdr{
				Hdr: unix.Msghdr{
					Iov:        &iovecs[i],
					Iovlen:     1,
					Name:       (*byte)(unsafe.Pointer(&sockaddrs[i])),
					Namelen:    uint32(unsafe.Sizeof(sockaddrs[i])),
					Control:    &oobBufs[i][0],
					Controllen: uint64(oobBufSize),
				},
			}
		}

		// Batch receive
		n, err := h.recvBatch(msgs, iovecs, buffers, oobBufs)
		if err != nil {
			errors.LogInfoInner(context.Background(), err, "recvmmsg failed, falling back to single read")
			// Release unused buffers
			for i := 0; i < batchSize; i++ {
				buffers[i].Release()
			}
			break
		}

		// Process received packets
		for i := 0; i < n; i++ {
			msgLen := int32(msgs[i].Len)
			buffers[i].Resize(0, msgLen)

			if buffers[i].IsEmpty() {
				buffers[i].Release()
				continue
			}

			// Parse source address
			udpAddr := sockaddrToUDPAddr(&sockaddrs[i])
			if udpAddr == nil {
				buffers[i].Release()
				continue
			}

			payload := &udp.Packet{
				Payload: buffers[i],
				Source:  net.UDPDestination(net.IPAddress(udpAddr.IP), net.Port(udpAddr.Port)),
			}

			if h.recvOrigDest && msgs[i].Hdr.Controllen > 0 {
				oobData := oobBufs[i][:msgs[i].Hdr.Controllen]
				payload.Target = RetrieveOriginalDest(oobData)
				if payload.Target.IsValid() {
					errors.LogDebug(context.Background(), "UDP original destination: ", payload.Target)
				} else {
					errors.LogInfo(context.Background(), "failed to read UDP original destination")
				}
			}

			select {
			case c <- payload:
			default:
				buffers[i].Release()
				payload.Payload = nil
			}
		}

		// Release unused buffers
		for i := n; i < batchSize; i++ {
			buffers[i].Release()
		}
	}
}

// sockaddrToUDPAddr converts a raw sockaddr to *net.UDPAddr.
func sockaddrToUDPAddr(sa *unix.RawSockaddrInet6) *net.UDPAddr {
	// Check if it's IPv4 (family == AF_INET)
	if sa.Family == unix.AF_INET {
		sa4 := (*unix.RawSockaddrInet4)(unsafe.Pointer(sa))
		return &net.UDPAddr{
			IP:   net.IP(sa4.Addr[:]),
			Port: int(sa4.Port>>8) | int(sa4.Port&0xff)<<8, // network byte order
		}
	}
	// IPv6
	if sa.Family == unix.AF_INET6 {
		return &net.UDPAddr{
			IP:   net.IP(sa.Addr[:]),
			Port: int(sa.Port>>8) | int(sa.Port&0xff)<<8, // network byte order
		}
	}
	return nil
}

func canUseBatchRead() bool {
	return true
}
