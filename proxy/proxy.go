// Package proxy contains all proxies used by Xray.
//
// To implement an inbound or outbound proxy, one needs to do the following:
// 1. Implement the interface(s) below.
// 2. Register a config creator through common.RegisterConfig.
package proxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"reflect"
	"runtime"
	"strconv"
	"time"

	"github.com/pires/go-proxyproto"
	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/native"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy/vless/encryption"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/ebpf"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

var (
	Tls13SupportedVersions  = []byte{0x00, 0x2b, 0x00, 0x02, 0x03, 0x04}
	TlsClientHandShakeStart = []byte{0x16, 0x03}
	TlsServerHandShakeStart = []byte{0x16, 0x03, 0x03}
	TlsApplicationDataStart = []byte{0x17, 0x03, 0x03}

	Tls13CipherSuiteDic = map[uint16]string{
		0x1301: "TLS_AES_128_GCM_SHA256",
		0x1302: "TLS_AES_256_GCM_SHA384",
		0x1303: "TLS_CHACHA20_POLY1305_SHA256",
		0x1304: "TLS_AES_128_CCM_SHA256",
		0x1305: "TLS_AES_128_CCM_8_SHA256",
	}
)

const (
	TlsHandshakeTypeClientHello byte = 0x01
	TlsHandshakeTypeServerHello byte = 0x02

	CommandPaddingContinue byte = 0x00
	CommandPaddingEnd      byte = 0x01
	CommandPaddingDirect   byte = 0x02
)

// An Inbound processes inbound connections.
type Inbound interface {
	// Network returns a list of networks that this inbound supports. Connections with not-supported networks will not be passed into Process().
	Network() []net.Network

	// Process processes a connection of given network. If necessary, the Inbound can dispatch the connection to an Outbound.
	Process(context.Context, net.Network, stat.Connection, routing.Dispatcher) error
}

// An Outbound process outbound connections.
type Outbound interface {
	// Process processes the given connection. The given dialer may be used to dial a system outbound connection.
	Process(context.Context, *transport.Link, internet.Dialer) error
}

// UserManager is the interface for Inbounds and Outbounds that can manage their users.
type UserManager interface {
	// AddUser adds a new user.
	AddUser(context.Context, *protocol.MemoryUser) error

	// RemoveUser removes a user by email.
	RemoveUser(context.Context, string) error

	// Get user by email.
	GetUser(context.Context, string) *protocol.MemoryUser

	// Get all users.
	GetUsers(context.Context) []*protocol.MemoryUser

	// Get users count.
	GetUsersCount(context.Context) int64
}

type GetInbound interface {
	GetInbound() Inbound
}

type GetOutbound interface {
	GetOutbound() Outbound
}

// TrafficState is used to track uplink and downlink of one connection
// It is used by XTLS to determine if switch to raw copy mode, It is used by Vision to calculate padding
type TrafficState struct {
	UserUUID               []byte
	NumberOfPacketToFilter int
	EnableXtls             bool
	IsTLS12orAbove         bool
	IsTLS                  bool
	Cipher                 uint16
	RemainingServerHello   int32
	Inbound                InboundState
	Outbound               OutboundState
}

type InboundState struct {
	// reader link state
	WithinPaddingBuffers   bool
	UplinkReaderDirectCopy bool
	RemainingCommand       int32
	RemainingContent       int32
	RemainingPadding       int32
	CurrentCommand         int
	// write link state
	IsPadding                bool
	DownlinkWriterDirectCopy bool
}

type OutboundState struct {
	// reader link state
	WithinPaddingBuffers     bool
	DownlinkReaderDirectCopy bool
	RemainingCommand         int32
	RemainingContent         int32
	RemainingPadding         int32
	CurrentCommand           int
	// write link state
	IsPadding              bool
	UplinkWriterDirectCopy bool
}

func NewTrafficState(userUUID []byte) *TrafficState {
	return &TrafficState{
		UserUUID:               userUUID,
		NumberOfPacketToFilter: 8,
		EnableXtls:             false,
		IsTLS12orAbove:         false,
		IsTLS:                  false,
		Cipher:                 0,
		RemainingServerHello:   -1,
		Inbound: InboundState{
			WithinPaddingBuffers:     true,
			UplinkReaderDirectCopy:   false,
			RemainingCommand:         -1,
			RemainingContent:         -1,
			RemainingPadding:         -1,
			CurrentCommand:           0,
			IsPadding:                true,
			DownlinkWriterDirectCopy: false,
		},
		Outbound: OutboundState{
			WithinPaddingBuffers:     true,
			DownlinkReaderDirectCopy: false,
			RemainingCommand:         -1,
			RemainingContent:         -1,
			RemainingPadding:         -1,
			CurrentCommand:           0,
			IsPadding:                true,
			UplinkWriterDirectCopy:   false,
		},
	}
}

// VisionReader is used to read xtls vision protocol
// Note Vision probably only make sense as the inner most layer of reader, since it need assess traffic state from origin proxy traffic
type VisionReader struct {
	buf.Reader
	trafficState *TrafficState
	ctx          context.Context
	isUplink     bool
	conn         net.Conn
	input        *bytes.Reader
	rawInput     *bytes.Buffer
	ob           *session.Outbound

	// internal
	directReadCounter stats.Counter
}

func NewVisionReader(reader buf.Reader, trafficState *TrafficState, isUplink bool, ctx context.Context, conn net.Conn, input *bytes.Reader, rawInput *bytes.Buffer, ob *session.Outbound) *VisionReader {
	return &VisionReader{
		Reader:       reader,
		trafficState: trafficState,
		ctx:          ctx,
		isUplink:     isUplink,
		conn:         conn,
		input:        input,
		rawInput:     rawInput,
		ob:           ob,
	}
}

func (w *VisionReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	buffer, err := w.Reader.ReadMultiBuffer()
	if buffer.IsEmpty() {
		return buffer, err
	}

	var withinPaddingBuffers *bool
	var remainingContent *int32
	var remainingPadding *int32
	var currentCommand *int
	var switchToDirectCopy *bool
	if w.isUplink {
		withinPaddingBuffers = &w.trafficState.Inbound.WithinPaddingBuffers
		remainingContent = &w.trafficState.Inbound.RemainingContent
		remainingPadding = &w.trafficState.Inbound.RemainingPadding
		currentCommand = &w.trafficState.Inbound.CurrentCommand
		switchToDirectCopy = &w.trafficState.Inbound.UplinkReaderDirectCopy
	} else {
		withinPaddingBuffers = &w.trafficState.Outbound.WithinPaddingBuffers
		remainingContent = &w.trafficState.Outbound.RemainingContent
		remainingPadding = &w.trafficState.Outbound.RemainingPadding
		currentCommand = &w.trafficState.Outbound.CurrentCommand
		switchToDirectCopy = &w.trafficState.Outbound.DownlinkReaderDirectCopy
	}

	if *switchToDirectCopy {
		if w.directReadCounter != nil {
			w.directReadCounter.Add(int64(buffer.Len()))
		}
		return buffer, err
	}

	if *withinPaddingBuffers || w.trafficState.NumberOfPacketToFilter > 0 {
		mb2 := buf.GetMultiBuffer()
		for _, b := range buffer {
			newbuffer := XtlsUnpadding(b, w.trafficState, w.isUplink, w.ctx)
			if newbuffer.Len() > 0 {
				mb2 = append(mb2, newbuffer)
			}
		}
		buffer = mb2
		if *remainingContent > 0 || *remainingPadding > 0 || *currentCommand == 0 {
			*withinPaddingBuffers = true
		} else if *currentCommand == 1 {
			*withinPaddingBuffers = false
		} else if *currentCommand == 2 {
			*withinPaddingBuffers = false
			*switchToDirectCopy = true
		} else {
			errors.LogDebug(w.ctx, "XtlsRead unknown command ", *currentCommand, buffer.Len())
		}
	}
	if w.trafficState.NumberOfPacketToFilter > 0 {
		XtlsFilterTls(buffer, w.trafficState, w.ctx)
	}

	if *switchToDirectCopy {
		// XTLS Vision processes TLS-like conn's input and rawInput
		if inputBuffer, err := buf.ReadFrom(w.input); err == nil && !inputBuffer.IsEmpty() {
			buffer, _ = buf.MergeMulti(buffer, inputBuffer)
		}
		if rawInputBuffer, err := buf.ReadFrom(w.rawInput); err == nil && !rawInputBuffer.IsEmpty() {
			buffer, _ = buf.MergeMulti(buffer, rawInputBuffer)
		}
		*w.input = bytes.Reader{} // release memory
		w.input = nil
		*w.rawInput = bytes.Buffer{} // release memory
		w.rawInput = nil

		if inbound := session.InboundFromContext(w.ctx); inbound != nil && inbound.Conn != nil {
			// if w.isUplink && inbound.CanSpliceCopy == 2 { // TODO: enable uplink splice
			// 	inbound.CanSpliceCopy = 1
			// }
			if !w.isUplink && w.ob != nil && w.ob.CanSpliceCopy == 2 { // ob need to be passed in due to context can have more than one ob
				w.ob.CanSpliceCopy = 1
			}
		}
		readerConn, readCounter, _, readerHandler := UnwrapRawConn(w.conn)
		w.directReadCounter = readCounter
		if readerHandler != nil {
			w.Reader = buf.NewReader(&ktlsReader{Conn: readerConn, handler: readerHandler})
		} else {
			w.Reader = buf.NewReader(readerConn)
		}
	}
	return buffer, err
}

// VisionWriter is used to write xtls vision protocol
// Note Vision probably only make sense as the inner most layer of writer, since it need assess traffic state from origin proxy traffic
type VisionWriter struct {
	buf.Writer
	trafficState *TrafficState
	ctx          context.Context
	isUplink     bool
	conn         net.Conn
	ob           *session.Outbound

	// internal
	writeOnceUserUUID  []byte
	directWriteCounter stats.Counter

	testseed []uint32
}

func NewVisionWriter(writer buf.Writer, trafficState *TrafficState, isUplink bool, ctx context.Context, conn net.Conn, ob *session.Outbound, testseed []uint32) *VisionWriter {
	w := make([]byte, len(trafficState.UserUUID))
	copy(w, trafficState.UserUUID)
	if len(testseed) < 4 {
		testseed = []uint32{900, 500, 900, 256}
	}
	return &VisionWriter{
		Writer:            writer,
		trafficState:      trafficState,
		ctx:               ctx,
		writeOnceUserUUID: w,
		isUplink:          isUplink,
		conn:              conn,
		ob:                ob,
		testseed:          testseed,
	}
}

func (w *VisionWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	var isPadding *bool
	var switchToDirectCopy *bool
	if w.isUplink {
		isPadding = &w.trafficState.Outbound.IsPadding
		switchToDirectCopy = &w.trafficState.Outbound.UplinkWriterDirectCopy
	} else {
		isPadding = &w.trafficState.Inbound.IsPadding
		switchToDirectCopy = &w.trafficState.Inbound.DownlinkWriterDirectCopy
	}

	if *switchToDirectCopy {
		if inbound := session.InboundFromContext(w.ctx); inbound != nil {
			if !w.isUplink && inbound.CanSpliceCopy == 2 {
				inbound.CanSpliceCopy = 1
			}
			// if w.isUplink && w.ob != nil && w.ob.CanSpliceCopy == 2 { // TODO: enable uplink splice
			// 	w.ob.CanSpliceCopy = 1
			// }
		}
		rawConn, _, writerCounter, _ := UnwrapRawConn(w.conn)
		w.Writer = buf.NewWriter(rawConn)
		w.directWriteCounter = writerCounter
		*switchToDirectCopy = false
	}
	if !mb.IsEmpty() && w.directWriteCounter != nil {
		w.directWriteCounter.Add(int64(mb.Len()))
	}

	if w.trafficState.NumberOfPacketToFilter > 0 {
		XtlsFilterTls(mb, w.trafficState, w.ctx)
	}

	if *isPadding {
		if len(mb) == 1 && mb[0] == nil {
			mb[0] = XtlsPadding(nil, CommandPaddingContinue, &w.writeOnceUserUUID, true, w.ctx, w.testseed) // we do a long padding to hide vless header
			return w.Writer.WriteMultiBuffer(mb)
		}
		isComplete := IsCompleteRecord(mb)
		mb = ReshapeMultiBuffer(w.ctx, mb)
		longPadding := w.trafficState.IsTLS
		for i, b := range mb {
			if w.trafficState.IsTLS && b.Len() >= 6 && bytes.Equal(TlsApplicationDataStart, b.BytesTo(3)) && isComplete {
				if w.trafficState.EnableXtls {
					*switchToDirectCopy = true
				}
				var command byte = CommandPaddingContinue
				if i == len(mb)-1 {
					command = CommandPaddingEnd
					if w.trafficState.EnableXtls {
						command = CommandPaddingDirect
					}
				}
				mb[i] = XtlsPadding(b, command, &w.writeOnceUserUUID, true, w.ctx, w.testseed)
				*isPadding = false // padding going to end
				longPadding = false
				continue
			} else if !w.trafficState.IsTLS12orAbove && w.trafficState.NumberOfPacketToFilter <= 1 { // For compatibility with earlier vision receiver, we finish padding 1 packet early
				*isPadding = false
				mb[i] = XtlsPadding(b, CommandPaddingEnd, &w.writeOnceUserUUID, longPadding, w.ctx, w.testseed)
				break
			}
			var command byte = CommandPaddingContinue
			if i == len(mb)-1 && !*isPadding {
				command = CommandPaddingEnd
				if w.trafficState.EnableXtls {
					command = CommandPaddingDirect
				}
			}
			mb[i] = XtlsPadding(b, command, &w.writeOnceUserUUID, longPadding, w.ctx, w.testseed)
		}
	}
	return w.Writer.WriteMultiBuffer(mb)
}

// IsCompleteRecord checks if the MultiBuffer contains complete TLS application
// data records. Scans across buffer segments in-place without copying.
func IsCompleteRecord(buffer buf.MultiBuffer) bool {
	s := newMultiBufferScanner(buffer)
	headerLen := 5
	recordLen := 0

	for s.remaining() > 0 {
		if headerLen > 0 {
			data := s.readByte()
			switch headerLen {
			case 5:
				if data != 0x17 {
					return false
				}
			case 4:
				if data != 0x03 {
					return false
				}
			case 3:
				if data != 0x03 {
					return false
				}
			case 2:
				recordLen = int(data) << 8
			case 1:
				recordLen = recordLen | int(data)
			}
			headerLen--
		} else if recordLen > 0 {
			if s.remaining() < recordLen {
				return false
			}
			s.skip(recordLen)
			recordLen = 0
			headerLen = 5
		} else {
			return false
		}
	}
	return headerLen == 5 && recordLen == 0
}

// multiBufferScanner walks a MultiBuffer's segments without copying.
type multiBufferScanner struct {
	mb     buf.MultiBuffer
	bufIdx int   // current buffer index
	offset int32 // offset within current buffer
	total  int   // total remaining bytes
}

func newMultiBufferScanner(mb buf.MultiBuffer) multiBufferScanner {
	total := 0
	for _, b := range mb {
		if b != nil {
			total += int(b.Len())
		}
	}
	s := multiBufferScanner{mb: mb, total: total}
	s.advance() // skip nil/empty leading buffers
	return s
}

// advance moves past nil/empty buffers.
func (s *multiBufferScanner) advance() {
	for s.bufIdx < len(s.mb) {
		b := s.mb[s.bufIdx]
		if b != nil && s.offset < b.Len() {
			return
		}
		s.bufIdx++
		s.offset = 0
	}
}

func (s *multiBufferScanner) remaining() int {
	return s.total
}

func (s *multiBufferScanner) readByte() byte {
	if s.bufIdx >= len(s.mb) {
		return 0
	}
	b := s.mb[s.bufIdx]
	val := b.Byte(s.offset)
	s.offset++
	s.total--
	if s.offset >= b.Len() {
		s.bufIdx++
		s.offset = 0
		s.advance()
	}
	return val
}

func (s *multiBufferScanner) skip(n int) {
	s.total -= n
	for n > 0 && s.bufIdx < len(s.mb) {
		b := s.mb[s.bufIdx]
		avail := int(b.Len() - s.offset)
		if avail > n {
			s.offset += int32(n)
			return
		}
		n -= avail
		s.bufIdx++
		s.offset = 0
		s.advance()
	}
}

// ReshapeMultiBuffer prepare multi buffer for padding structure (max 21 bytes)
func ReshapeMultiBuffer(ctx context.Context, buffer buf.MultiBuffer) buf.MultiBuffer {
	needReshape := 0
	for _, b := range buffer {
		if b.Len() >= buf.Size-21 {
			needReshape += 1
		}
	}
	if needReshape == 0 {
		return buffer
	}
	mb2 := buf.GetMultiBuffer()
	for i, buffer1 := range buffer {
		if buffer1.Len() >= buf.Size-21 {
			index := int32(bytes.LastIndex(buffer1.Bytes(), TlsApplicationDataStart))
			if index < 21 || index > buf.Size-21 {
				index = buf.Size / 2
			}
			buffer2 := buf.New()
			buffer2.Write(buffer1.BytesFrom(index))
			buffer1.Resize(0, index)
			mb2 = append(mb2, buffer1, buffer2)
		} else {
			mb2 = append(mb2, buffer1)
		}
		buffer[i] = nil
	}
	buffer = buffer[:0]
	errors.LogDebug(ctx, "ReshapeMultiBuffer: reshaped ", needReshape, " oversized buffer(s)")
	return mb2
}

// XtlsPadding add padding to eliminate length signature during tls handshake
func XtlsPadding(b *buf.Buffer, command byte, userUUID *[]byte, longPadding bool, ctx context.Context, testseed []uint32) *buf.Buffer {
	// Delegate to Rust when the native library is linked.
	if native.Available() {
		return xtlsPaddingRust(b, command, userUUID, longPadding, ctx, testseed)
	}
	return xtlsPaddingGoFallback(b, command, userUUID, longPadding, ctx, testseed)
}

// xtlsPaddingRust delegates Vision padding to the Rust native library.
func xtlsPaddingRust(b *buf.Buffer, command byte, userUUID *[]byte, longPadding bool, ctx context.Context, testseed []uint32) *buf.Buffer {
	var data []byte
	if b != nil {
		data = b.Bytes()
	}
	var uuid []byte
	if userUUID != nil {
		uuid = *userUUID
	}

	// Ensure testseed has 4 elements.
	var seeds [4]uint32
	copy(seeds[:], testseed)

	var outBuf *buf.Buffer
	if arena := buf.ArenaFromContext(ctx); arena != nil {
		outBuf = arena.NewBuffer()
	} else {
		outBuf = buf.New()
	}
	// Extend to full capacity to get a writable slice, then resize after.
	outBytes := outBuf.Extend(buf.Size)

	n, err := native.VisionPad(data, command, uuid, longPadding, seeds, outBytes)
	if err != nil {
		// Fallback to Go implementation on error.
		outBuf.Release()
		errors.LogDebugInner(ctx, err, "native VisionPad failed, falling back to Go")
		return xtlsPaddingGoFallback(b, command, userUUID, longPadding, ctx, testseed)
	}

	// Resize to actual written length.
	outBuf.Resize(0, int32(n))

	// Clean up inputs.
	if userUUID != nil {
		*userUUID = nil
	}
	if b != nil {
		b.Release()
	}

	return outBuf
}

// xtlsPaddingGoFallback is the original Go padding implementation.
func xtlsPaddingGoFallback(b *buf.Buffer, command byte, userUUID *[]byte, longPadding bool, ctx context.Context, testseed []uint32) *buf.Buffer {
	var contentLen int32 = 0
	var paddingLen int32 = 0
	if b != nil {
		contentLen = b.Len()
	}
	if contentLen < int32(testseed[0]) && longPadding {
		paddingLen = int32(cryptoRandIntn(testseed[1])) + int32(testseed[2]) - contentLen
	} else {
		paddingLen = int32(cryptoRandIntn(testseed[3]))
	}
	if paddingLen > buf.Size-21-contentLen {
		paddingLen = buf.Size - 21 - contentLen
	}
	var newbuffer *buf.Buffer
	if arena := buf.ArenaFromContext(ctx); arena != nil {
		newbuffer = arena.NewBuffer()
	} else {
		newbuffer = buf.New()
	}
	if userUUID != nil {
		newbuffer.Write(*userUUID)
		*userUUID = nil
	}
	hdr := [5]byte{command, byte(contentLen >> 8), byte(contentLen), byte(paddingLen >> 8), byte(paddingLen)}
	newbuffer.Write(hdr[:])
	if b != nil {
		newbuffer.Write(b.Bytes())
		b.Release()
		b = nil
	}
	newbuffer.Extend(paddingLen)
	errors.LogDebug(ctx, "XtlsPadding ", contentLen, " ", paddingLen, " ", command)
	return newbuffer
}

// cryptoRandIntn returns a cryptographically random int64 in [0, n).
// On RNG failure, falls back to a time-derived value rather than returning 0.
//
// Trade-off: time-based padding is statistically distinguishable from CSPRNG
// output by a DPI adversary with sub-microsecond timing. However, crypto/rand
// failure means /dev/urandom is broken — the system is already unable to
// perform TLS handshakes, so this is a degraded mode for a degraded system.
// This is strictly better than the previous behavior (nil pointer panic).
func cryptoRandIntn(n uint32) int64 {
	if n == 0 {
		return 0
	}
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return int64(uint32(time.Now().UnixNano()) % n)
	}
	return int64(binary.BigEndian.Uint32(buf[:]) % n)
}

// XtlsUnpadding remove padding and parse command
func XtlsUnpadding(b *buf.Buffer, s *TrafficState, isUplink bool, ctx context.Context) *buf.Buffer {
	var remainingCommand *int32
	var remainingContent *int32
	var remainingPadding *int32
	var currentCommand *int
	if isUplink {
		remainingCommand = &s.Inbound.RemainingCommand
		remainingContent = &s.Inbound.RemainingContent
		remainingPadding = &s.Inbound.RemainingPadding
		currentCommand = &s.Inbound.CurrentCommand
	} else {
		remainingCommand = &s.Outbound.RemainingCommand
		remainingContent = &s.Outbound.RemainingContent
		remainingPadding = &s.Outbound.RemainingPadding
		currentCommand = &s.Outbound.CurrentCommand
	}
	if *remainingCommand == -1 && *remainingContent == -1 && *remainingPadding == -1 { // initial state
		if b.Len() >= 21 && bytes.Equal(s.UserUUID, b.BytesTo(16)) {
			b.Advance(16)
			*remainingCommand = 5
		} else {
			return b
		}
	}
	var newbuffer *buf.Buffer
	if arena := buf.ArenaFromContext(ctx); arena != nil {
		newbuffer = arena.NewBuffer()
	} else {
		newbuffer = buf.New()
	}
	for b.Len() > 0 {
		if *remainingCommand > 0 {
			data, err := b.ReadByte()
			if err != nil {
				return newbuffer
			}
			switch *remainingCommand {
			case 5:
				*currentCommand = int(data)
			case 4:
				*remainingContent = int32(data) << 8
			case 3:
				*remainingContent = *remainingContent | int32(data)
			case 2:
				*remainingPadding = int32(data) << 8
			case 1:
				*remainingPadding = *remainingPadding | int32(data)
				errors.LogDebug(ctx, "Xtls Unpadding new block, content ", *remainingContent, " padding ", *remainingPadding, " command ", *currentCommand)
			}
			*remainingCommand--
		} else if *remainingContent > 0 {
			len := *remainingContent
			if b.Len() < len {
				len = b.Len()
			}
			data, err := b.ReadBytes(len)
			if err != nil {
				return newbuffer
			}
			newbuffer.Write(data)
			*remainingContent -= len
		} else { // remainingPadding > 0
			len := *remainingPadding
			if b.Len() < len {
				len = b.Len()
			}
			b.Advance(len)
			*remainingPadding -= len
		}
		if *remainingCommand <= 0 && *remainingContent <= 0 && *remainingPadding <= 0 { // this block done
			if *currentCommand == 0 {
				*remainingCommand = 5
			} else {
				*remainingCommand = -1 // set to initial state
				*remainingContent = -1
				*remainingPadding = -1
				if b.Len() > 0 { // shouldn't happen
					newbuffer.Write(b.Bytes())
				}
				break
			}
		}
	}
	b.Release()
	b = nil
	return newbuffer
}

// XtlsFilterTls filter and recognize tls 1.3 and other info
func XtlsFilterTls(buffer buf.MultiBuffer, trafficState *TrafficState, ctx context.Context) {
	for _, b := range buffer {
		if b == nil {
			continue
		}
		trafficState.NumberOfPacketToFilter--
		if b.Len() >= 6 {
			startsBytes := b.BytesTo(6)
			if bytes.Equal(TlsServerHandShakeStart, startsBytes[:3]) && startsBytes[5] == TlsHandshakeTypeServerHello {
				trafficState.RemainingServerHello = (int32(startsBytes[3])<<8 | int32(startsBytes[4])) + 5
				trafficState.IsTLS12orAbove = true
				trafficState.IsTLS = true
				if b.Len() >= 79 && trafficState.RemainingServerHello >= 79 {
					sessionIdLen := min(int32(b.Byte(43)), 32) // TLS session IDs are at most 32 bytes
					if 43+sessionIdLen+3 > b.Len() {
						errors.LogDebug(ctx, "XtlsFilterTls sessionIdLen exceeds buffer, skipping cipher suite parse")
					} else {
						cipherSuite := b.BytesRange(43+sessionIdLen+1, 43+sessionIdLen+3)
						trafficState.Cipher = uint16(cipherSuite[0])<<8 | uint16(cipherSuite[1])
					}
				} else {
					errors.LogDebug(ctx, "XtlsFilterTls short server hello, tls 1.2 or older? ", b.Len(), " ", trafficState.RemainingServerHello)
				}
			} else if bytes.Equal(TlsClientHandShakeStart, startsBytes[:2]) && startsBytes[5] == TlsHandshakeTypeClientHello {
				trafficState.IsTLS = true
				errors.LogDebug(ctx, "XtlsFilterTls found tls client hello! ", buffer.Len())
			}
		}
		if trafficState.RemainingServerHello > 0 {
			end := trafficState.RemainingServerHello
			if end > b.Len() {
				end = b.Len()
			}
			trafficState.RemainingServerHello -= b.Len()
			if bytes.Contains(b.BytesTo(end), Tls13SupportedVersions) {
				v, ok := Tls13CipherSuiteDic[trafficState.Cipher]
				if !ok {
					v = "Old cipher: " + strconv.FormatUint(uint64(trafficState.Cipher), 16)
				} else if v != "TLS_AES_128_CCM_8_SHA256" {
					trafficState.EnableXtls = true
				}
				errors.LogDebug(ctx, "XtlsFilterTls found tls 1.3! ", b.Len(), " ", v)
				trafficState.NumberOfPacketToFilter = 0
				return
			} else if trafficState.RemainingServerHello <= 0 {
				errors.LogDebug(ctx, "XtlsFilterTls found tls 1.2! ", b.Len())
				trafficState.NumberOfPacketToFilter = 0
				return
			}
			errors.LogDebug(ctx, "XtlsFilterTls inconclusive server hello ", b.Len(), " ", trafficState.RemainingServerHello)
		}
		if trafficState.NumberOfPacketToFilter <= 0 {
			errors.LogDebug(ctx, "XtlsFilterTls stop filtering", buffer.Len())
		}
	}
}

// ktlsReader wraps a raw connection to handle EKEYEXPIRED errors from kTLS
// when the peer sends a TLS 1.3 KeyUpdate message.
type ktlsReader struct {
	net.Conn
	handler *tls.KTLSKeyUpdateHandler
}

func (r *ktlsReader) Read(b []byte) (int, error) {
	n, err := r.Conn.Read(b)
	if err != nil && tls.IsKeyExpired(err) && r.handler != nil {
		if herr := r.handler.Handle(); herr != nil {
			return 0, herr
		}
		return r.Conn.Read(b)
	}
	return n, err
}

// UnwrapRawConn support unwrap encryption, stats, tls, utls, reality, proxyproto, uds-wrapper conn and get raw tcp/uds conn from it
func UnwrapRawConn(conn net.Conn) (net.Conn, stats.Counter, stats.Counter, *tls.KTLSKeyUpdateHandler) {
	var readCounter, writerCounter stats.Counter
	var handler *tls.KTLSKeyUpdateHandler
	if conn != nil {
		isEncryption := false
		if commonConn, ok := conn.(*encryption.CommonConn); ok {
			conn = commonConn.Conn
			isEncryption = true
		}
		if xorConn, ok := conn.(*encryption.XorConn); ok {
			return xorConn, nil, nil, nil // full-random xorConn should not be penetrated
		}
		if statConn, ok := conn.(*stat.CounterConnection); ok {
			conn = statConn.Connection
			readCounter = statConn.ReadCounter
			writerCounter = statConn.WriteCounter
		}
		if !isEncryption { // avoids double penetration
			if xc, ok := conn.(*tls.Conn); ok {
				handler = xc.KTLSKeyUpdateHandler()
				conn = xc.NetConn()
			} else if rc, ok := conn.(*tls.RustConn); ok {
				handler = rc.KTLSKeyUpdateHandler()
				conn = rc.NetConn()
			} else if utlsConn, ok := conn.(*tls.UConn); ok {
				conn = utlsConn.NetConn()
			} else if realityConn, ok := conn.(*reality.Conn); ok {
				conn = realityConn.NetConn()
			} else if realityUConn, ok := conn.(*reality.UConn); ok {
				conn = realityUConn.NetConn()
			}
		}
		if pc, ok := conn.(*proxyproto.Conn); ok {
			conn = pc.Raw()
			// 8192 > 4096, there is no need to process pc's bufReader
		}
		if uc, ok := conn.(*internet.UnixConnWrapper); ok {
			conn = uc.UnixConn
		}
	}
	return conn, readCounter, writerCounter, handler
}

// startKeyUpdateMonitor creates and starts a KeyUpdateMonitor for a raw
// connection with the given handler. Returns nil (safe to Stop()) on any
// failure. Used by zero-copy paths (SOCKMAP, splice) that bypass Write()
// and thus skip the per-record write counter for TX key rotation.
func startKeyUpdateMonitor(rawConn net.Conn, handler *tls.KTLSKeyUpdateHandler) *tls.KeyUpdateMonitor {
	if handler == nil {
		return nil
	}
	fd, err := tls.ExtractFd(rawConn)
	if err != nil {
		return nil
	}
	m := tls.NewKeyUpdateMonitor(fd, handler)
	m.Start()
	return m
}

// DetermineSocketCryptoHint peels off connection wrappers and returns the
// underlying raw connection plus a CryptoHint describing the TLS state.
// This must be called BEFORE UnwrapRawConn because it inspects TLS wrappers.
func DetermineSocketCryptoHint(conn net.Conn) (net.Conn, ebpf.CryptoHint) {
	raw, hint, _ := determineSocketCryptoHintWithSource(conn)
	return raw, hint
}

const maxCryptoHintDepth = 8

func determineSocketCryptoHintWithSource(conn net.Conn) (net.Conn, ebpf.CryptoHint, string) {
	return determineSocketCryptoHintRecurse(conn, 0)
}

func determineSocketCryptoHintRecurse(conn net.Conn, depth int) (net.Conn, ebpf.CryptoHint, string) {
	if conn == nil {
		return nil, ebpf.CryptoNone, "nil"
	}
	if depth > maxCryptoHintDepth {
		// Conservative default: assume userspace TLS to prevent sockmap
		// from forwarding data under incorrect crypto assumptions.
		return nil, ebpf.CryptoUserspaceTLS, "depth-exceeded"
	}
	source := connTypeName(conn)

	// Peel encryption wrappers
	if commonConn, ok := conn.(*encryption.CommonConn); ok {
		source = appendCryptoHintSource(source, "*encryption.CommonConn")
		conn = commonConn.Conn
	}
	if _, ok := conn.(*encryption.XorConn); ok {
		return nil, ebpf.CryptoUserspaceTLS, appendCryptoHintSource(source, "*encryption.XorConn")
	}

	// Peel stats and proxyproto wrappers before TLS inspection.
	// NOTE: peel order here differs from UnwrapRawConn (which peels proxyproto
	// after TLS). Both orderings are correct because the type assertions are
	// independent — if proxyproto wraps TLS, we peel it first and see TLS next;
	// if TLS wraps proxyproto, the TLS branch fires first.
	if statConn, ok := conn.(*stat.CounterConnection); ok {
		source = appendCryptoHintSource(source, "*stat.CounterConnection")
		conn = statConn.Connection
	}
	if pc, ok := conn.(*proxyproto.Conn); ok {
		source = appendCryptoHintSource(source, "*proxyproto.Conn")
		conn = pc.Raw()
	}

	// Check TLS type
	if xc, ok := conn.(*tls.Conn); ok {
		ktls := xc.KTLSEnabled()
		raw := xc.NetConn()
		if ktls.TxReady && ktls.RxReady {
			return raw, ebpf.CryptoKTLSBoth, appendCryptoHintSource(source, "*tls.Conn("+ktlsStateName(ktls.TxReady, ktls.RxReady)+")")
		}
		if ktls.TxReady {
			return raw, ebpf.CryptoKTLSTxOnly, appendCryptoHintSource(source, "*tls.Conn("+ktlsStateName(ktls.TxReady, ktls.RxReady)+")")
		}
		if ktls.RxReady {
			return raw, ebpf.CryptoKTLSRxOnly, appendCryptoHintSource(source, "*tls.Conn("+ktlsStateName(ktls.TxReady, ktls.RxReady)+")")
		}
		return raw, ebpf.CryptoUserspaceTLS, appendCryptoHintSource(source, "*tls.Conn("+ktlsStateName(ktls.TxReady, ktls.RxReady)+")")
	}

	if rc, ok := conn.(*tls.RustConn); ok {
		ktls := rc.KTLSEnabled()
		raw := rc.NetConn()
		if ktls.TxReady && ktls.RxReady {
			return raw, ebpf.CryptoKTLSBoth, appendCryptoHintSource(source, "*tls.RustConn("+ktlsStateName(ktls.TxReady, ktls.RxReady)+")")
		}
		if ktls.TxReady {
			return raw, ebpf.CryptoKTLSTxOnly, appendCryptoHintSource(source, "*tls.RustConn("+ktlsStateName(ktls.TxReady, ktls.RxReady)+")")
		}
		if ktls.RxReady {
			return raw, ebpf.CryptoKTLSRxOnly, appendCryptoHintSource(source, "*tls.RustConn("+ktlsStateName(ktls.TxReady, ktls.RxReady)+")")
		}
		return raw, ebpf.CryptoUserspaceTLS, appendCryptoHintSource(source, "*tls.RustConn("+ktlsStateName(ktls.TxReady, ktls.RxReady)+")")
	}

	if utlsConn, ok := conn.(*tls.UConn); ok {
		if utlsConn == nil || utlsConn.UConn == nil {
			return nil, ebpf.CryptoUserspaceTLS, appendCryptoHintSource(source, "*tls.UConn(nil)")
		}
		inner := utlsConn.NetConn()
		innerRaw, _, innerSource := determineSocketCryptoHintRecurse(inner, depth+1)
		return innerRaw, ebpf.CryptoUserspaceTLS, appendCryptoHintSource(source, "*tls.UConn(userspace inner="+innerSource+")")
	}
	if realityConn, ok := conn.(*reality.Conn); ok {
		if realityConn == nil || realityConn.Conn == nil {
			return nil, ebpf.CryptoUserspaceTLS, appendCryptoHintSource(source, "*reality.Conn(nil)")
		}
		inner := realityConn.NetConn()
		innerRaw, _, innerSource := determineSocketCryptoHintRecurse(inner, depth+1)
		return innerRaw, ebpf.CryptoUserspaceTLS, appendCryptoHintSource(source, "*reality.Conn(userspace inner="+innerSource+")")
	}
	if realityUConn, ok := conn.(*reality.UConn); ok {
		if realityUConn == nil || realityUConn.UConn == nil {
			return nil, ebpf.CryptoUserspaceTLS, appendCryptoHintSource(source, "*reality.UConn(nil)")
		}
		inner := realityUConn.NetConn()
		innerRaw, _, innerSource := determineSocketCryptoHintRecurse(inner, depth+1)
		return innerRaw, ebpf.CryptoUserspaceTLS, appendCryptoHintSource(source, "*reality.UConn(userspace inner="+innerSource+")")
	}

	if _, ok := conn.(*net.TCPConn); ok {
		return conn, ebpf.CryptoNone, appendCryptoHintSource(source, "*net.TCPConn(raw)")
	}

	return nil, ebpf.CryptoNone, appendCryptoHintSource(source, connTypeName(conn))
}

// CopyRawConnIfExist use the most efficient copy method.
// - If caller don't want to turn on splice, do not pass in both reader conn and writer conn
// - writer are from *transport.Link
func CopyRawConnIfExist(ctx context.Context, readerConn net.Conn, writerConn net.Conn, writer buf.Writer, timer *signal.ActivityTimer, inTimer *signal.ActivityTimer) error {
	// Capture crypto state and diagnostic source before unwrapping TLS wrappers.
	// Source strings are computed once here and reused in the debug path below,
	// avoiding a redundant second traversal of the connection wrapper chain.
	_, readerCrypto, readerCryptoSource := determineSocketCryptoHintWithSource(readerConn)
	_, writerCrypto, writerCryptoSource := determineSocketCryptoHintWithSource(writerConn)

	readerConn, readCounter, _, readerHandler := UnwrapRawConn(readerConn)
	writerConn, _, writeCounter, writerHandler := UnwrapRawConn(writerConn)
	var readerForBuf net.Conn = readerConn
	if readerHandler != nil {
		readerForBuf = &ktlsReader{Conn: readerConn, handler: readerHandler}
	}
	reader := buf.NewReader(readerForBuf)
	if runtime.GOOS != "linux" && runtime.GOOS != "android" {
		errors.LogDebug(ctx, "CopyRawConn fallback to readv: unsupported OS ", runtime.GOOS)
		return readV(ctx, reader, writer, timer, readCounter)
	}
	if readerConn == nil || writerConn == nil {
		errors.LogDebug(ctx, "CopyRawConn fallback to readv: nil raw conn(s) readerType=", connTypeName(readerConn), " writerType=", connTypeName(writerConn))
		return readV(ctx, reader, writer, timer, readCounter)
	}
	tc, ok := writerConn.(*net.TCPConn)
	if !ok {
		errors.LogDebug(ctx, "CopyRawConn fallback to readv: writer is not *net.TCPConn (writerType=", connTypeName(writerConn), ")")
		return readV(ctx, reader, writer, timer, readCounter)
	}
	inbound := session.InboundFromContext(ctx)
	if inbound == nil {
		errors.LogDebug(ctx, "CopyRawConn fallback to readv: missing inbound metadata")
		return readV(ctx, reader, writer, timer, readCounter)
	}
	if inbound.CanSpliceCopy == 3 {
		errors.LogDebug(ctx, "CopyRawConn fallback to readv: inbound.CanSpliceCopy=3")
		return readV(ctx, reader, writer, timer, readCounter)
	}
	outbounds := session.OutboundsFromContext(ctx)
	if len(outbounds) == 0 {
		errors.LogDebug(ctx, "CopyRawConn fallback to readv: no outbound metadata")
		return readV(ctx, reader, writer, timer, readCounter)
	}
	for i, ob := range outbounds {
		if ob.CanSpliceCopy == 3 {
			errors.LogDebug(ctx, "CopyRawConn fallback to readv: outbounds[", i, "].CanSpliceCopy=3")
			return readV(ctx, reader, writer, timer, readCounter)
		}
	}

	loggedUserspaceLoop := false
	for {
		var splice = inbound.CanSpliceCopy == 1
		firstNonSpliceOutbound := -1
		firstNonSpliceValue := 0
		for i, ob := range outbounds {
			if ob.CanSpliceCopy != 1 {
				splice = false
				if firstNonSpliceOutbound == -1 {
					firstNonSpliceOutbound = i
					firstNonSpliceValue = ob.CanSpliceCopy
				}
			}
		}
		if splice {
			// Try eBPF sockmap first — kernel-level forwarding without pipe buffers.
			if mgr := ebpf.GlobalSockmapManager(); mgr == nil {
				errors.LogDebug(ctx, "CopyRawConn sockmap skipped: manager unavailable")
			} else if mgr.ShouldFallbackToSplice() {
				errors.LogDebug(ctx, "CopyRawConn sockmap skipped: contention fallback active")
			} else if !ebpf.CanUseZeroCopyWithCrypto(readerConn, writerConn, readerCrypto, writerCrypto) {
				errors.LogDebug(ctx, "CopyRawConn crypto hint: reader=", int(readerCrypto), "[", cryptoHintName(readerCrypto), "] source=", readerCryptoSource, " writer=", int(writerCrypto), "[", cryptoHintName(writerCrypto), "] source=", writerCryptoSource)
				switch {
				case !ebpf.KTLSSockhashCompatible() && (readerCrypto == ebpf.CryptoKTLSBoth || writerCrypto == ebpf.CryptoKTLSBoth):
					errors.LogDebug(ctx, "CopyRawConn sockmap skipped: kTLS+SOCKHASH not supported on this kernel, using splice")
					mgr.IncrementKTLSSpliceFallback()
				case readerCrypto == ebpf.CryptoUserspaceTLS || writerCrypto == ebpf.CryptoUserspaceTLS:
					errors.LogDebug(ctx, "CopyRawConn sockmap skipped: userspace TLS not eligible (readerCrypto=", int(readerCrypto), "[", cryptoHintName(readerCrypto), "] writerCrypto=", int(writerCrypto), "[", cryptoHintName(writerCrypto), "] readerType=", connTypeName(readerConn), " writerType=", connTypeName(writerConn), ")")
				case (readerCrypto == ebpf.CryptoKTLSBoth) != (writerCrypto == ebpf.CryptoKTLSBoth):
					errors.LogDebug(ctx, "CopyRawConn sockmap skipped: asymmetric kTLS state (readerCrypto=", int(readerCrypto), "[", cryptoHintName(readerCrypto), "] writerCrypto=", int(writerCrypto), "[", cryptoHintName(writerCrypto), "] readerType=", connTypeName(readerConn), " writerType=", connTypeName(writerConn), ")")
				default:
					errors.LogDebug(ctx, "CopyRawConn sockmap skipped: policy/type mismatch (readerCrypto=", int(readerCrypto), "[", cryptoHintName(readerCrypto), "] writerCrypto=", int(writerCrypto), "[", cryptoHintName(writerCrypto), "] readerType=", connTypeName(readerConn), " writerType=", connTypeName(writerConn), ")")
				}
			} else {
				if err := mgr.RegisterPairWithCrypto(readerConn, writerConn, readerCrypto, writerCrypto); err == nil {
					errors.LogDebug(ctx, "CopyRawConn sockmap (crypto: reader=", int(readerCrypto), " writer=", int(writerCrypto), ")")
					writerMonitor := startKeyUpdateMonitor(writerConn, writerHandler)
					timer.SetTimeout(24 * time.Hour)
					if inTimer != nil {
						inTimer.SetTimeout(24 * time.Hour)
					}
					fallbackToSplice, waitErr := waitForSockmapForwarding(readerConn, writerConn)
					writerMonitor.Stop()
					if err := mgr.UnregisterPair(readerConn, writerConn); err != nil {
						errors.LogDebugInner(ctx, err, "CopyRawConn sockmap unregister failed")
					}
					// Prevent GC from finalizing connections while BPF ops used their FDs.
					runtime.KeepAlive(readerConn)
					runtime.KeepAlive(writerConn)
					if waitErr != nil {
						errors.LogDebugInner(ctx, waitErr, "CopyRawConn sockmap wait failed, falling back to splice")
					} else if !fallbackToSplice {
						return nil
					} else {
						errors.LogDebug(ctx, "CopyRawConn sockmap inactive, falling back to splice")
					}
				} else {
					errors.LogDebugInner(ctx, err, "CopyRawConn sockmap register failed, falling back to splice")
				}
			}
			// Fall through to splice on sockmap failure

			errors.LogDebug(ctx, "CopyRawConn splice")
			statWriter, _ := writer.(*dispatcher.SizeStatWriter)
			//runtime.Gosched() // necessary
			time.Sleep(time.Millisecond)     // without this, there will be a rare ssl error for freedom splice
			timer.SetTimeout(24 * time.Hour) // prevent leak, just in case
			if inTimer != nil {
				inTimer.SetTimeout(24 * time.Hour)
			}
			writerMonitor := startKeyUpdateMonitor(writerConn, writerHandler)
			w, err := tc.ReadFrom(readerConn)
			writerMonitor.Stop()
			if readCounter != nil {
				readCounter.Add(w) // outbound stats
			}
			if writeCounter != nil {
				writeCounter.Add(w) // inbound stats
			}
			if statWriter != nil {
				statWriter.Counter.Add(w) // user stats
			}
			if err != nil && readerHandler != nil && tls.IsKeyExpired(err) {
				if herr := readerHandler.Handle(); herr != nil {
					return herr
				}
				continue // retry splice after key update
			}
			if err != nil && errors.Cause(err) != io.EOF {
				return err
			}
			return nil
		}
		if !loggedUserspaceLoop {
			if inbound.CanSpliceCopy != 1 {
				errors.LogDebug(ctx, "CopyRawConn userspace copy loop: inbound.CanSpliceCopy=", inbound.CanSpliceCopy)
			} else {
				errors.LogDebug(ctx, "CopyRawConn userspace copy loop: outbounds[", firstNonSpliceOutbound, "].CanSpliceCopy=", firstNonSpliceValue)
			}
			loggedUserspaceLoop = true
		}
		buffer, err := reader.ReadMultiBuffer()
		if !buffer.IsEmpty() {
			if readCounter != nil {
				readCounter.Add(int64(buffer.Len()))
			}
			timer.Update()
			if werr := writer.WriteMultiBuffer(buffer); werr != nil {
				return werr
			}
		}
		if err != nil {
			if errors.Cause(err) == io.EOF {
				return nil
			}
			return err
		}
	}
}

func connTypeName(conn net.Conn) string {
	if conn == nil {
		return "<nil>"
	}
	return reflect.TypeOf(conn).String()
}

func appendCryptoHintSource(source, step string) string {
	if source == "" {
		return step
	}
	if step == "" {
		return source
	}
	return source + " -> " + step
}

func ktlsStateName(txReady, rxReady bool) string {
	switch {
	case txReady && rxReady:
		return "ktls-both"
	case txReady:
		return "ktls-tx-only"
	case rxReady:
		return "ktls-rx-only"
	default:
		return "userspace"
	}
}

func cryptoHintName(h ebpf.CryptoHint) string {
	switch h {
	case ebpf.CryptoNone:
		return "none"
	case ebpf.CryptoKTLSBoth:
		return "ktls-both"
	case ebpf.CryptoKTLSTxOnly:
		return "ktls-tx-only"
	case ebpf.CryptoKTLSRxOnly:
		return "ktls-rx-only"
	case ebpf.CryptoUserspaceTLS:
		return "userspace-tls"
	default:
		return "unknown"
	}
}

func readV(ctx context.Context, reader buf.Reader, writer buf.Writer, timer signal.ActivityUpdater, readCounter stats.Counter) error {
	errors.LogDebug(ctx, "CopyRawConn (maybe) readv")
	if err := buf.Copy(reader, writer, buf.UpdateActivity(timer), buf.AddToStatCounter(readCounter)); err != nil {
		return errors.New("failed to process response").Base(err)
	}
	return nil
}

func IsRAWTransportWithoutSecurity(conn stat.Connection) bool {
	iConn := stat.TryUnwrapStatsConn(conn)
	_, ok1 := iConn.(*proxyproto.Conn)
	_, ok2 := iConn.(*net.TCPConn)
	_, ok3 := iConn.(*internet.UnixConnWrapper)
	return ok1 || ok2 || ok3
}
