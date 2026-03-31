//go:build !cgo || !linux

package native

import (
	"errors"
	"os"
	"strings"
	"time"
	"unsafe"

	"lukechampine.com/blake3"

	"github.com/xtls/xray-core/common/pipeline"
)

// Available returns false when the native Rust library is not linked.
func Available() bool {
	return false
}

func CapabilitiesSummary() pipeline.CapabilitySummary {
	return pipeline.CapabilitySummary{SpliceSupported: true}
}

// EbpfAvailable reports whether native eBPF support is available.
func EbpfAvailable() bool {
	return false
}

var errNotAvailable = errors.New("native TLS not available (build without CGO or non-Linux)")

type deferredDeadlineError struct{}

func (deferredDeadlineError) Error() string   { return os.ErrDeadlineExceeded.Error() }
func (deferredDeadlineError) Timeout() bool   { return true }
func (deferredDeadlineError) Temporary() bool { return true }
func (deferredDeadlineError) Unwrap() error   { return os.ErrDeadlineExceeded }

type deferredWouldBlockError struct{}

func (deferredWouldBlockError) Error() string   { return "native: deferred read would block" }
func (deferredWouldBlockError) Timeout() bool   { return false }
func (deferredWouldBlockError) Temporary() bool { return true }

// ErrDeferredWouldBlock mirrors the CGO build's retryable zero-deadline
// deferred-read wake-up signal.
var ErrDeferredWouldBlock error = deferredWouldBlockError{}

// ErrRealityAuthFailed indicates REALITY auth failed and Go should handle fallback.
var ErrRealityAuthFailed = errors.New("REALITY auth failed: needs fallback")

// ErrRealityDeferredPeekTimeout indicates deferred REALITY failed during the
// pre-auth MSG_PEEK phase and callers may safely fall back to Go REALITY.
var ErrRealityDeferredPeekTimeout = errors.New("REALITY deferred peek timeout: needs fallback")

// ErrRealityDeferredHandshakePeerAbort indicates deferred REALITY advanced
// into the handshake phase and then hit a peer-abort/short-read condition.
// The connection is no longer safe for same-socket Go fallback, but this
// should not be treated as a breaker-worthy internal transport failure.
var ErrRealityDeferredHandshakePeerAbort = errors.New("REALITY deferred handshake peer abort: close connection")

func isRealityDeferredPeekTimeoutMsg(msg string) bool {
	m := strings.ToLower(msg)
	return strings.Contains(m, "peek_exact: receive timeout") ||
		strings.Contains(m, "peek_exact: handshake timeout exceeded") ||
		strings.Contains(m, "peek_exact: short read after")
}

func isRealityDeferredHandshakePeerAbortMsg(msg string) bool {
	m := strings.ToLower(msg)
	return strings.Contains(m, "handshake: failed to fill whole buffer") ||
		strings.Contains(m, "handshake: peer closed")
}

// IsRealityDeferredPeekTimeout reports whether err represents a deferred
// REALITY pre-auth MSG_PEEK timeout/short-read condition.
func IsRealityDeferredPeekTimeout(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrRealityDeferredPeekTimeout) {
		return true
	}
	return isRealityDeferredPeekTimeoutMsg(err.Error())
}

// IsRealityDeferredHandshakePeerAbort reports whether err represents a
// deferred REALITY handshake short-read / peer-close after the handshake
// phase has begun consuming bytes.
func IsRealityDeferredHandshakePeerAbort(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrRealityDeferredHandshakePeerAbort) {
		return true
	}
	return isRealityDeferredHandshakePeerAbortMsg(err.Error())
}

// --- TLS Types ---

type TlsConfigHandle struct{}
type TlsStateHandle struct{}

func (*TlsConfigHandle) release() {}
func (*TlsStateHandle) release()  {}

type DeferredHandleOwnership uint8

const (
	DeferredHandleOwnershipUnknown DeferredHandleOwnership = iota
	DeferredHandleOwnershipConsumed
	DeferredHandleOwnershipRetained
)

type TlsResult struct {
	KtlsTx                  bool
	KtlsRx                  bool
	Version                 uint16
	CipherSuite             uint16
	ALPN                    string
	RxSeqStart              uint64
	StateHandle             *TlsStateHandle
	DeferredHandleOwnership DeferredHandleOwnership
	TxSecret                []byte
	RxSecret                []byte
	DrainedData             []byte
}

// ZeroSecrets zeroes the traffic secret fields after they have been copied.
//
//go:noinline
func (r *TlsResult) ZeroSecrets() {
	for i := range r.TxSecret {
		r.TxSecret[i] = 0
	}
	for i := range r.RxSecret {
		r.RxSecret[i] = 0
	}
	r.TxSecret = nil
	r.RxSecret = nil
}

// --- TLS Config Builder Stubs ---

func TlsConfigNew(bool) *TlsConfigHandle                         { return nil }
func TlsConfigSetServerName(*TlsConfigHandle, string)            {}
func TlsConfigAddCertPEM(*TlsConfigHandle, []byte, []byte) error { return errNotAvailable }
func TlsConfigAddRootCAPEM(*TlsConfigHandle, []byte) error       { return errNotAvailable }
func TlsConfigUseSystemRoots(*TlsConfigHandle)                   {}
func TlsConfigSetALPN(*TlsConfigHandle, []byte)                  {}
func TlsConfigSetVersions(*TlsConfigHandle, uint16, uint16)      {}
func TlsConfigSetInsecureSkipVerify(*TlsConfigHandle, bool)      {}
func TlsConfigPinCertSHA256(*TlsConfigHandle, []byte)            {}
func TlsConfigAddVerifyName(*TlsConfigHandle, string)            {}
func TlsConfigSetKeyLogPath(*TlsConfigHandle, string)            {}
func TlsConfigFree(*TlsConfigHandle)                             {}

// --- TLS Handshake Stubs ---

func TlsHandshake(int, *TlsConfigHandle, bool) (*TlsResult, error) {
	return nil, errNotAvailable
}

func TlsHandshakeWithTimeout(int, *TlsConfigHandle, bool, time.Duration) (*TlsResult, error) {
	return nil, errNotAvailable
}

func TlsKeyUpdate(*TlsStateHandle) error {
	return errNotAvailable
}

func TlsStateFree(*TlsStateHandle) {}

// --- REALITY Types ---

type RealityConfigHandle struct{}

func (*RealityConfigHandle) release() {}

// --- REALITY Config Builder Stubs ---

func RealityConfigNew(bool) *RealityConfigHandle                                                  { return nil }
func RealityConfigSetServerPubkey(*RealityConfigHandle, []byte)                                   {}
func RealityConfigSetShortId(*RealityConfigHandle, []byte)                                        {}
func RealityConfigSetMldsa65Verify(*RealityConfigHandle, []byte)                                  {}
func RealityConfigSetVersion(*RealityConfigHandle, uint8, uint8, uint8)                           {}
func RealityConfigFree(*RealityConfigHandle)                                                      {}
func RealityConfigSetPrivateKey(*RealityConfigHandle, []byte)                                     {}
func RealityConfigSetServerNames(*RealityConfigHandle, []byte)                                    {}
func RealityConfigSetShortIds(*RealityConfigHandle, []byte)                                       {}
func RealityConfigSetMldsa65Key(*RealityConfigHandle, []byte)                                     {}
func RealityConfigSetDest(*RealityConfigHandle, string)                                           {}
func RealityConfigSetMaxTimeDiff(*RealityConfigHandle, uint64)                                    {}
func RealityConfigSetVersionRange(*RealityConfigHandle, uint8, uint8, uint8, uint8, uint8, uint8) {}
func RealityConfigSetTLSCert(*RealityConfigHandle, []byte, []byte)                                {}

func RealityConfigAddShortId(*RealityConfigHandle, []byte) {}

// --- REALITY Handshake Stubs ---

func RealityClientConnect(int, []byte, []byte, *RealityConfigHandle) (*TlsResult, error) {
	return nil, errNotAvailable
}

func RealityServerAccept(int, *RealityConfigHandle) (*TlsResult, error) {
	return nil, errNotAvailable
}

func RealityServerHandshake(int, *RealityConfigHandle) (*TlsResult, error) {
	return nil, errNotAvailable
}

func RealityServerHandshakeWithTimeout(int, *RealityConfigHandle, time.Duration) (*TlsResult, error) {
	return nil, errNotAvailable
}

// --- Deferred REALITY Session Stubs ---

type DeferredSessionHandle struct{}
type DeferredResult struct {
	Handle      *DeferredSessionHandle
	Version     uint16
	CipherSuite uint16
	ALPN        string
	SNI         string
}

func RealityServerDeferred(int, *RealityConfigHandle, time.Duration) (*DeferredResult, error) {
	return nil, errNotAvailable
}
func TlsServerDeferred(int, *TlsConfigHandle, time.Duration) (*DeferredResult, error) {
	return nil, errNotAvailable
}
func DeferredRead(*DeferredSessionHandle, []byte) (int, error)  { return 0, errNotAvailable }
func DeferredWrite(*DeferredSessionHandle, []byte) (int, error) { return 0, errNotAvailable }
func DeferredReadWithDeadline(*DeferredSessionHandle, []byte, time.Time) (int, error) {
	return 0, errNotAvailable
}
func DeferredWriteWithDeadline(*DeferredSessionHandle, []byte, time.Time) (int, error) {
	return 0, errNotAvailable
}
func DeferredDrainAndDetach(*DeferredSessionHandle) ([]byte, []byte, error) {
	return nil, nil, errNotAvailable
}
func DeferredEnableKTLS(*DeferredSessionHandle) (*TlsResult, error) {
	return nil, errNotAvailable
}
func DeferredHandleAlive(*DeferredSessionHandle) bool      { return false }
func DeferredRestoreNonBlock(*DeferredSessionHandle) error { return nil }
func DeferredFree(*DeferredSessionHandle)                  {}

// --- Blake3 (delegates to lukechampine.com/blake3) ---

// Blake3DeriveKey derives a key using BLAKE3's KDF mode.
func Blake3DeriveKey(out []byte, ctx string, key []byte) {
	blake3.DeriveKey(out, ctx, key)
}

// Blake3Sum256 computes a 32-byte BLAKE3 hash.
func Blake3Sum256(data []byte) [32]byte {
	return blake3.Sum256(data)
}

// Blake3KeyedHash computes a BLAKE3 keyed hash (MAC mode).
func Blake3KeyedHash(key *[32]byte, data []byte, outLen int) []byte {
	if outLen <= 0 {
		return nil
	}
	h := blake3.New(outLen, key[:])
	h.Write(data)
	return h.Sum(nil)
}

// --- MPH (stubs — caller must fall back to Go implementation) ---

// MphHandle is an opaque handle to a native MPH table.
type MphHandle struct {
	ptr unsafe.Pointer
}

func MphNew() *MphHandle                     { return nil }
func MphAddPattern(*MphHandle, string, byte) {}
func MphBuild(*MphHandle)                    {}
func MphMatch(*MphHandle, string) bool       { return false }
func MphFree(*MphHandle)                     {}

// --- GeoIP (stubs — caller must fall back to Go implementation) ---

// IpSetHandle is an opaque handle to a native IP prefix set.
type IpSetHandle struct {
	ptr unsafe.Pointer
}

func IpSetNew() *IpSetHandle                   { return nil }
func IpSetAddPrefix(*IpSetHandle, []byte, int) {}
func IpSetBuild(*IpSetHandle)                  {}
func IpSetContains(*IpSetHandle, []byte) bool  { return false }
func IpSetMax4(*IpSetHandle) uint8             { return 0xff }
func IpSetMax6(*IpSetHandle) uint8             { return 0xff }
func IpSetFree(*IpSetHandle)                   {}

// --- Vision Padding Stubs ---

type VisionUnpadState struct {
	RemainingCommand int32
	RemainingContent int32
	RemainingPadding int32
	CurrentCommand   int32
}

func NewVisionUnpadState() *VisionUnpadState {
	return &VisionUnpadState{
		RemainingCommand: -1,
		RemainingContent: -1,
		RemainingPadding: -1,
		CurrentCommand:   0,
	}
}

func VisionPad([]byte, byte, []byte, bool, [4]uint32, []byte) (int, error) {
	return 0, errNotAvailable
}

func VisionUnpad([]byte, *VisionUnpadState, []byte, []byte) (int, error) {
	return 0, errNotAvailable
}

// VisionFilterState is the stateful TLS filter state (matches Rust's VisionFilterState).
type VisionFilterState struct {
	RemainingServerHello    int32
	NumberOfPacketsToFilter int32
	Cipher                  uint16
	IsTLS                   bool
	IsTLS12orAbove          bool
	EnableXtls              bool
}

// VisionFilterStateSizeC returns the Go-side sizeof(VisionFilterState) when native is unavailable.
func VisionFilterStateSizeC() uintptr {
	return unsafe.Sizeof(VisionFilterState{})
}

func VisionFilterTls([]byte, *VisionFilterState) bool {
	return false
}

func VisionIsCompleteRecord([]byte) bool {
	return false
}

// --- AEAD Stubs ---

const (
	AeadAes128Gcm        = 0
	AeadAes256Gcm        = 1
	AeadChacha20Poly1305 = 2
)

type AeadHandle struct {
	ptr unsafe.Pointer
}

func (*AeadHandle) release() {}

func AeadNew(byte, []byte) *AeadHandle                                    { return nil }
func AeadSeal(*AeadHandle, []byte, []byte, []byte) ([]byte, error)        { return nil, errNotAvailable }
func AeadOpen(*AeadHandle, []byte, []byte, []byte) ([]byte, error)        { return nil, errNotAvailable }
func AeadSealTo(*AeadHandle, []byte, []byte, []byte, []byte) (int, error) { return 0, errNotAvailable }
func AeadOpenTo(*AeadHandle, []byte, []byte, []byte, []byte) (int, error) { return 0, errNotAvailable }
func AeadOverhead(*AeadHandle) int                                        { return 0 }
func AeadNonceSize(*AeadHandle) int                                       { return 0 }
func aeadFree(*AeadHandle)                                                {}

// --- VMess AEAD Header Stubs ---

func VMessSealHeader([16]byte, []byte) ([]byte, error)           { return nil, errNotAvailable }
func VMessOpenHeader([16]byte, [16]byte, []byte) ([]byte, error) { return nil, errNotAvailable }

// --- Geodata Batch Loading Stubs ---

type GeoSiteEntry struct {
	DomainType byte
	Value      string
}

func GeoIPLoad(string, []string) ([]*IpSetHandle, error)     { return nil, errNotAvailable }
func GeoSiteLoad(string, []string) ([][]GeoSiteEntry, error) { return nil, errNotAvailable }

// --- eBPF Stubs ---

// SkMsgCapability indicates which SK_MSG tier the Rust/Aya loader achieved.
type SkMsgCapability int

const (
	SkMsgFull     SkMsgCapability = 0
	SkMsgCorkOnly SkMsgCapability = 1
	SkMsgNone     SkMsgCapability = 2
)

// EbpfSkMsgCapability returns SkMsgNone when native eBPF is not available.
func EbpfSkMsgCapability() SkMsgCapability { return SkMsgNone }
func EbpfMaxEntries() uint32               { return 0 }

func EbpfSetup(string, uint32, uint32) error                  { return errNotAvailable }
func EbpfTeardown() error                                     { return errNotAvailable }
func EbpfRegisterPair(int, int, uint64, uint64, uint32) error { return errNotAvailable }
func EbpfUnregisterPair(uint64, uint64) error                 { return errNotAvailable }
