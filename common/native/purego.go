//go:build !cgo || !linux

package native

import "errors"

// Available returns false when the native Rust library is not linked.
func Available() bool {
	return false
}

var errNotAvailable = errors.New("native TLS not available (build without CGO or non-Linux)")

// ErrRealityAuthFailed indicates REALITY auth failed and Go should handle fallback.
var ErrRealityAuthFailed = errors.New("REALITY auth failed: needs fallback")

// --- TLS Types ---

type TlsConfigHandle struct{}
type TlsStateHandle struct{}

func (*TlsConfigHandle) release() {}
func (*TlsStateHandle) release()  {}

type TlsResult struct {
	KtlsTx      bool
	KtlsRx      bool
	Version     uint16
	CipherSuite uint16
	ALPN        string
	StateHandle *TlsStateHandle
	TxSecret    []byte
	RxSecret    []byte
	DrainedData []byte
}

// ZeroSecrets zeroes the traffic secret fields after they have been copied.
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

func TlsConfigNew(bool) *TlsConfigHandle                             { return nil }
func TlsConfigSetServerName(*TlsConfigHandle, string)                {}
func TlsConfigAddCertPEM(*TlsConfigHandle, []byte, []byte) error     { return errNotAvailable }
func TlsConfigAddRootCAPEM(*TlsConfigHandle, []byte) error           { return errNotAvailable }
func TlsConfigUseSystemRoots(*TlsConfigHandle)                       {}
func TlsConfigSetALPN(*TlsConfigHandle, []byte)                      {}
func TlsConfigSetVersions(*TlsConfigHandle, uint16, uint16)          {}
func TlsConfigSetInsecureSkipVerify(*TlsConfigHandle, bool)          {}
func TlsConfigPinCertSHA256(*TlsConfigHandle, []byte)                {}
func TlsConfigAddVerifyName(*TlsConfigHandle, string)                {}
func TlsConfigSetKeyLogPath(*TlsConfigHandle, string)                {}
func TlsConfigFree(*TlsConfigHandle)                                 {}

// --- TLS Handshake Stubs ---

func TlsHandshake(int, *TlsConfigHandle, bool) (*TlsResult, error) {
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

func RealityConfigNew(bool) *RealityConfigHandle                                      { return nil }
func RealityConfigSetServerPubkey(*RealityConfigHandle, []byte)                        {}
func RealityConfigSetShortId(*RealityConfigHandle, []byte)                             {}
func RealityConfigSetMldsa65Verify(*RealityConfigHandle, []byte)                       {}
func RealityConfigSetVersion(*RealityConfigHandle, uint8, uint8, uint8)                {}
func RealityConfigFree(*RealityConfigHandle)                                           {}
func RealityConfigSetPrivateKey(*RealityConfigHandle, []byte)                          {}
func RealityConfigSetServerNames(*RealityConfigHandle, []byte)                         {}
func RealityConfigSetShortIds(*RealityConfigHandle, []byte)                            {}
func RealityConfigSetMldsa65Key(*RealityConfigHandle, []byte)                          {}
func RealityConfigSetDest(*RealityConfigHandle, string)                                {}
func RealityConfigSetMaxTimeDiff(*RealityConfigHandle, uint64)                         {}
func RealityConfigSetVersionRange(*RealityConfigHandle, uint8, uint8, uint8, uint8, uint8, uint8) {}
func RealityConfigSetTLSCert(*RealityConfigHandle, []byte, []byte)                     {}

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
