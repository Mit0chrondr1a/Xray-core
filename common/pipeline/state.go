package pipeline

// FFI-stable state and error enums for the REALITY/Vision handoff.
// These mirror rust/xray-rust/src/pipeline.rs and keep ownership clear.

type State int32

const (
	StateInit     State = 0
	StatePeek     State = 1
	StatePadWait  State = 2
	StateDetach   State = 3
	StateZeroCopy State = 4
	StateFallback State = 5
	StateClosed   State = 6
	StateFatal    State = 7
)

type ErrorClass int32

const (
	ErrNone    ErrorClass = 0
	ErrTimeout ErrorClass = 1
	ErrRefused ErrorClass = 2
	ErrNoRoute ErrorClass = 3
	ErrFatal   ErrorClass = 4
)

// CapabilitySummary is meant to be filled from a single startup probe and cached.
type CapabilitySummary struct {
	KTLSSupported    bool
	SockmapSupported bool
	SpliceSupported  bool
}
