//go:build linux && !(amd64 || arm64)

package tls

// memzero overwrites b with zeros.
//
// On architectures without dedicated assembly (amd64 and arm64 have assembly
// in memzero_*.s), this falls back to a Go loop guarded by //go:noinline.
//
// # Strength of guarantee
//
// The //go:noinline directive prevents the compiler from inlining this function
// and subsequently eliminating the zero writes as dead stores.  Inside this
// function, Go 1.26's compiler recognises the zero-loop and emits a call to
// runtime.memclrNoHeapPointers (assembly), which itself cannot be eliminated.
//
// The remaining theoretical weakness: a future compiler with interprocedural
// dead-store analysis could determine this function only modifies its argument
// and eliminate the call when the argument is provably dead.  This does NOT
// happen with any current Go compiler version (verified through Go 1.26).
//
// For kTLS in practice, this fallback is academic: kTLS requires kernel support
// that only exists on amd64 and arm64, where the assembly path applies.
//
// # Migration path
//
// When crypto/subtle.Zero or an equivalent stable stdlib API appears
// (see https://go.dev/issue/33325), replace this entire file and its assembly
// counterparts with a one-line call.  See memzero_asm.go for the full
// migration plan.
//
//go:noinline
func memzero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
