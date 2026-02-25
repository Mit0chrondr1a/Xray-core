//go:build linux && (amd64 || arm64)

package tls

// memzero overwrites b with zeros using a platform-specific assembly routine.
//
// # Why assembly
//
// Go 1.26's compiler performs dead-store elimination (DSE) on clear() and
// zero-loops when it can prove the buffer is unused after the writes.  We
// verified this empirically: a function that writes key material to a stack
// buffer then calls clear() compiles to a single RET — the key stays on the
// stack.  The //go:noinline directive on a wrapper function prevents DSE
// today (the compiler won't inline across the call), but that is a compiler
// behaviour, not a spec guarantee.  A future interprocedural DSE pass could
// analyse the non-inlined callee, determine it only modifies its dead
// argument, and eliminate the call.
//
// Assembly combined with //go:noescape provides a formal guarantee:
//
//  1. The compiler cannot inspect the function body (opaque assembly).
//  2. //go:noescape declares the pointer may escape to unknown code.
//  3. Therefore the compiler cannot prove the memory is dead at the call site.
//  4. Therefore it must retain the call under any optimisation strategy.
//
// # Migration path — when to remove this
//
// Replace memzero with a standard-library secure-zero API when one becomes
// available.  Candidates, in order of preference:
//
//   - crypto/subtle.Zero (proposed: https://go.dev/issue/33325) — if accepted,
//     this would be a single-line drop-in replacement with stdlib guarantees.
//     Delete memzero_*.s, memzero_asm.go, and memzero_noasm.go entirely.
//
//   - runtime/secret.Do wrapping (Go 1.26 GOEXPERIMENT=runtimesecret) — when
//     the experiment graduates to a stable API, consider wrapping the entire
//     kTLS key-install path in secret.Do() for stack+register+heap erasure.
//     This is heavier than a point-zero API but provides forward secrecy for
//     the full call tree, not just individual buffers.
//
// Until one of these lands as a stable API, this assembly approach is correct,
// portable across Go versions (Go plan9 assembly is stable ABI), and has zero
// runtime cost beyond the actual memset.
//
//go:noescape
func memzero(b []byte)
