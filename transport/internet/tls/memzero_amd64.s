// Copyright 2026 Xray Authors. All rights reserved.
// Use of this source code is governed by the same license as xray-core.

#include "textflag.h"

// func memzero(b []byte)
//
// Zeroes len(b) bytes starting at &b[0] using REP STOSB.
// Modern x86-64 CPUs with ERMS (Enhanced REP MOVSB/STOSB, Sandy Bridge+)
// execute REP STOSB at memory-bandwidth speed, making this optimal for the
// 16–76 byte crypto info structs we erase after setsockopt.
//
// This MUST be in assembly so that the compiler cannot analyse the function
// body and conclude the stores are dead.  The Go-side //go:noescape directive
// forces the compiler to treat the slice pointer as potentially escaping,
// preventing elimination of the call.  See memzero_asm.go for the full
// rationale and migration plan.
//
// DELETE THIS FILE when crypto/subtle.Zero or runtime/secret graduates to
// a stable API.  See memzero_asm.go for the migration checklist.
TEXT ·memzero(SB), NOSPLIT, $0-24
	MOVQ	b_base+0(FP), DI	// dst pointer
	MOVQ	b_len+8(FP), CX	// byte count
	XORQ	AX, AX			// value to store (zero)
	REP
	STOSB
	RET
