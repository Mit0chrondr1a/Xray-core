// Copyright 2026 Xray Authors. All rights reserved.
// Use of this source code is governed by the same license as xray-core.

#include "textflag.h"

// func memzero(b []byte)
//
// Zeroes len(b) bytes starting at &b[0].
// Uses 16-byte STP (store pair of zero registers) for bulk, byte stores
// for the tail.  Sufficient for the 16–76 byte crypto structs we erase.
//
// See memzero_amd64.s for rationale on why this must be assembly, and
// memzero_asm.go for the migration plan.
//
// DELETE THIS FILE when crypto/subtle.Zero or runtime/secret graduates to
// a stable API.  See memzero_asm.go for the migration checklist.
TEXT ·memzero(SB), NOSPLIT, $0-24
	MOVD	b_base+0(FP), R0	// dst pointer
	MOVD	b_len+8(FP), R1	// byte count
	CBZ	R1, done

	// Bulk: 16 bytes at a time via STP of zero register pair.
	CMP	$16, R1
	BLT	tail
bulk:
	STP	(ZR, ZR), (R0)
	ADD	$16, R0
	SUB	$16, R1
	CMP	$16, R1
	BGE	bulk

tail:
	CBZ	R1, done
tail_loop:
	MOVB	ZR, (R0)
	ADD	$1, R0
	SUB	$1, R1
	CBNZ	R1, tail_loop

done:
	RET
