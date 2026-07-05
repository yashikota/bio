// Copyright 2024 The bio authors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

// Assembly stubs for reading C library constants from their addresses.
// These are used to dereference uintptr values from purego.Dlsym without
// triggering the go vet unsafeptr check, which is a false positive for
// stable C library memory that is not managed by the Go GC.

#include "textflag.h"

// func derefUintptr(addr uintptr) uintptr
TEXT ·derefUintptr(SB),NOSPLIT,$0-16
	MOVQ	addr+0(FP), AX
	MOVQ	(AX), AX
	MOVQ	AX, ret+8(FP)
	RET

// func copyFromC(src uintptr, dst unsafe.Pointer, n int)
// Copies n bytes from C address src to Go address dst.
TEXT ·copyFromC(SB),NOSPLIT,$0-24
	MOVQ	src+0(FP), SI
	MOVQ	dst+8(FP), DI
	MOVQ	n+16(FP), CX
	REP; MOVSB
	RET
