// Copyright 2024 The bio authors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

// Assembly stubs for reading C library constants from their addresses.
// These are used to dereference uintptr values from purego.Dlsym without
// triggering the go vet unsafeptr check, which is a false positive for
// stable C library memory that is not managed by the Go GC.

#include "textflag.h"

// func derefUintptr(addr uintptr) uintptr
TEXT ·derefUintptr(SB),NOSPLIT,$0-16
	MOVD	addr+0(FP), R0
	MOVD	(R0), R0
	MOVD	R0, ret+8(FP)
	RET

// func copyFromC(src uintptr, dst unsafe.Pointer, n int)
// Copies n bytes from C address src to Go address dst.
TEXT ·copyFromC(SB),NOSPLIT,$0-24
	MOVD	src+0(FP), R0
	MOVD	dst+8(FP), R1
	MOVD	n+16(FP), R2
	CBZ	R2, done
loop:
	MOVBU	(R0), R3
	MOVBU	R3, (R1)
	ADD	$1, R0
	ADD	$1, R1
	SUB	$1, R2
	CBNZ	R2, loop
done:
	RET
