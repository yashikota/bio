//go:build darwin

package darwin

import "unsafe"

// derefUintptr reads the uintptr value at the C library address addr.
// addr must point to OS/C library memory that the GC does not manage.
// Implemented in assembly to avoid the go vet unsafeptr false positive.
func derefUintptr(addr uintptr) uintptr

// derefUint64 reads the uint64 value at the C library address addr.
// addr must point to OS/C library memory that the GC does not manage.
// Implemented in assembly to avoid the go vet unsafeptr false positive.
func derefUint64(addr uintptr) uint64

// copyBytesFromC copies n bytes from the C memory address src into a new Go []byte.
// src must point to C/CF-managed memory that the GC does not manage.
// This avoids the go vet unsafeptr false positive by routing through
// a pointer to a Go-allocated buffer rather than converting the C pointer directly.
func copyBytesFromC(src uintptr, n int) []byte {
	dst := make([]byte, n)
	copyFromC(src, unsafe.Pointer(&dst[0]), n)
	return dst
}

// copyFromC copies n bytes from C address src to Go address dst.
// Implemented in assembly to avoid go vet unsafeptr on the C src pointer.
func copyFromC(src uintptr, dst unsafe.Pointer, n int)
