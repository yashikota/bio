//go:build darwin

package darwin

import (
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
)

// C memory (Dlsym symbol addresses, CFData bytes) is read with libc's memcpy
// instead of converting a uintptr to unsafe.Pointer, which go vet flags and
// which is not a valid Go pointer anyway.

var (
	memcpyOnce sync.Once
	memcpyErr  error
	fnMemcpy   func(dst unsafe.Pointer, src uintptr, n uintptr) uintptr
)

func loadMemcpy() error {
	memcpyOnce.Do(func() {
		libc, err := purego.Dlopen("/usr/lib/libSystem.B.dylib", purego.RTLD_NOW|purego.RTLD_GLOBAL)
		if err != nil {
			memcpyErr = err
			return
		}
		purego.RegisterLibFunc(&fnMemcpy, libc, "memcpy")
	})
	return memcpyErr
}

// derefUintptr reads the pointer-sized value stored at the C address addr.
func derefUintptr(addr uintptr) uintptr {
	var v uintptr
	fnMemcpy(unsafe.Pointer(&v), addr, unsafe.Sizeof(v))
	return v
}

// copyBytesFromC copies n bytes of C memory at src into a new Go slice.
func copyBytesFromC(src uintptr, n int) []byte {
	if src == 0 || n <= 0 {
		return nil
	}
	dst := make([]byte, n)
	fnMemcpy(unsafe.Pointer(&dst[0]), src, uintptr(n))
	return dst
}
