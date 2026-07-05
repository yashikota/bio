//go:build darwin

package darwin

import (
	"sync"
	"unsafe"

	"github.com/ebitengine/purego/objc"
)

var (
	nsStringOnce      sync.Once
	classNSString     objc.Class
	selStringWithUTF8 objc.SEL
)

// NSStringFromGoString creates an NSString from a Go string.
// The returned ID is autoreleased.
func NSStringFromGoString(s string) objc.ID {
	nsStringOnce.Do(func() {
		classNSString = objc.GetClass("NSString")
		selStringWithUTF8 = objc.RegisterName("stringWithUTF8String:")
	})
	cstr := append([]byte(s), 0)
	return objc.Send[objc.ID](objc.ID(classNSString), selStringWithUTF8, unsafe.Pointer(&cstr[0]))
}
