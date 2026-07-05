//go:build darwin

package darwin

import (
	"unsafe"

	"github.com/ebitengine/purego/objc"
)

var (
	classNSString     objc.Class
	selStringWithUTF8 objc.SEL
)

func init() {
	classNSString = objc.GetClass("NSString")
	selStringWithUTF8 = objc.RegisterName("stringWithUTF8String:")
}

// NSStringFromGoString creates an NSString from a Go string.
// The returned ID is autoreleased.
func NSStringFromGoString(s string) objc.ID {
	cstr := append([]byte(s), 0)
	return objc.Send[objc.ID](objc.ID(classNSString), selStringWithUTF8, unsafe.Pointer(&cstr[0]))
}
