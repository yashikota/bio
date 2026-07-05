//go:build darwin

package darwin

import (
	"sync"

	"github.com/ebitengine/purego"
	"github.com/ebitengine/purego/objc"
)

var (
	laOnce  sync.Once
	laErr   error

	classLAContext       objc.Class
	selAlloc             objc.SEL
	selInit              objc.SEL
	selCanEvaluatePolicy objc.SEL
	selBiometryType      objc.SEL
	selRelease           objc.SEL
)

func loadLA() {
	laOnce.Do(func() {
		_, laErr = purego.Dlopen(
			"/System/Library/Frameworks/LocalAuthentication.framework/LocalAuthentication",
			purego.RTLD_NOW|purego.RTLD_GLOBAL,
		)
		if laErr != nil {
			return
		}
		classLAContext = objc.GetClass("LAContext")
		selAlloc = objc.RegisterName("alloc")
		selInit = objc.RegisterName("init")
		selCanEvaluatePolicy = objc.RegisterName("canEvaluatePolicy:error:")
		selBiometryType = objc.RegisterName("biometryType")
		selRelease = objc.RegisterName("release")
	})
}

// CheckAvailability calls LAContext canEvaluatePolicy:error: and returns biometryType.
func CheckAvailability(policy int64) (canEval bool, biometryType int64, err error) {
	loadLA()
	if laErr != nil {
		return false, 0, laErr
	}

	ctx := objc.ID(classLAContext).Send(selAlloc).Send(selInit)
	defer ctx.Send(selRelease)

	var nsErrPtr uintptr
	canEval = objc.Send[bool](ctx, selCanEvaluatePolicy, policy, &nsErrPtr)

	biometryType = objc.Send[int64](ctx, selBiometryType)
	return canEval, biometryType, nil
}
