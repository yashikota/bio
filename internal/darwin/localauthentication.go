//go:build darwin

package darwin

import (
	"fmt"
	"sync"

	"github.com/ebitengine/purego"
	"github.com/ebitengine/purego/objc"
)


var (
	laOnce  sync.Once
	laErr   error

	classLAContext            objc.Class
	selAlloc                  objc.SEL
	selInit                   objc.SEL
	selCanEvaluatePolicy      objc.SEL
	selBiometryType           objc.SEL
	selRelease                objc.SEL
	selCode                   objc.SEL
	selEvaluatePolicyWithReply objc.SEL
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
		if classLAContext == 0 {
			laErr = fmt.Errorf("darwin: LAContext class not found")
			return
		}
		selAlloc = objc.RegisterName("alloc")
		selInit = objc.RegisterName("init")
		selCanEvaluatePolicy = objc.RegisterName("canEvaluatePolicy:error:")
		selBiometryType = objc.RegisterName("biometryType")
		selRelease = objc.RegisterName("release")
		selCode = objc.RegisterName("code")
		selEvaluatePolicyWithReply = objc.RegisterName("evaluatePolicy:localizedReason:reply:")
	})
}

// Authenticate calls LAContext evaluatePolicy:localizedReason:reply: and blocks until
// the biometric prompt completes or fails. Returns a LAError on denial/cancel.
func Authenticate(policy int64, reason string) error {
	loadLA()
	if laErr != nil {
		return laErr
	}

	ctx := objc.ID(classLAContext).Send(selAlloc).Send(selInit)
	defer ctx.Send(selRelease)

	type result struct {
		success bool
		errCode int64
	}
	ch := make(chan result, 1)

	block := objc.NewBlock(func(_ objc.Block, success bool, errPtr uintptr) {
		var code int64
		if !success && errPtr != 0 {
			code = objc.Send[int64](objc.ID(errPtr), selCode)
		}
		ch <- result{success: success, errCode: code}
	})

	nsReason := NSStringFromGoString(reason)
	ctx.Send(selEvaluatePolicyWithReply, policy, nsReason, block)

	res := <-ch
	if !res.success {
		return NewLAError("Authenticate", res.errCode)
	}
	return nil
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

	if !canEval && nsErrPtr != 0 {
		code := objc.Send[int64](objc.ID(nsErrPtr), selCode)
		return false, biometryType, NewLAError("CheckAvailability", code)
	}
	return canEval, biometryType, nil
}
