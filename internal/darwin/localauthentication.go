//go:build darwin

package darwin

import (
	"context"
	"fmt"
	"sync"
	"time"
	"unsafe"

	"github.com/ebitengine/purego"
	"github.com/ebitengine/purego/objc"
)

var (
	laOnce sync.Once
	laErr  error

	classLAContext             objc.Class
	classNSString              objc.Class
	selAlloc                   objc.SEL
	selInit                    objc.SEL
	selInitWithUTF8            objc.SEL
	selCanEvaluatePolicy       objc.SEL
	selBiometryType            objc.SEL
	selRelease                 objc.SEL
	selCode                    objc.SEL
	selEvaluatePolicyWithReply objc.SEL
	selInvalidate              objc.SEL
)

func loadLA() error {
	laOnce.Do(func() {
		_, laErr = purego.Dlopen(
			"/System/Library/Frameworks/LocalAuthentication.framework/LocalAuthentication",
			purego.RTLD_NOW|purego.RTLD_GLOBAL,
		)
		if laErr != nil {
			return
		}
		classLAContext = objc.GetClass("LAContext")
		classNSString = objc.GetClass("NSString")
		if classLAContext == 0 || classNSString == 0 {
			laErr = fmt.Errorf("darwin: LAContext or NSString class not found")
			return
		}
		selAlloc = objc.RegisterName("alloc")
		selInit = objc.RegisterName("init")
		selInitWithUTF8 = objc.RegisterName("initWithUTF8String:")
		selCanEvaluatePolicy = objc.RegisterName("canEvaluatePolicy:error:")
		selBiometryType = objc.RegisterName("biometryType")
		selRelease = objc.RegisterName("release")
		selCode = objc.RegisterName("code")
		selEvaluatePolicyWithReply = objc.RegisterName("evaluatePolicy:localizedReason:reply:")
		selInvalidate = objc.RegisterName("invalidate")
	})
	return laErr
}

// newNSString returns a retained NSString; the caller must release it. No
// autorelease pool is involved, so nothing leaks on Go-created threads.
func newNSString(s string) objc.ID {
	cstr := append([]byte(s), 0)
	return objc.ID(classNSString).Send(selAlloc).Send(selInitWithUTF8, unsafe.Pointer(&cstr[0]))
}

// LAContext is a retained LocalAuthentication context.
type LAContext struct {
	id objc.ID
}

// NewLAContext allocates an LAContext. Call Release when done.
func NewLAContext() (*LAContext, error) {
	if err := loadLA(); err != nil {
		return nil, err
	}
	return &LAContext{id: objc.ID(classLAContext).Send(selAlloc).Send(selInit)}, nil
}

// ID returns the Objective-C object, for kSecUseAuthenticationContext.
func (c *LAContext) ID() objc.ID { return c.id }

// Release releases the context.
func (c *LAContext) Release() {
	if c.id != 0 {
		c.id.Send(selRelease)
		c.id = 0
	}
}

// replyGrace bounds how long Evaluate waits for the reply after invalidating
// a canceled evaluation.
const replyGrace = 5 * time.Second

// Evaluate shows the biometric prompt and blocks until the user responds or
// ctx is done. On cancellation the prompt is dismissed with -[LAContext
// invalidate] and ctx.Err() is returned.
func (c *LAContext) Evaluate(ctx context.Context, policy int64, reason string) error {
	type result struct {
		success bool
		code    int64
	}
	ch := make(chan result, 1)
	block := objc.NewBlock(func(_ objc.Block, success bool, errPtr uintptr) {
		var code int64
		if !success && errPtr != 0 {
			code = objc.Send[int64](objc.ID(errPtr), selCode)
		}
		ch <- result{success: success, code: code}
	})

	nsReason := newNSString(reason)
	defer nsReason.Send(selRelease)
	c.id.Send(selEvaluatePolicyWithReply, policy, nsReason, block)

	select {
	case res := <-ch:
		block.Release()
		if !res.success {
			return NewLAError("Evaluate", res.code)
		}
		return nil
	case <-ctx.Done():
		c.id.Send(selInvalidate)
		select {
		case <-ch:
			block.Release()
		case <-time.After(replyGrace):
			// The reply never came; leak the block rather than free it under the framework.
		}
		return ctx.Err()
	}
}

// CheckAvailability calls -[LAContext canEvaluatePolicy:error:] and returns the biometry type.
func CheckAvailability(policy int64) (canEval bool, biometryType int64, err error) {
	c, err := NewLAContext()
	if err != nil {
		return false, 0, err
	}
	defer c.Release()

	var nsErr uintptr
	canEval = objc.Send[bool](c.id, selCanEvaluatePolicy, policy, &nsErr)
	biometryType = objc.Send[int64](c.id, selBiometryType)
	if !canEval && nsErr != 0 {
		code := objc.Send[int64](objc.ID(nsErr), selCode)
		return false, biometryType, NewLAError("CheckAvailability", code)
	}
	return canEval, biometryType, nil
}
