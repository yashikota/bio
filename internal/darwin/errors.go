//go:build darwin

package darwin

import (
	"errors"
	"fmt"
)

// LAError is a LocalAuthentication error with its LAError code.
type LAError struct {
	Op   string
	Code int64
}

func (e *LAError) Error() string {
	return fmt.Sprintf("darwin LAError: op=%s code=%d", e.Op, e.Code)
}

// NewLAError wraps an LAError code as a typed error.
func NewLAError(op string, code int64) error {
	return &LAError{Op: op, Code: code}
}

// SecError is a Security framework failure: an OSStatus, or a CFError's code and description.
type SecError struct {
	Op     string
	Status int64
	Desc   string
}

func (e *SecError) Error() string {
	if e.Desc != "" {
		return fmt.Sprintf("darwin %s: status=%d %s", e.Op, e.Status, e.Desc)
	}
	return fmt.Sprintf("darwin %s: status=%d", e.Op, e.Status)
}

// MissingEntitlement reports whether the operation needs a code-signed app
// with the keychain-access-groups entitlement (errSecMissingEntitlement).
func (e *SecError) MissingEntitlement() bool { return e.Status == errSecMissingEntitlement }

// ErrNotFound is returned when no Keychain item matches.
var ErrNotFound = errors.New("darwin: keychain item not found")
