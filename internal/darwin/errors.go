//go:build darwin

package darwin

import "fmt"

// LAError is a local authentication error with the LAError code.
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
