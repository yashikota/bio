//go:build linux

package linux

import "fmt"

type FprintdError struct {
	Op     string
	Status string
}

func (e *FprintdError) Error() string {
	return fmt.Sprintf("linux fprintd %s: %s", e.Op, e.Status)
}

type TPMError struct {
	Op   string
	Code uint32
	Err  error
}

func (e *TPMError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("linux tpm %s: %v", e.Op, e.Err)
	}
	return fmt.Sprintf("linux tpm %s: code 0x%08x", e.Op, e.Code)
}

func (e *TPMError) Unwrap() error { return e.Err }
