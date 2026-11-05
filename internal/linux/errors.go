//go:build linux

package linux

import (
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2"
)

// FprintdError is a failure reported by fprintd or the D-Bus connection to it.
type FprintdError struct {
	Op     string
	Status string
}

func (e *FprintdError) Error() string {
	return fmt.Sprintf("linux fprintd %s: %s", e.Op, e.Status)
}

// TPMError is a failure talking to the TPM.
type TPMError struct {
	Op string
	// Code is the TPM response code (TPM_RC), or 0 if the failure did not come from the TPM.
	Code uint32
	Err  error
}

func newTPMError(op string, err error) *TPMError {
	e := &TPMError{Op: op, Err: err}
	var rc tpm2.TPMRC
	if errors.As(err, &rc) {
		e.Code = uint32(rc)
	}
	return e
}

func (e *TPMError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("linux tpm %s: %v", e.Op, e.Err)
	}
	return fmt.Sprintf("linux tpm %s: code 0x%08x", e.Op, e.Code)
}

func (e *TPMError) Unwrap() error { return e.Err }

// IsAuthFailure reports whether the TPM rejected the key's authorization value (a wrong PIN).
func (e *TPMError) IsAuthFailure() bool {
	return errors.Is(e.Err, tpm2.TPMRCAuthFail) || errors.Is(e.Err, tpm2.TPMRCBadAuth)
}

// IsLockout reports whether the TPM's dictionary-attack protection is active.
func (e *TPMError) IsLockout() bool {
	return errors.Is(e.Err, tpm2.TPMRCLockout)
}
