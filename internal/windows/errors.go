//go:build windows

package winwebauthn

import "fmt"

// WinError represents a Windows webauthn error with a semantic Kind.
type WinError struct {
	Op   string
	Kind WinErrorKind
	HR   uint32
}

func (e *WinError) Error() string {
	if e.Kind == WinErrPlatform {
		return fmt.Sprintf("webauthn: %s: HRESULT 0x%08X", e.Op, e.HR)
	}
	return fmt.Sprintf("webauthn: %s: %s (HRESULT 0x%08X)", e.Op, e.Kind, e.HR)
}

// WinErrorKind classifies the error for easy mapping in the parent package.
type WinErrorKind int

const (
	WinErrPlatform      WinErrorKind = 0
	WinErrUserCanceled  WinErrorKind = 1
	WinErrTimeout       WinErrorKind = 2
	WinErrInvalidParam  WinErrorKind = 3
	WinErrNoCredentials WinErrorKind = 4
	WinErrExists        WinErrorKind = 5
	WinErrNotSupported  WinErrorKind = 6
)

func (k WinErrorKind) String() string {
	switch k {
	case WinErrUserCanceled:
		return "user canceled"
	case WinErrTimeout:
		return "timeout"
	case WinErrInvalidParam:
		return "invalid parameter"
	case WinErrNoCredentials:
		return "no credentials"
	case WinErrExists:
		return "credential exists"
	case WinErrNotSupported:
		return "not supported"
	default:
		return "platform error"
	}
}

// HRESULTToError maps a Windows HRESULT to a WinError. Returns nil for S_OK.
// The mapping follows what browsers do with webauthn.dll results.
func HRESULTToError(op string, hr uintptr) error {
	kind := WinErrPlatform
	switch int32(hr) {
	case S_OK:
		return nil
	case ERROR_CANCELLED, NTE_USER_CANCELLED:
		kind = WinErrUserCanceled
	case ERROR_TIMEOUT_WIN:
		kind = WinErrTimeout
	case NTE_INVALID_PARAMETER, E_INVALIDARG:
		kind = WinErrInvalidParam
	case ERROR_NOT_FOUND, NTE_NOT_FOUND:
		kind = WinErrNoCredentials
	case NTE_EXISTS:
		kind = WinErrExists
	case NTE_NOT_SUPPORTED:
		kind = WinErrNotSupported
	}
	return &WinError{Op: op, Kind: kind, HR: uint32(hr)}
}

// toHR converts a signed HRESULT constant to its unsigned form.
func toHR(hr int32) uint32 { return uint32(hr) }
