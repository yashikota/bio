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
	WinErrPlatform        WinErrorKind = 0
	WinErrUserCanceled    WinErrorKind = 1
	WinErrTimeout         WinErrorKind = 2
	WinErrInvalidParam    WinErrorKind = 3
	WinErrNoCredentials   WinErrorKind = 4
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
	default:
		return "platform error"
	}
}

// HRESULTToError maps a Windows HRESULT to a WinError.
// Returns nil for S_OK.
func HRESULTToError(op string, hr uintptr) error {
	switch int32(hr) {
	case S_OK:
		return nil
	case ERROR_CANCELLED:
		return &WinError{Op: op, Kind: WinErrUserCanceled, HR: uint32(hr)}
	case ERROR_TIMEOUT_WIN:
		return &WinError{Op: op, Kind: WinErrTimeout, HR: uint32(hr)}
	case NTE_INVALID_PARAMETER:
		return &WinError{Op: op, Kind: WinErrInvalidParam, HR: uint32(hr)}
	case ERROR_NOT_FOUND:
		return &WinError{Op: op, Kind: WinErrNoCredentials, HR: uint32(hr)}
	default:
		return &WinError{Op: op, Kind: WinErrPlatform, HR: uint32(hr)}
	}
}
