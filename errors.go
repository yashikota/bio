package bio

import (
	"errors"
	"fmt"
)

var (
	ErrUnsupportedPlatform = errors.New("bio: platform not supported")
	ErrNotAvailable        = errors.New("bio: biometric authentication not available")
	ErrNotEnrolled         = errors.New("bio: no biometric data enrolled")
	ErrUserCanceled        = errors.New("bio: user canceled")
	ErrTimeout             = errors.New("bio: operation timed out")
	ErrCredentialExcluded  = errors.New("bio: credential already exists")
	ErrNoCredentials       = errors.New("bio: no matching credentials")
	ErrInvalidParameter    = errors.New("bio: invalid parameter")
	// ErrUnsupportedAlgorithm is returned when none of the requested
	// PubKeyCredParams can be created by the platform authenticator.
	ErrUnsupportedAlgorithm = errors.New("bio: no supported algorithm requested")
)

// PlatformError wraps a platform-specific error.
type PlatformError struct {
	Op       string
	Platform string
	Code     int64
	Err      error
}

func (e *PlatformError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("bio: %s [%s code=%d]: %v", e.Op, e.Platform, e.Code, e.Err)
	}
	return fmt.Sprintf("bio: %s [%s code=%d]", e.Op, e.Platform, e.Code)
}

func (e *PlatformError) Unwrap() error { return e.Err }

var sentinels = []error{
	ErrUnsupportedPlatform, ErrNotAvailable, ErrNotEnrolled, ErrUserCanceled, ErrTimeout,
	ErrCredentialExcluded, ErrNoCredentials, ErrInvalidParameter, ErrUnsupportedAlgorithm,
}

// isSentinel reports whether err already is (or wraps) one of the package's errors.
func isSentinel(err error) bool {
	for _, s := range sentinels {
		if errors.Is(err, s) {
			return true
		}
	}
	return false
}
