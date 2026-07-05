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
