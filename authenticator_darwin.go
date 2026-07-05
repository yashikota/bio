//go:build darwin

package bio

import (
	"context"
	"errors"
	"fmt"

	"github.com/yashikota/bio/internal/darwin"
)

type darwinAuthenticator struct {
	cfg *config
}

func newAuthenticator(opts ...Option) (Authenticator, error) {
	cfg := defaultConfig()
	for _, o := range opts {
		o(cfg)
	}
	return &darwinAuthenticator{cfg: cfg}, nil
}

func (a *darwinAuthenticator) Available(_ context.Context) (BiometryInfo, error) {
	canEval, biometryType, err := darwin.CheckAvailability(darwin.LAPolicyDeviceOwnerAuthenticationWithBiometrics)
	if err != nil {
		return BiometryInfo{}, mapLAError("Available", err)
	}
	return BiometryInfo{
		Available:    canEval,
		BiometryType: mapBiometryType(biometryType),
		Enrolled:     biometryType != darwin.LABiometryTypeNone,
	}, nil
}

// mapLAError converts a darwin.LAError into the appropriate bio package error.
func mapLAError(op string, err error) error {
	if err == nil {
		return nil
	}
	var laErr *darwin.LAError
	if !errors.As(err, &laErr) {
		return err
	}
	switch laErr.Code {
	case darwin.LAErrorUserCancel, darwin.LAErrorUserFallback, darwin.LAErrorSystemCancel, darwin.LAErrorAppCancel:
		return ErrUserCanceled
	case darwin.LAErrorPasscodeNotSet, darwin.LAErrorBiometryNotEnrolled:
		return ErrNotEnrolled
	case darwin.LAErrorBiometryNotAvailable:
		return ErrNotAvailable
	case darwin.LAErrorBiometryLockout:
		return &PlatformError{Op: op, Platform: "darwin", Code: laErr.Code,
			Err: fmt.Errorf("biometry locked out")}
	case darwin.LAErrorAuthenticationFailed:
		return &PlatformError{Op: op, Platform: "darwin", Code: laErr.Code,
			Err: fmt.Errorf("authentication failed")}
	default:
		return &PlatformError{Op: op, Platform: "darwin", Code: laErr.Code,
			Err: fmt.Errorf("platform error")}
	}
}

func mapBiometryType(t int64) BiometryType {
	switch t {
	case darwin.LABiometryTypeTouchID:
		return BiometryTouchID
	case darwin.LABiometryTypeFaceID:
		return BiometryFaceID
	case darwin.LABiometryTypeOpticID:
		return BiometryOpticID
	default:
		return BiometryNone
	}
}

func (a *darwinAuthenticator) MakeCredential(_ context.Context, _ MakeCredentialOptions) (*Credential, error) {
	return nil, errors.New("bio: MakeCredential not yet implemented on darwin")
}

func (a *darwinAuthenticator) GetAssertion(_ context.Context, _ GetAssertionOptions) (*Assertion, error) {
	return nil, errors.New("bio: GetAssertion not yet implemented on darwin")
}
