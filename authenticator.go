package bio

import "context"

// Authenticator provides FIDO2/WebAuthn-level biometric authentication.
type Authenticator interface {
	Available(ctx context.Context) (BiometryInfo, error)
	MakeCredential(ctx context.Context, opts MakeCredentialOptions) (*Credential, error)
	GetAssertion(ctx context.Context, opts GetAssertionOptions) (*Assertion, error)
}

// BiometryType indicates the type of biometric sensor.
type BiometryType int

const (
	BiometryNone    BiometryType = 0
	BiometryTouchID BiometryType = 1
	BiometryFaceID  BiometryType = 2
	BiometryOpticID BiometryType = 4
	BiometryHello   BiometryType = 5 // Windows Hello
)

func (b BiometryType) String() string {
	switch b {
	case BiometryTouchID:
		return "TouchID"
	case BiometryFaceID:
		return "FaceID"
	case BiometryOpticID:
		return "OpticID"
	case BiometryHello:
		return "WindowsHello"
	default:
		return "None"
	}
}

// BiometryInfo describes the biometric capabilities of the platform authenticator.
type BiometryInfo struct {
	Available    bool
	BiometryType BiometryType
	Enrolled     bool
}
