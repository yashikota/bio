// Package bio provides CGo-free FIDO2/WebAuthn biometric authentication
// for macOS (Touch ID / Face ID) and Windows (Windows Hello).
package bio

// New returns a platform-specific Authenticator.
// Returns ErrUnsupportedPlatform on unsupported operating systems.
func New(opts ...Option) (Authenticator, error) {
	return newAuthenticator(opts...)
}
