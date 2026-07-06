// Package bio provides CGo-free FIDO2/WebAuthn biometric authentication
// for macOS (Touch ID / Face ID), Windows (Windows Hello), and Linux (fprintd + TPM2).
package bio

// New returns a platform-specific Authenticator.
// Returns ErrUnsupportedPlatform on unsupported operating systems.
func New(opts ...Option) (Authenticator, error) {
	return newAuthenticator(opts...)
}
