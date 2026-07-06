//go:build !darwin && !windows && !linux

package bio

func newAuthenticator(opts ...Option) (Authenticator, error) {
	return nil, ErrUnsupportedPlatform
}
