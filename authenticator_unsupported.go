//go:build !darwin && !windows

package bio

func newAuthenticator(opts ...Option) (Authenticator, error) {
	return nil, ErrUnsupportedPlatform
}
