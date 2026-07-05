//go:build darwin

package bio

func newAuthenticator(opts ...Option) (Authenticator, error) {
	return nil, ErrUnsupportedPlatform // placeholder until full impl
}
