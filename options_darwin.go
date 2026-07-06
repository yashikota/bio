//go:build darwin

package bio

type config struct {
	localizedReason string
}

func defaultConfig() *config {
	return &config{
		localizedReason: "Authenticate using biometrics",
	}
}

// WithLocalizedReason sets the reason string shown in the biometric prompt (macOS only).
func WithLocalizedReason(reason string) Option {
	return func(c *config) { c.localizedReason = reason }
}
