package bio

type config struct {
	hwnd            uintptr
	localizedReason string
}

func defaultConfig() *config {
	return &config{
		localizedReason: "Authenticate using biometrics",
	}
}

// Option configures an Authenticator.
type Option func(*config)

// WithHWND sets the parent window handle (Windows only).
func WithHWND(hwnd uintptr) Option {
	return func(c *config) { c.hwnd = hwnd }
}

// WithLocalizedReason sets the reason string shown in the biometric prompt (macOS only).
func WithLocalizedReason(reason string) Option {
	return func(c *config) { c.localizedReason = reason }
}
