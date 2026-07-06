package bio

import "time"

type config struct {
	hwnd            uintptr
	localizedReason string
	verifyTimeout   time.Duration
}

func defaultConfig() *config {
	return &config{
		localizedReason: "Authenticate using biometrics",
		verifyTimeout:   30 * time.Second,
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

// WithVerifyTimeout sets how long to wait for a fingerprint scan (Linux only).
func WithVerifyTimeout(d time.Duration) Option {
	return func(c *config) { c.verifyTimeout = d }
}
