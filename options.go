package bio

import (
	"context"
	"time"
)

type config struct {
	hwnd            uintptr
	localizedReason string
	verifyTimeout   time.Duration
	namespace       string
	secureEnclave   bool
	pinPrompt       func(ctx context.Context) (string, error)
}

// defaultNamespace keeps credentials created by earlier versions reachable.
const defaultNamespace = "bio"

func defaultConfig() *config {
	return &config{
		verifyTimeout: 30 * time.Second,
		namespace:     defaultNamespace,
	}
}

func newConfig(opts []Option) *config {
	cfg := defaultConfig()
	for _, o := range opts {
		o(cfg)
	}
	return cfg
}

// Option configures an Authenticator.
type Option func(*config)

// WithHWND sets the parent window handle (Windows only).
func WithHWND(hwnd uintptr) Option {
	return func(c *config) { c.hwnd = hwnd }
}

// WithLocalizedReason sets the reason string shown in the biometric prompt
// (macOS only). By default the prompt names the relying party.
func WithLocalizedReason(reason string) Option {
	return func(c *config) { c.localizedReason = reason }
}

// WithVerifyTimeout sets how long to wait for a fingerprint scan (Linux only).
// The per-request Timeout and the context deadline also apply.
func WithVerifyTimeout(d time.Duration) Option {
	return func(c *config) { c.verifyTimeout = d }
}

// WithNamespace separates this application's credentials from those of other
// applications using this library (macOS Keychain tag prefix and Linux
// credential directory). The default is "bio".
func WithNamespace(ns string) Option {
	return func(c *config) {
		if ns != "" {
			c.namespace = ns
		}
	}
}

// WithSecureEnclave creates keys in the Secure Enclave with a biometric
// access-control policy, so that the operating system itself refuses to sign
// without Touch ID (macOS only). This requires a code-signed application with
// the keychain-access-groups entitlement; unsigned binaries get a
// PlatformError. Without this option keys are software keys in the login
// Keychain and biometrics are checked by the library only.
func WithSecureEnclave() Option {
	return func(c *config) { c.secureEnclave = true }
}

// WithPINPrompt protects new TPM keys with a PIN as their TPM authorization
// value (Linux only). prompt is called on every MakeCredential and
// GetAssertion that uses such a key. Unlike the fingerprint check, the PIN is
// enforced by the TPM itself, with its dictionary-attack lockout.
func WithPINPrompt(prompt func(ctx context.Context) (string, error)) Option {
	return func(c *config) { c.pinPrompt = prompt }
}
