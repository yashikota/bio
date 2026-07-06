//go:build linux

package bio

import "time"

type config struct {
	verifyTimeout time.Duration
}

func defaultConfig() *config {
	return &config{
		verifyTimeout: 30 * time.Second,
	}
}

// WithVerifyTimeout sets how long to wait for a fingerprint scan (Linux only).
func WithVerifyTimeout(d time.Duration) Option {
	return func(c *config) { c.verifyTimeout = d }
}
