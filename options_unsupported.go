//go:build !darwin && !windows && !linux

package bio

type config struct{}

func defaultConfig() *config { return &config{} }
