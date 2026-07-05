//go:build !darwin && !windows

package bio

import (
	"errors"
	"testing"
)

func TestNew_UnsupportedPlatform(t *testing.T) {
	_, err := New()
	if err == nil {
		t.Fatal("expected error on unsupported platform, got nil")
	}
	if !errors.Is(err, ErrUnsupportedPlatform) {
		t.Errorf("err = %v, want ErrUnsupportedPlatform", err)
	}
}
