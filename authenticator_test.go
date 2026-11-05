package bio

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestBiometryTypeString(t *testing.T) {
	tests := []struct {
		bt   BiometryType
		want string
	}{
		{BiometryTouchID, "TouchID"},
		{BiometryFaceID, "FaceID"},
		{BiometryOpticID, "OpticID"},
		{BiometryHello, "WindowsHello"},
		{BiometryFingerprint, "Fingerprint"},
		{BiometryNone, "None"},
		{BiometryType(99), "None"},
	}
	for _, tt := range tests {
		if got := tt.bt.String(); got != tt.want {
			t.Errorf("BiometryType(%d).String() = %q, want %q", int(tt.bt), got, tt.want)
		}
	}
}

func TestNewReturnsAuthenticatorOrUnsupported(t *testing.T) {
	a, err := New(WithNamespace("bio-test"), WithLocalizedReason("x"))
	if err != nil {
		if !errors.Is(err, ErrUnsupportedPlatform) {
			t.Fatalf("New: %v", err)
		}
		return
	}
	if a == nil {
		t.Fatal("New returned nil without an error")
	}
}

func TestOptions(t *testing.T) {
	prompt := func(_ context.Context) (string, error) { return "", nil }
	cfg := newConfig([]Option{WithHWND(7), WithLocalizedReason("r"), WithVerifyTimeout(time.Second),
		WithNamespace("app"), WithSecureEnclave(), WithPINPrompt(prompt)})
	if cfg.hwnd != 7 || cfg.localizedReason != "r" || cfg.verifyTimeout != time.Second ||
		cfg.namespace != "app" || !cfg.secureEnclave || cfg.pinPrompt == nil {
		t.Errorf("unexpected config %+v", cfg)
	}
	if newConfig([]Option{WithNamespace("")}).namespace != defaultNamespace {
		t.Error("empty namespace should keep the default")
	}
}
