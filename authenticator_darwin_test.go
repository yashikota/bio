//go:build darwin

package bio

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"testing"

	"github.com/yashikota/bio/internal/darwin"
)

// TestContract_DarwinKeychain runs the contract against the real Keychain
// code with faked Touch ID. It writes to the login Keychain, so it only runs
// when BIO_KEYCHAIN_TESTS=1 (set in CI). Items use a random namespace and are
// deleted afterwards.
func TestContract_DarwinKeychain(t *testing.T) {
	if os.Getenv("BIO_KEYCHAIN_TESTS") != "1" {
		t.Skip("set BIO_KEYCHAIN_TESTS=1 to run against the login Keychain")
	}
	runContract(t, func(t *testing.T) contractEnv {
		suffix := make([]byte, 8)
		rand.Read(suffix)
		v := &fakeVerifier{}
		keys := &keychainStore{namespace: "bio-test-" + hex.EncodeToString(suffix)}
		a := newDarwinAuthenticator(newConfig(nil), v, keys)
		return contractEnv{
			Authn:            a,
			CancelNextVerify: func() { v.next = darwin.NewLAError("Evaluate", darwin.LAErrorUserCancel) },
			BlockVerify:      func() { v.block = true },
			VerifyCalls:      v.Calls,
		}
	})
}

// TestDarwinAvailable calls the real LocalAuthentication framework. CI
// machines have no biometrics, which must be reported as unavailable, not as an error.
func TestDarwinAvailable(t *testing.T) {
	info, err := darwinAvailable(t.Context())
	if err != nil {
		t.Fatalf("Available: %v", err)
	}
	t.Logf("Available = %+v", info)
}

// TestDarwinEvaluateCancel checks that a canceled context dismisses a pending
// prompt. On a machine without biometrics, evaluation fails immediately instead.
func TestDarwinEvaluateCancel(t *testing.T) {
	la, err := darwin.NewLAContext()
	if err != nil {
		t.Fatal(err)
	}
	defer la.Release()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	err = la.Evaluate(ctx, darwin.LAPolicyDeviceOwnerAuthenticationWithBiometrics, "test")
	var laErr *darwin.LAError
	if !errors.Is(err, context.Canceled) && !errors.As(err, &laErr) {
		t.Fatalf("Evaluate = %v", err)
	}
}

func TestMapDarwinError(t *testing.T) {
	tests := []struct {
		code int64
		want error
	}{
		{darwin.LAErrorUserCancel, ErrUserCanceled},
		{darwin.LAErrorUserFallback, ErrUserCanceled},
		{darwin.LAErrorSystemCancel, ErrUserCanceled},
		{darwin.LAErrorAppCancel, ErrUserCanceled},
		{darwin.LAErrorPasscodeNotSet, ErrNotEnrolled},
		{darwin.LAErrorBiometryNotEnrolled, ErrNotEnrolled},
		{darwin.LAErrorBiometryNotAvailable, ErrNotAvailable},
	}
	for _, tt := range tests {
		if got := mapDarwinError("Op", darwin.NewLAError("x", tt.code)); !errors.Is(got, tt.want) {
			t.Errorf("code %d: got %v, want %v", tt.code, got, tt.want)
		}
	}
	var pe *PlatformError
	for _, code := range []int64{darwin.LAErrorBiometryLockout, darwin.LAErrorAuthenticationFailed, darwin.LAErrorInvalidContext} {
		if err := mapDarwinError("Op", darwin.NewLAError("x", code)); !errors.As(err, &pe) || pe.Code != code {
			t.Errorf("code %d: got %v", code, err)
		}
	}
	if err := mapDarwinError("Op", &darwin.SecError{Op: "SecItemAdd", Status: -34018}); !errors.As(err, &pe) || pe.Code != -34018 {
		t.Errorf("SecError: got %v", err)
	}
}

func TestMapBiometryType(t *testing.T) {
	for in, want := range map[int64]BiometryType{
		darwin.LABiometryTypeNone: BiometryNone, darwin.LABiometryTypeTouchID: BiometryTouchID,
		darwin.LABiometryTypeFaceID: BiometryFaceID, darwin.LABiometryTypeOpticID: BiometryOpticID, 99: BiometryNone,
	} {
		if got := mapBiometryType(in); got != want {
			t.Errorf("mapBiometryType(%d) = %v, want %v", in, got, want)
		}
	}
}
