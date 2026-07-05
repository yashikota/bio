package bio

import (
	"errors"
	"strings"
	"testing"
)

func TestPlatformError_Error(t *testing.T) {
	t.Run("with underlying error", func(t *testing.T) {
		e := &PlatformError{Op: "MakeCredential", Platform: "darwin", Code: -6, Err: ErrNotAvailable}
		got := e.Error()
		if !strings.Contains(got, "MakeCredential") {
			t.Errorf("Error() missing op: %q", got)
		}
		if !strings.Contains(got, "darwin") {
			t.Errorf("Error() missing platform: %q", got)
		}
		if !strings.Contains(got, "-6") {
			t.Errorf("Error() missing code: %q", got)
		}
	})

	t.Run("nil underlying error does not print <nil>", func(t *testing.T) {
		e := &PlatformError{Op: "GetAssertion", Platform: "windows", Code: -2147023673, Err: nil}
		got := e.Error()
		if strings.Contains(got, "<nil>") {
			t.Errorf("Error() should not print <nil>: %q", got)
		}
	})

	t.Run("Unwrap returns inner error", func(t *testing.T) {
		inner := errors.New("inner")
		e := &PlatformError{Err: inner}
		if !errors.Is(e, inner) {
			t.Error("errors.Is should find inner error via Unwrap")
		}
	})
}

func TestSentinelErrors(t *testing.T) {
	sentinels := []error{
		ErrUnsupportedPlatform,
		ErrNotAvailable,
		ErrNotEnrolled,
		ErrUserCanceled,
		ErrTimeout,
		ErrCredentialExcluded,
		ErrNoCredentials,
		ErrInvalidParameter,
	}
	for _, err := range sentinels {
		if err == nil {
			t.Errorf("sentinel error should not be nil")
		}
		if err.Error() == "" {
			t.Errorf("sentinel error message should not be empty")
		}
	}
}
