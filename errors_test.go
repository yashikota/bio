package bio

import (
	"context"
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

func TestSentinelErrorsAreDistinct(t *testing.T) {
	for i, a := range sentinels {
		if !strings.HasPrefix(a.Error(), "bio: ") {
			t.Errorf("%q lacks the bio: prefix", a)
		}
		for _, b := range sentinels[i+1:] {
			if errors.Is(a, b) || errors.Is(b, a) {
				t.Errorf("%v and %v are not distinct", a, b)
			}
		}
	}
}

func TestContextError(t *testing.T) {
	if err := contextError(context.DeadlineExceeded); !errors.Is(err, ErrTimeout) || !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("deadline: %v", err)
	}
	if err := contextError(context.Canceled); !errors.Is(err, ErrUserCanceled) || !errors.Is(err, context.Canceled) {
		t.Errorf("canceled: %v", err)
	}
	other := errors.New("other")
	if !errors.Is(contextError(other), other) {
		t.Error("other errors must pass through")
	}
}
