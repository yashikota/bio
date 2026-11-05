//go:build linux

package linux_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yashikota/bio/internal/linux"
	"github.com/yashikota/bio/internal/linux/linuxtest"
)

func openFake(t *testing.T) (*linuxtest.FakeFprintd, *linux.FprintdClient) {
	t.Helper()
	fake := linuxtest.StartFakeFprintd(t)
	c, err := linux.NewFprintdWithAddress(fake.Address).Open()
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return fake, c
}

func TestFprintdVerify(t *testing.T) {
	tests := []struct {
		name       string
		script     []linuxtest.Status
		wantStatus string // "" means success
	}{
		{"match after retry", linuxtest.Match, ""},
		{"transient errors then match", []linuxtest.Status{
			{Result: "verify-swipe-too-short", Done: false}, {Result: "verify-finger-not-centered", Done: false},
			{Result: "verify-no-match", Done: false}, {Result: "verify-match", Done: true},
		}, ""},
		{"no match", []linuxtest.Status{{Result: "verify-no-match", Done: true}}, "verify-no-match"},
		{"disconnected", []linuxtest.Status{{Result: "verify-disconnected", Done: true}}, "verify-disconnected"},
		{"unknown failure", []linuxtest.Status{{Result: "verify-unknown-error", Done: true}}, "verify-unknown-error"},
	}
	fake, c := openFake(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake.Script(tt.script...)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			err := c.Verify(ctx)
			if tt.wantStatus == "" {
				if err != nil {
					t.Fatalf("Verify: %v", err)
				}
			} else {
				var fe *linux.FprintdError
				if !errors.As(err, &fe) || fe.Status != tt.wantStatus {
					t.Fatalf("Verify = %v, want status %q", err, tt.wantStatus)
				}
			}
			if fake.Claimed() {
				t.Error("device left claimed after Verify")
			}
		})
	}
}

func TestFprintdVerifyHonorsContext(t *testing.T) {
	fake, c := openFake(t)
	fake.Script() // no signals at all
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	if err := c.Verify(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Verify = %v, want DeadlineExceeded", err)
	}
	if fake.Claimed() {
		t.Error("device left claimed after timeout")
	}
}

func TestFprintdClaimFailure(t *testing.T) {
	fake, c := openFake(t)
	fake.FailClaim("AlreadyInUse")
	var fe *linux.FprintdError
	if err := c.Verify(t.Context()); !errors.As(err, &fe) || fe.Op != "Claim" {
		t.Fatalf("Verify = %v, want Claim error", err)
	}
	if fake.VerifyStarts() != 0 {
		t.Error("VerifyStart called after Claim failed")
	}
}

func TestFprintdEnrolled(t *testing.T) {
	fake, c := openFake(t)
	if ok, err := c.HasEnrolledFingerprints(); !ok || err != nil {
		t.Errorf("HasEnrolledFingerprints = %v, %v", ok, err)
	}
	fake.SetEnrolled()
	if ok, err := c.HasEnrolledFingerprints(); ok || err != nil {
		t.Errorf("no fingers: HasEnrolledFingerprints = %v, %v", ok, err)
	}
}

func TestFprintdUnreachable(t *testing.T) {
	_, err := linux.NewFprintdWithAddress("unix:path=/nonexistent/bus").Open()
	var fe *linux.FprintdError
	if !errors.As(err, &fe) || fe.Op != "connect" {
		t.Fatalf("Open = %v, want connect error", err)
	}
}
