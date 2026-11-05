package bio

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func fakeLocalEnv(t *testing.T) contractEnv {
	a, v := newFakeLocal()
	return contractEnv{
		Authn:            a,
		CancelNextVerify: func() { v.next = context.Canceled },
		BlockVerify:      func() { v.block = true },
		VerifyCalls:      v.Calls,
		SignCounter:      true,
	}
}

// TestContract_Fake runs the shared contract against the platform-independent
// flow with fake user verification and software keys, on every OS.
func TestContract_Fake(t *testing.T) {
	runContract(t, fakeLocalEnv)
}

func TestLocal_PromptReason(t *testing.T) {
	c := newContractCase(t)

	a, v := newFakeLocal()
	if _, err := a.MakeCredential(t.Context(), c.makeOpts(t)); err != nil {
		t.Fatal(err)
	}
	if got := v.reasons[0]; got != "Register with Example" {
		t.Errorf("default reason = %q", got)
	}

	a, v = newFakeLocal(WithLocalizedReason("Unlock the vault"))
	if _, err := a.MakeCredential(t.Context(), c.makeOpts(t)); err != nil {
		t.Fatal(err)
	}
	if got := v.reasons[0]; got != "Unlock the vault" {
		t.Errorf("custom reason = %q", got)
	}
}

func TestLocal_PlatformErrorsAreMapped(t *testing.T) {
	c := newContractCase(t)
	a, v := newFakeLocal()
	platformErr := errors.New("sensor exploded")
	a.mapErr = func(op string, err error) error {
		return &PlatformError{Op: op, Platform: "fake", Err: err}
	}
	v.next = platformErr
	_, err := a.MakeCredential(t.Context(), c.makeOpts(t))
	var pe *PlatformError
	if !errors.As(err, &pe) || pe.Op != "MakeCredential" || !errors.Is(err, platformErr) {
		t.Fatalf("err = %v, want PlatformError wrapping the cause", err)
	}
}

func TestLocal_DefaultAlgorithmWhenParamsEmpty(t *testing.T) {
	c := newContractCase(t)
	a, _ := newFakeLocal()
	opts := c.makeOpts(t)
	opts.PubKeyCredParams = nil
	if _, err := a.MakeCredential(t.Context(), opts); err != nil {
		t.Fatalf("empty PubKeyCredParams should default to ES256: %v", err)
	}
}

func TestLocal_ExcludedStillPrompts(t *testing.T) {
	c := newContractCase(t)
	a, v := newFakeLocal()
	cred, _ := c.register(t, contractEnv{Authn: a})
	before := v.Calls()
	opts := c.makeOpts(t)
	opts.ExcludeCredentials = []CredentialDescriptor{{ID: cred.ID}}
	if _, err := a.MakeCredential(t.Context(), opts); !errors.Is(err, ErrCredentialExcluded) {
		t.Fatal(err)
	}
	if v.Calls() != before+1 {
		t.Error("an excluded credential must be reported only after user consent")
	}
}

func TestValidateErrorsAreDescriptive(t *testing.T) {
	c := newContractCase(t)
	opts := c.makeOpts(t)
	opts.RP.ID = ""
	err := validateMakeCredential(&opts)
	if !errors.Is(err, ErrInvalidParameter) || !strings.Contains(err.Error(), "RP.ID") {
		t.Errorf("err = %v", err)
	}
}
