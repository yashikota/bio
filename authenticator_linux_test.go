//go:build linux

package bio

import (
	"context"
	"errors"
	"testing"

	"github.com/yashikota/bio/internal/linux"
	"github.com/yashikota/bio/internal/linux/linuxtest"
)

type linuxEnv struct {
	authn *localAuthenticator
	fake  *linuxtest.FakeFprintd
	store *linux.CredentialStore
}

func newLinuxEnv(t *testing.T, opts ...Option) linuxEnv {
	t.Helper()
	fake := linuxtest.StartFakeFprintd(t)
	tpm := linuxtest.StartSwtpm(t)
	store, err := linux.OpenCredentialStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	a := newLinuxAuthenticator(newConfig(opts), linux.NewFprintdWithAddress(fake.Address), tpm,
		func() (*linux.CredentialStore, error) { return store, nil })
	return linuxEnv{authn: a, fake: fake, store: store}
}

// TestContract_Linux runs the shared contract against the real Linux stack:
// D-Bus client, TPM code (on swtpm) and credential store, with only fprintd faked.
func TestContract_Linux(t *testing.T) {
	runContract(t, func(t *testing.T) contractEnv {
		e := newLinuxEnv(t)
		return contractEnv{
			Authn:       e.authn,
			BlockVerify: e.fake.Block,
			VerifyCalls: e.fake.VerifyStarts,
			SignCounter: true,
		}
	})
}

func TestLinux_NoMatchIsPlatformError(t *testing.T) {
	e := newLinuxEnv(t)
	c := newContractCase(t)
	e.fake.Script(linuxtest.Status{Result: "verify-no-match", Done: true})
	_, err := e.authn.MakeCredential(t.Context(), c.makeOpts(t))
	var pe *PlatformError
	if !errors.As(err, &pe) || pe.Platform != "linux" {
		t.Fatalf("err = %v, want PlatformError", err)
	}
}

func TestLinux_Disconnected(t *testing.T) {
	e := newLinuxEnv(t)
	c := newContractCase(t)
	e.fake.Script(linuxtest.Status{Result: "verify-disconnected", Done: true})
	if _, err := e.authn.MakeCredential(t.Context(), c.makeOpts(t)); !errors.Is(err, ErrNotAvailable) {
		t.Fatalf("err = %v, want ErrNotAvailable", err)
	}
}

func TestLinux_VerifyTimeoutOption(t *testing.T) {
	e := newLinuxEnv(t, WithVerifyTimeout(50e6))
	c := newContractCase(t)
	e.fake.Script()
	if _, err := e.authn.MakeCredential(t.Context(), c.makeOpts(t)); !errors.Is(err, ErrTimeout) {
		t.Fatalf("err = %v, want ErrTimeout", err)
	}
}

func TestLinux_Available(t *testing.T) {
	e := newLinuxEnv(t)
	info, err := e.authn.Available(t.Context())
	if err != nil || !info.Available || !info.Enrolled || info.BiometryType != BiometryFingerprint {
		t.Fatalf("Available = %+v, %v", info, err)
	}
	e.fake.SetEnrolled()
	if info, _ := e.authn.Available(t.Context()); info.Available || info.Enrolled {
		t.Errorf("no fingers enrolled: %+v", info)
	}
}

func TestLinux_PINProtectedKeys(t *testing.T) {
	pin := "2468"
	prompt := func(context.Context) (string, error) { return pin, nil }
	e := newLinuxEnv(t, WithPINPrompt(prompt))
	c := newContractCase(t)
	cred, pub := c.register(t, contractEnv{Authn: e.authn})

	rec, err := e.store.Lookup(c.rp.ID, cred.ID)
	if err != nil || !rec.PINProtected {
		t.Fatalf("record = %+v, %v; want PIN-protected", rec, err)
	}
	opts := c.getOpts(t, cred.ID)
	a, err := e.authn.GetAssertion(t.Context(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.rp.VerifyAssertion(opts.Challenge, a.CredentialID, a.AuthenticatorData, a.Signature, a.UserHandle, a.ClientDataJSON, pub); err != nil {
		t.Fatal(err)
	}

	pin = "0000"
	_, err = e.authn.GetAssertion(t.Context(), c.getOpts(t, cred.ID))
	var pe *PlatformError
	if !errors.As(err, &pe) || pe.Code == 0 {
		t.Fatalf("wrong PIN: err = %v, want PlatformError with a TPM code", err)
	}

	// The same key without a PIN prompt configured is refused before touching the TPM.
	e.authn.verifier.(*fprintdVerifier).pinPrompt = nil
	if _, err := e.authn.GetAssertion(t.Context(), c.getOpts(t, cred.ID)); !errors.Is(err, errPINRequired) {
		t.Fatalf("no prompt: err = %v, want errPINRequired", err)
	}
}

func TestLinux_PINPromptCancel(t *testing.T) {
	e := newLinuxEnv(t, WithPINPrompt(func(context.Context) (string, error) { return "", ErrUserCanceled }))
	c := newContractCase(t)
	if _, err := e.authn.MakeCredential(t.Context(), c.makeOpts(t)); !errors.Is(err, ErrUserCanceled) {
		t.Fatalf("err = %v, want ErrUserCanceled", err)
	}
}

func TestMapLinuxError(t *testing.T) {
	tests := []struct {
		name string
		in   error
		want error
	}{
		{"disconnected", &linux.FprintdError{Op: "Verify", Status: "verify-disconnected"}, ErrNotAvailable},
		{"no device", &linux.FprintdError{Op: "GetDefaultDevice", Status: "net.reactivated.Fprint.Error.NoSuchDevice"}, ErrNotAvailable},
		{"no bus", &linux.FprintdError{Op: "connect", Status: "dial unix: no such file"}, ErrNotAvailable},
		{"no prints", &linux.FprintdError{Op: "Claim", Status: "net.reactivated.Fprint.Error.NoEnrolledPrints"}, ErrNotEnrolled},
	}
	for _, tt := range tests {
		if got := mapLinuxError("Op", tt.in); !errors.Is(got, tt.want) {
			t.Errorf("%s: got %v, want %v", tt.name, got, tt.want)
		}
	}
	var pe *PlatformError
	if err := mapLinuxError("Op", &linux.TPMError{Op: "Sign", Code: 0x98e, Err: errors.New("x")}); !errors.As(err, &pe) || pe.Code != 0x98e {
		t.Errorf("TPM error: %v", err)
	}
	if err := mapLinuxError("Op", &linux.FprintdError{Op: "Verify", Status: "verify-no-match"}); !errors.As(err, &pe) {
		t.Errorf("no match: %v", err)
	}
}
