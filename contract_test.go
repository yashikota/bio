package bio

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/yashikota/bio/internal/webauthn"
	"github.com/yashikota/bio/internal/webauthntest"
)

// contractEnv is one Authenticator under test plus the hooks the contract
// needs to drive user verification. Every platform implementation, real or
// faked, must pass runContract; that is what keeps macOS, Windows and Linux
// behaving the same way.
type contractEnv struct {
	Authn Authenticator
	// CancelNextVerify makes the next user verification fail the way the
	// platform reports a user cancel. Nil if the platform has no cancel action.
	CancelNextVerify func()
	// BlockVerify makes user verification wait until its context is done.
	BlockVerify func()
	// VerifyCalls counts user verification prompts.
	VerifyCalls func() int
	// Discoverable is true if GetAssertion accepts an empty AllowCredentials.
	Discoverable bool
	// SignCounter is true if assertions carry an increasing signature counter.
	SignCounter bool
}

type contractCase struct {
	rp   webauthntest.RP
	user User
}

func randBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func newContractCase(t *testing.T) contractCase {
	return contractCase{
		rp:   webauthntest.Default,
		user: User{ID: randBytes(t, 16), Name: "alice@example.com", DisplayName: "Alice"},
	}
}

func (c contractCase) makeOpts(t *testing.T) MakeCredentialOptions {
	ch := randBytes(t, 32)
	return MakeCredentialOptions{
		RP:               RelyingParty{ID: c.rp.ID, Name: "Example"},
		User:             c.user,
		Challenge:        ch,
		ClientDataJSON:   c.rp.ClientData(webauthn.TypeCreate, ch),
		PubKeyCredParams: []CredentialParameter{{Type: "public-key", Algorithm: AlgES256}},
		UserVerification: UVRequired,
	}
}

func (c contractCase) getOpts(t *testing.T, credID []byte) GetAssertionOptions {
	ch := randBytes(t, 32)
	return GetAssertionOptions{
		RPID:             c.rp.ID,
		Challenge:        ch,
		ClientDataJSON:   c.rp.ClientData(webauthn.TypeGet, ch),
		AllowCredentials: []CredentialDescriptor{{Type: "public-key", ID: credID}},
		UserVerification: UVRequired,
	}
}

// register creates a credential, checks it with the oracle and arranges for
// it to be deleted at the end of the test.
func (c contractCase) register(t *testing.T, env contractEnv) (*Credential, []byte) {
	t.Helper()
	opts := c.makeOpts(t)
	cred, err := env.Authn.MakeCredential(t.Context(), opts)
	if err != nil {
		t.Fatalf("MakeCredential: %v", err)
	}
	t.Cleanup(func() { _ = env.Authn.DeleteCredential(context.Background(), c.rp.ID, cred.ID) })
	pub, err := c.rp.VerifyRegistration(opts.Challenge, cred.ID, cred.AttestationObject, cred.ClientDataJSON)
	if err != nil {
		t.Fatalf("relying party rejected registration: %v", err)
	}
	return cred, pub
}

func runContract(t *testing.T, newEnv func(t *testing.T) contractEnv) {
	t.Run("RegisterAndSignIn", func(t *testing.T) {
		env, c := newEnv(t), newContractCase(t)
		cred, pub := c.register(t, env)
		if !bytes.Equal(cred.PublicKey, pub) {
			t.Errorf("Credential.PublicKey does not match the attested key")
		}
		var last uint32
		for i := range 2 {
			opts := c.getOpts(t, cred.ID)
			a, err := env.Authn.GetAssertion(t.Context(), opts)
			if err != nil {
				t.Fatalf("GetAssertion #%d: %v", i, err)
			}
			if !bytes.Equal(a.CredentialID, cred.ID) {
				t.Errorf("CredentialID mismatch")
			}
			if !bytes.Equal(a.UserHandle, c.user.ID) {
				t.Errorf("UserHandle = %x, want %x", a.UserHandle, c.user.ID)
			}
			count, err := c.rp.VerifyAssertion(opts.Challenge, a.CredentialID, a.AuthenticatorData, a.Signature, a.UserHandle, a.ClientDataJSON, pub)
			if err != nil {
				t.Fatalf("relying party rejected assertion #%d: %v", i, err)
			}
			if env.SignCounter && count <= last {
				t.Errorf("sign count %d did not increase from %d", count, last)
			}
			last = count
		}
	})

	t.Run("InvalidRequestsFailBeforePrompt", func(t *testing.T) {
		env, c := newEnv(t), newContractCase(t)
		other := randBytes(t, 32)
		makeCases := map[string]func(*MakeCredentialOptions){
			"empty challenge":        func(o *MakeCredentialOptions) { o.Challenge = nil },
			"empty RP ID":            func(o *MakeCredentialOptions) { o.RP.ID = "" },
			"empty client data":      func(o *MakeCredentialOptions) { o.ClientDataJSON = nil },
			"challenge mismatch":     func(o *MakeCredentialOptions) { o.ClientDataJSON = c.rp.ClientData(webauthn.TypeCreate, other) },
			"wrong client data type": func(o *MakeCredentialOptions) { o.ClientDataJSON = c.rp.ClientData(webauthn.TypeGet, o.Challenge) },
			"bad credential type":    func(o *MakeCredentialOptions) { o.PubKeyCredParams[0].Type = "password" },
		}
		for name, mutate := range makeCases {
			opts := c.makeOpts(t)
			mutate(&opts)
			if _, err := env.Authn.MakeCredential(t.Context(), opts); !errors.Is(err, ErrInvalidParameter) {
				t.Errorf("MakeCredential(%s) = %v, want ErrInvalidParameter", name, err)
			}
		}
		getCases := map[string]func(*GetAssertionOptions){
			"empty challenge":    func(o *GetAssertionOptions) { o.Challenge = nil },
			"empty RP ID":        func(o *GetAssertionOptions) { o.RPID = "" },
			"empty client data":  func(o *GetAssertionOptions) { o.ClientDataJSON = nil },
			"challenge mismatch": func(o *GetAssertionOptions) { o.ClientDataJSON = c.rp.ClientData(webauthn.TypeGet, other) },
		}
		for name, mutate := range getCases {
			opts := c.getOpts(t, []byte("x"))
			mutate(&opts)
			if _, err := env.Authn.GetAssertion(t.Context(), opts); !errors.Is(err, ErrInvalidParameter) {
				t.Errorf("GetAssertion(%s) = %v, want ErrInvalidParameter", name, err)
			}
		}
		if n := env.VerifyCalls(); n != 0 {
			t.Errorf("user was prompted %d times for invalid requests", n)
		}
	})

	t.Run("UnsupportedAlgorithm", func(t *testing.T) {
		env, c := newEnv(t), newContractCase(t)
		opts := c.makeOpts(t)
		opts.PubKeyCredParams = []CredentialParameter{{Type: "public-key", Algorithm: COSEAlgorithm(-65000)}} // no platform supports this
		if _, err := env.Authn.MakeCredential(t.Context(), opts); !errors.Is(err, ErrUnsupportedAlgorithm) {
			t.Errorf("err = %v, want ErrUnsupportedAlgorithm", err)
		}
	})

	t.Run("UserCancel", func(t *testing.T) {
		env, c := newEnv(t), newContractCase(t)
		if env.CancelNextVerify == nil {
			t.Skip("platform has no user cancel")
		}
		env.CancelNextVerify()
		if _, err := env.Authn.MakeCredential(t.Context(), c.makeOpts(t)); !errors.Is(err, ErrUserCanceled) {
			t.Errorf("MakeCredential err = %v, want ErrUserCanceled", err)
		}
		cred, _ := c.register(t, env)
		env.CancelNextVerify()
		if _, err := env.Authn.GetAssertion(t.Context(), c.getOpts(t, cred.ID)); !errors.Is(err, ErrUserCanceled) {
			t.Errorf("GetAssertion err = %v, want ErrUserCanceled", err)
		}
	})

	t.Run("CanceledContext", func(t *testing.T) {
		env, c := newEnv(t), newContractCase(t)
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		_, err := env.Authn.MakeCredential(ctx, c.makeOpts(t))
		if !errors.Is(err, ErrUserCanceled) || !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v, want ErrUserCanceled wrapping context.Canceled", err)
		}
		if n := env.VerifyCalls(); n != 0 {
			t.Errorf("user was prompted %d times with a canceled context", n)
		}
	})

	t.Run("Timeout", func(t *testing.T) {
		env, c := newEnv(t), newContractCase(t)
		env.BlockVerify()
		opts := c.makeOpts(t)
		opts.Timeout = 50 * time.Millisecond
		_, err := env.Authn.MakeCredential(t.Context(), opts)
		if !errors.Is(err, ErrTimeout) || !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("Timeout option: err = %v, want ErrTimeout wrapping DeadlineExceeded", err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
		defer cancel()
		if _, err := env.Authn.MakeCredential(ctx, c.makeOpts(t)); !errors.Is(err, ErrTimeout) {
			t.Errorf("context deadline: err = %v, want ErrTimeout", err)
		}
	})

	t.Run("ExcludeCredentials", func(t *testing.T) {
		env, c := newEnv(t), newContractCase(t)
		cred, _ := c.register(t, env)
		opts := c.makeOpts(t)
		opts.ExcludeCredentials = []CredentialDescriptor{{Type: "public-key", ID: cred.ID}}
		if _, err := env.Authn.MakeCredential(t.Context(), opts); !errors.Is(err, ErrCredentialExcluded) {
			t.Errorf("err = %v, want ErrCredentialExcluded", err)
		}
	})

	t.Run("UnknownCredential", func(t *testing.T) {
		env, c := newEnv(t), newContractCase(t)
		if _, err := env.Authn.GetAssertion(t.Context(), c.getOpts(t, randBytes(t, 32))); !errors.Is(err, ErrNoCredentials) {
			t.Errorf("err = %v, want ErrNoCredentials", err)
		}
		if !env.Discoverable {
			opts := c.getOpts(t, nil)
			opts.AllowCredentials = nil
			if _, err := env.Authn.GetAssertion(t.Context(), opts); !errors.Is(err, ErrNoCredentials) {
				t.Errorf("empty AllowCredentials: err = %v, want ErrNoCredentials", err)
			}
		}
	})

	t.Run("CredentialsAreScopedToRP", func(t *testing.T) {
		env, c := newEnv(t), newContractCase(t)
		cred, _ := c.register(t, env)
		opts := c.getOpts(t, cred.ID)
		other := webauthntest.RP{ID: "other.example", Origin: "https://other.example"}
		opts.RPID = other.ID
		opts.ClientDataJSON = other.ClientData(webauthn.TypeGet, opts.Challenge)
		if _, err := env.Authn.GetAssertion(t.Context(), opts); !errors.Is(err, ErrNoCredentials) {
			t.Errorf("err = %v, want ErrNoCredentials", err)
		}
	})

	t.Run("DeleteCredential", func(t *testing.T) {
		env, c := newEnv(t), newContractCase(t)
		cred, _ := c.register(t, env)
		if err := env.Authn.DeleteCredential(t.Context(), c.rp.ID, cred.ID); err != nil {
			t.Fatalf("DeleteCredential: %v", err)
		}
		if _, err := env.Authn.GetAssertion(t.Context(), c.getOpts(t, cred.ID)); !errors.Is(err, ErrNoCredentials) {
			t.Errorf("GetAssertion after delete: err = %v, want ErrNoCredentials", err)
		}
		if err := env.Authn.DeleteCredential(t.Context(), c.rp.ID, cred.ID); !errors.Is(err, ErrNoCredentials) {
			t.Errorf("second delete: err = %v, want ErrNoCredentials", err)
		}
	})

	t.Run("Available", func(t *testing.T) {
		env := newEnv(t)
		if _, err := env.Authn.Available(t.Context()); err != nil {
			t.Errorf("Available: %v", err)
		}
	})
}
