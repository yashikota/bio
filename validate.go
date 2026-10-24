package bio

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/yashikota/bio/internal/webauthn"
)

const publicKeyType = "public-key"

func invalidParam(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidParameter, fmt.Sprintf(format, args...))
}

// validateMakeCredential checks a request before any user interaction.
func validateMakeCredential(opts *MakeCredentialOptions) error {
	if len(opts.Challenge) == 0 {
		return invalidParam("empty Challenge")
	}
	if opts.RP.ID == "" {
		return invalidParam("empty RP.ID")
	}
	if len(opts.ClientDataJSON) == 0 {
		return invalidParam("empty ClientDataJSON")
	}
	if err := webauthn.CheckClientData(opts.ClientDataJSON, webauthn.TypeCreate, opts.Challenge); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidParameter, err)
	}
	for _, p := range opts.PubKeyCredParams {
		if p.Type != "" && p.Type != publicKeyType {
			return invalidParam("unsupported credential type %q", p.Type)
		}
	}
	return nil
}

// validateGetAssertion checks a request before any user interaction.
func validateGetAssertion(opts *GetAssertionOptions) error {
	if len(opts.Challenge) == 0 {
		return invalidParam("empty Challenge")
	}
	if opts.RPID == "" {
		return invalidParam("empty RPID")
	}
	if len(opts.ClientDataJSON) == 0 {
		return invalidParam("empty ClientDataJSON")
	}
	if err := webauthn.CheckClientData(opts.ClientDataJSON, webauthn.TypeGet, opts.Challenge); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidParameter, err)
	}
	return nil
}

// supportsES256 reports whether params allow an ES256 credential.
// An empty list means the WebAuthn default, which includes ES256.
func supportsES256(params []CredentialParameter) bool {
	return len(params) == 0 || slices.ContainsFunc(params, func(p CredentialParameter) bool {
		return p.Algorithm == AlgES256
	})
}

// contextError maps a context error to the package's sentinel while keeping
// the original in the chain: errors.Is works for both ErrTimeout and
// context.DeadlineExceeded.
func contextError(err error) error {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("%w: %w", ErrTimeout, err)
	case errors.Is(err, context.Canceled):
		return fmt.Errorf("%w: %w", ErrUserCanceled, err)
	default:
		return err
	}
}

// withRequestTimeout applies a per-request timeout on top of ctx.
func withRequestTimeout(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if d > 0 {
		return context.WithTimeout(ctx, d)
	}
	return context.WithCancel(ctx)
}
