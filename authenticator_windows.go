//go:build windows

package bio

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/yashikota/bio/internal/webauthn"
	winwebauthn "github.com/yashikota/bio/internal/windows"
)

// winAPI is the slice of webauthn.dll the authenticator uses; tests replace it.
type winAPI struct {
	isAvailable      func() (bool, error)
	makeCredential   func(context.Context, *winwebauthn.MakeCredentialParams) (*winwebauthn.MakeCredentialResult, error)
	getAssertion     func(context.Context, *winwebauthn.GetAssertionParams) (*winwebauthn.GetAssertionResult, error)
	deleteCredential func([]byte) error
	resolveHWND      func(uintptr) uintptr
}

var systemWinAPI = winAPI{
	isAvailable:      winwebauthn.IsAvailable,
	makeCredential:   winwebauthn.MakeCredential,
	getAssertion:     winwebauthn.GetAssertion,
	deleteCredential: winwebauthn.DeletePlatformCredential,
	resolveHWND:      winwebauthn.ResolveHWND,
}

type windowsAuthenticator struct {
	cfg *config
	api winAPI
}

func newAuthenticator(opts ...Option) (Authenticator, error) {
	return &windowsAuthenticator{cfg: newConfig(opts), api: systemWinAPI}, nil
}

func (a *windowsAuthenticator) Available(_ context.Context) (BiometryInfo, error) {
	ok, err := a.api.isAvailable()
	if err != nil {
		return BiometryInfo{}, mapWinError(err)
	}
	info := BiometryInfo{Available: ok, Enrolled: ok}
	if ok {
		info.BiometryType = BiometryHello
	}
	return info, nil
}

// mapWinError converts webauthn.dll errors into the package's errors.
func mapWinError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return contextError(err)
	}
	we, ok := errors.AsType[*winwebauthn.WinError](err)
	if !ok {
		return &PlatformError{Op: "webauthn", Platform: "windows", Err: err}
	}
	switch we.Kind {
	case winwebauthn.WinErrUserCanceled:
		return ErrUserCanceled
	case winwebauthn.WinErrTimeout:
		return ErrTimeout
	case winwebauthn.WinErrInvalidParam:
		return ErrInvalidParameter
	case winwebauthn.WinErrNoCredentials:
		return ErrNoCredentials
	case winwebauthn.WinErrExists:
		return ErrCredentialExcluded
	case winwebauthn.WinErrNotSupported:
		if we.Op == "MakeCredential" {
			return ErrUnsupportedAlgorithm
		}
	}
	return &PlatformError{Op: we.Op, Platform: "windows", Code: int64(we.HR), Err: we}
}

func uvRequirement(uv UserVerification) uint32 {
	switch uv {
	case UVRequired:
		return winwebauthn.WebAuthnUserVerificationRequirementRequired
	case UVDiscouraged:
		return winwebauthn.WebAuthnUserVerificationRequirementDiscouraged
	default:
		return winwebauthn.WebAuthnUserVerificationRequirementPreferred
	}
}

func attestationPref(a AttestationConveyance) uint32 {
	switch a {
	case AttestationDirect:
		return winwebauthn.WebAuthnAttestationConveyancePreferenceDirect
	case AttestationIndirect:
		return winwebauthn.WebAuthnAttestationConveyancePreferenceIndirect
	default:
		return winwebauthn.WebAuthnAttestationConveyancePreferenceNone
	}
}

// timeoutMS converts a timeout for the DLL, clamping instead of overflowing.
func timeoutMS(d time.Duration) uint32 {
	switch {
	case d <= 0:
		return 60000
	case d/time.Millisecond >= math.MaxUint32:
		return math.MaxUint32
	default:
		return max(uint32(d/time.Millisecond), 1)
	}
}

func descriptorIDs(ds []CredentialDescriptor) [][]byte {
	ids := make([][]byte, 0, len(ds))
	for _, d := range ds {
		ids = append(ids, d.ID)
	}
	return ids
}

func (a *windowsAuthenticator) MakeCredential(ctx context.Context, opts MakeCredentialOptions) (*Credential, error) {
	if err := validateMakeCredential(&opts); err != nil {
		return nil, err
	}
	ctx, cancel := withRequestTimeout(ctx, opts.Timeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, contextError(err)
	}

	algs := make([]int32, 0, len(opts.PubKeyCredParams))
	for _, p := range opts.PubKeyCredParams {
		algs = append(algs, int32(p.Algorithm))
	}
	if len(algs) == 0 {
		algs = []int32{int32(AlgES256), int32(AlgRS256)} // the WebAuthn default
	}

	res, err := a.api.makeCredential(ctx, &winwebauthn.MakeCredentialParams{
		HWND:             a.api.resolveHWND(a.cfg.hwnd),
		RPID:             opts.RP.ID,
		RPName:           opts.RP.Name,
		UserID:           opts.User.ID,
		UserName:         opts.User.Name,
		UserDisplayName:  opts.User.DisplayName,
		ClientDataJSON:   opts.ClientDataJSON,
		Algorithms:       algs,
		UserVerification: uvRequirement(opts.UserVerification),
		AttestationPref:  attestationPref(opts.Attestation),
		TimeoutMS:        timeoutMS(opts.Timeout),
		ExcludeIDs:       descriptorIDs(opts.ExcludeCredentials),
	})
	if err != nil {
		return nil, mapWinError(err)
	}
	pub, err := webauthn.PublicKeyFromAuthData(res.AuthenticatorData)
	if err != nil {
		return nil, &PlatformError{Op: "MakeCredential", Platform: "windows", Err: err}
	}
	return &Credential{
		ID:                res.CredentialID,
		PublicKey:         pub,
		AttestationObject: res.AttestationObject,
		ClientDataJSON:    opts.ClientDataJSON,
		AuthenticatorData: res.AuthenticatorData,
		Transport:         []string{"internal"},
	}, nil
}

func (a *windowsAuthenticator) GetAssertion(ctx context.Context, opts GetAssertionOptions) (*Assertion, error) {
	if err := validateGetAssertion(&opts); err != nil {
		return nil, err
	}
	ctx, cancel := withRequestTimeout(ctx, opts.Timeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, contextError(err)
	}
	res, err := a.api.getAssertion(ctx, &winwebauthn.GetAssertionParams{
		HWND:             a.api.resolveHWND(a.cfg.hwnd),
		RPID:             opts.RPID,
		ClientDataJSON:   opts.ClientDataJSON,
		AllowIDs:         descriptorIDs(opts.AllowCredentials),
		UserVerification: uvRequirement(opts.UserVerification),
		TimeoutMS:        timeoutMS(opts.Timeout),
	})
	if err != nil {
		return nil, mapWinError(err)
	}
	return &Assertion{
		CredentialID:      res.CredentialID,
		AuthenticatorData: res.AuthenticatorData,
		Signature:         res.Signature,
		UserHandle:        res.UserID,
		ClientDataJSON:    opts.ClientDataJSON,
	}, nil
}

func (a *windowsAuthenticator) DeleteCredential(_ context.Context, rpID string, credentialID []byte) error {
	if rpID == "" || len(credentialID) == 0 {
		return invalidParam("empty rpID or credentialID")
	}
	if err := a.api.deleteCredential(credentialID); err != nil {
		if we, ok := errors.AsType[*winwebauthn.WinError](err); ok && we.Kind == winwebauthn.WinErrNotSupported {
			return &PlatformError{Op: "DeleteCredential", Platform: "windows", Code: int64(we.HR),
				Err: fmt.Errorf("needs WebAuthn API version 4 (Windows 11): %w", err)}
		}
		return mapWinError(err)
	}
	return nil
}
