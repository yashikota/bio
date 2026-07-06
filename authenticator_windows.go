//go:build windows

package bio

import (
	"context"
	"errors"
	"fmt"
	"time"

	winwebauthn "github.com/yashikota/bio/internal/windows"
)

type windowsAuthenticator struct {
	cfg *config
}

func newAuthenticator(opts ...Option) (Authenticator, error) {
	cfg := defaultConfig()
	for _, o := range opts {
		o(cfg)
	}
	return &windowsAuthenticator{cfg: cfg}, nil
}

func (a *windowsAuthenticator) Available(_ context.Context) (BiometryInfo, error) {
	ok, err := winwebauthn.IsAvailable()
	if err != nil {
		return BiometryInfo{}, mapWinError(err)
	}
	biometryType := BiometryNone
	if ok {
		biometryType = BiometryHello
	}
	return BiometryInfo{
		Available:    ok,
		BiometryType: biometryType,
		Enrolled:     ok,
	}, nil
}

// mapWinError converts a winwebauthn.WinError to a bio package error.
func mapWinError(err error) error {
	if err == nil {
		return nil
	}
	we, ok := errors.AsType[*winwebauthn.WinError](err)
	if !ok {
		return err
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
	default:
		return &PlatformError{
			Op:       we.Op,
			Platform: "windows",
			Code:     int64(we.HR),
			Err:      fmt.Errorf("HRESULT 0x%08X", we.HR),
		}
	}
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

func (a *windowsAuthenticator) MakeCredential(ctx context.Context, opts MakeCredentialOptions) (*Credential, error) {
	if len(opts.Challenge) == 0 {
		return nil, ErrInvalidParameter
	}
	if opts.RP.ID == "" {
		return nil, ErrInvalidParameter
	}

	var clientDataJSON []byte
	if len(opts.ClientDataJSON) > 0 {
		clientDataJSON = opts.ClientDataJSON
	} else {
		origin := rpIDOrigin(opts.RP.ID)
		var cdErr error
		clientDataJSON, cdErr = buildClientDataJSON("webauthn.create", origin, opts.Challenge)
		if cdErr != nil {
			return nil, cdErr
		}
	}

	algs := make([]int32, 0, len(opts.PubKeyCredParams))
	for _, p := range opts.PubKeyCredParams {
		algs = append(algs, int32(p.Algorithm))
	}
	if len(algs) == 0 {
		algs = []int32{int32(AlgES256)}
	}

	excludeIDs := make([][]byte, 0, len(opts.ExcludeCredentials))
	for _, c := range opts.ExcludeCredentials {
		excludeIDs = append(excludeIDs, c.ID)
	}

	timeoutMS := uint32(60000)
	if opts.Timeout > 0 {
		timeoutMS = uint32(opts.Timeout / time.Millisecond)
	}

	hwnd := winwebauthn.ResolveHWND(a.cfg.hwnd)

	res, err := winwebauthn.MakeCredential(ctx, &winwebauthn.MakeCredentialParams{
		HWND:             hwnd,
		RPID:             opts.RP.ID,
		RPName:           opts.RP.Name,
		UserID:           opts.User.ID,
		UserName:         opts.User.Name,
		UserDisplayName:  opts.User.DisplayName,
		Challenge:        opts.Challenge,
		ClientDataJSON:   clientDataJSON,
		Algorithms:       algs,
		UserVerification: uvRequirement(opts.UserVerification),
		AttestationPref:  attestationPref(opts.Attestation),
		TimeoutMS:        timeoutMS,
		ExcludeIDs:       excludeIDs,
	})
	if err != nil {
		return nil, mapWinError(err)
	}

	return &Credential{
		ID:                res.CredentialID,
		PublicKey:         nil, // Windows does not return the raw public key separately
		AttestationObject: res.AttestationObject,
		ClientDataJSON:    clientDataJSON,
		AuthenticatorData: res.AuthenticatorData,
		Transport:         []string{"internal"},
	}, nil
}

func (a *windowsAuthenticator) GetAssertion(ctx context.Context, opts GetAssertionOptions) (*Assertion, error) {
	if len(opts.Challenge) == 0 {
		return nil, ErrInvalidParameter
	}
	if opts.RPID == "" {
		return nil, ErrInvalidParameter
	}

	var clientDataJSON []byte
	if len(opts.ClientDataJSON) > 0 {
		clientDataJSON = opts.ClientDataJSON
	} else {
		origin := rpIDOrigin(opts.RPID)
		var cdErr error
		clientDataJSON, cdErr = buildClientDataJSON("webauthn.get", origin, opts.Challenge)
		if cdErr != nil {
			return nil, cdErr
		}
	}

	allowIDs := make([][]byte, 0, len(opts.AllowCredentials))
	for _, c := range opts.AllowCredentials {
		allowIDs = append(allowIDs, c.ID)
	}

	timeoutMS := uint32(60000)
	if opts.Timeout > 0 {
		timeoutMS = uint32(opts.Timeout / time.Millisecond)
	}

	hwnd := winwebauthn.ResolveHWND(a.cfg.hwnd)

	res, err := winwebauthn.GetAssertion(ctx, &winwebauthn.GetAssertionParams{
		HWND:             hwnd,
		RPID:             opts.RPID,
		ClientDataJSON:   clientDataJSON,
		AllowIDs:         allowIDs,
		UserVerification: uvRequirement(opts.UserVerification),
		TimeoutMS:        timeoutMS,
	})
	if err != nil {
		return nil, mapWinError(err)
	}

	return &Assertion{
		CredentialID:      res.CredentialID,
		AuthenticatorData: res.AuthenticatorData,
		Signature:         res.Signature,
		UserHandle:        res.UserID,
		ClientDataJSON:    clientDataJSON,
	}, nil
}
