//go:build darwin

package bio

import (
	"context"
	"errors"
	"fmt"

	"github.com/yashikota/bio/internal/darwin"
)

type darwinAuthenticator struct {
	cfg *config
}

func newAuthenticator(opts ...Option) (Authenticator, error) {
	cfg := defaultConfig()
	for _, o := range opts {
		o(cfg)
	}
	return &darwinAuthenticator{cfg: cfg}, nil
}

func (a *darwinAuthenticator) Available(_ context.Context) (BiometryInfo, error) {
	canEval, biometryType, err := darwin.CheckAvailability(darwin.LAPolicyDeviceOwnerAuthenticationWithBiometrics)
	if err != nil {
		return BiometryInfo{}, mapLAError("Available", err)
	}
	return BiometryInfo{
		Available:    canEval,
		BiometryType: mapBiometryType(biometryType),
		Enrolled:     biometryType != darwin.LABiometryTypeNone,
	}, nil
}

// mapLAError converts a darwin.LAError into the appropriate bio package error.
func mapLAError(op string, err error) error {
	if err == nil {
		return nil
	}
	var laErr *darwin.LAError
	if !errors.As(err, &laErr) {
		return err
	}
	switch laErr.Code {
	case darwin.LAErrorUserCancel, darwin.LAErrorUserFallback, darwin.LAErrorSystemCancel, darwin.LAErrorAppCancel:
		return ErrUserCanceled
	case darwin.LAErrorPasscodeNotSet, darwin.LAErrorBiometryNotEnrolled:
		return ErrNotEnrolled
	case darwin.LAErrorBiometryNotAvailable:
		return ErrNotAvailable
	case darwin.LAErrorBiometryLockout:
		return &PlatformError{Op: op, Platform: "darwin", Code: laErr.Code,
			Err: fmt.Errorf("biometry locked out")}
	case darwin.LAErrorAuthenticationFailed:
		return &PlatformError{Op: op, Platform: "darwin", Code: laErr.Code,
			Err: fmt.Errorf("authentication failed")}
	default:
		return &PlatformError{Op: op, Platform: "darwin", Code: laErr.Code,
			Err: fmt.Errorf("platform error")}
	}
}

func mapBiometryType(t int64) BiometryType {
	switch t {
	case darwin.LABiometryTypeTouchID:
		return BiometryTouchID
	case darwin.LABiometryTypeFaceID:
		return BiometryFaceID
	case darwin.LABiometryTypeOpticID:
		return BiometryOpticID
	default:
		return BiometryNone
	}
}

func (a *darwinAuthenticator) MakeCredential(ctx context.Context, opts MakeCredentialOptions) (*Credential, error) {
	if len(opts.Challenge) == 0 {
		return nil, ErrInvalidParameter
	}
	if opts.RP.ID == "" {
		return nil, ErrInvalidParameter
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Build clientDataJSON (or use caller-provided value)
	var clientDataJSON []byte
	if len(opts.ClientDataJSON) > 0 {
		clientDataJSON = opts.ClientDataJSON
	} else {
		origin := rpIDOrigin(opts.RP.ID)
		var err error
		clientDataJSON, err = buildClientDataJSON("webauthn.create", origin, opts.Challenge)
		if err != nil {
			return nil, err
		}
	}

	// Generate credential ID
	credID, err := darwin.GenerateCredentialID()
	if err != nil {
		return nil, err
	}

	// Build Keychain application tag
	tag := darwin.KeychainTag(opts.RP.ID, credID)

	// Authenticate with biometrics before creating the key
	reason := a.cfg.localizedReason
	if reason == "" {
		reason = "Register with " + opts.RP.Name
	}
	if authErr := darwin.Authenticate(darwin.LAPolicyDeviceOwnerAuthenticationWithBiometrics, reason); authErr != nil {
		return nil, mapLAError("MakeCredential", authErr)
	}

	// Create EC P-256 key stored in Keychain (biometric confirmed above)
	label := opts.RP.Name + "/" + opts.User.Name
	privKey, err := darwin.CreateBiometricKey(label, tag)
	if err != nil {
		return nil, err
	}
	defer darwin.ReleaseKey(privKey)

	// Export COSE public key
	coseKey, err := darwin.ExportPublicKeyCOSE(privKey)
	if err != nil {
		_ = darwin.DeleteCredential(opts.RP.ID, credID)
		return nil, err
	}

	// Build authenticator data (FIDO2 §6.1)
	var aaguid [16]byte // zero AAGUID for self-attestation
	flags := byte(darwin.FlagUP | darwin.FlagUV | darwin.FlagAT)
	authData := darwin.BuildAuthenticatorData(opts.RP.ID, flags, 0, aaguid, credID, coseKey)

	// Build attestation object — "none" attestation, CBOR encoded
	attObj := darwin.EncodeMap(
		darwin.EncodeText("fmt"), darwin.EncodeText("none"),
		darwin.EncodeText("attStmt"), darwin.EncodeMap(),
		darwin.EncodeText("authData"), darwin.EncodeBytes(authData),
	)

	return &Credential{
		ID:                credID,
		PublicKey:         coseKey,
		AttestationObject: attObj,
		ClientDataJSON:    clientDataJSON,
		AuthenticatorData: authData,
		Transport:         []string{"internal"},
	}, nil
}

func (a *darwinAuthenticator) GetAssertion(ctx context.Context, opts GetAssertionOptions) (*Assertion, error) {
	if len(opts.Challenge) == 0 {
		return nil, ErrInvalidParameter
	}
	if opts.RPID == "" {
		return nil, ErrInvalidParameter
	}

	// Build clientDataJSON (or use caller-provided value)
	var clientDataJSON []byte
	if len(opts.ClientDataJSON) > 0 {
		clientDataJSON = opts.ClientDataJSON
	} else {
		origin := rpIDOrigin(opts.RPID)
		var err error
		clientDataJSON, err = buildClientDataJSON("webauthn.get", origin, opts.Challenge)
		if err != nil {
			return nil, err
		}
	}
	cdHash := clientDataHash(clientDataJSON)

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Find the private key. If AllowCredentials is empty, credential scan is not supported.
	if len(opts.AllowCredentials) == 0 {
		return nil, ErrNoCredentials
	}

	var privKey darwin.SecKeyRefValue
	var usedCredID []byte
	var lastErr error

	for _, desc := range opts.AllowCredentials {
		tag := darwin.KeychainTag(opts.RPID, desc.ID)
		k, err := darwin.LookupPrivateKey(tag)
		if err != nil {
			lastErr = err
			continue
		}
		privKey = k
		usedCredID = desc.ID
		break
	}

	if usedCredID == nil {
		if lastErr != nil {
			return nil, lastErr
		}
		return nil, ErrNoCredentials
	}
	defer darwin.ReleaseKey(privKey)

	// Authenticate with biometrics before signing
	reason := a.cfg.localizedReason
	if reason == "" {
		reason = "Sign in to " + opts.RPID
	}
	if authErr := darwin.Authenticate(darwin.LAPolicyDeviceOwnerAuthenticationWithBiometrics, reason); authErr != nil {
		return nil, mapLAError("GetAssertion", authErr)
	}

	// Build authenticator data (no attested credential data for assertions)
	flags := byte(darwin.FlagUP | darwin.FlagUV)
	authData := darwin.BuildGetAssertionAuthData(opts.RPID, flags, 0)

	// Sign: authData || clientDataHash (FIDO2 spec §6.3.3).
	// Use make+copy to avoid mutating authData's backing array (returned in Assertion).
	dataToSign := make([]byte, len(authData)+len(cdHash))
	copy(dataToSign, authData)
	copy(dataToSign[len(authData):], cdHash)
	sig, err := darwin.Sign(privKey, dataToSign)
	if err != nil {
		return nil, err
	}

	return &Assertion{
		CredentialID:      usedCredID,
		AuthenticatorData: authData,
		Signature:         sig,
		UserHandle:        nil, // not stored in Keychain tag
		ClientDataJSON:    clientDataJSON,
	}, nil
}
