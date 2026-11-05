package bio

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/yashikota/bio/internal/webauthn"
)

// The macOS and Linux authenticators share this implementation of the
// WebAuthn authenticator model. Only user verification and key storage differ,
// and those are behind the interfaces below so that the whole flow can be
// tested with fakes on any platform.

// verification is the result of a successful user verification. Key stores
// that need it (Secure Enclave keys, PIN-protected TPM keys) type-assert it.
type verification interface {
	Release()
}

type noVerification struct{}

func (noVerification) Release() {}

// userVerifier prompts the user for biometrics.
type userVerifier interface {
	VerifyUser(ctx context.Context, reason string) (verification, error)
}

// errKeyNotFound is returned by keyStore.Lookup and keyStore.Delete.
var errKeyNotFound = errors.New("bio: key not found")

// storedKey is a credential held by a keyStore.
type storedKey struct {
	CredentialID []byte
	UserHandle   []byte
	handle       any // store-specific
}

// keyStore creates, persists and uses ES256 credential keys.
type keyStore interface {
	// Create generates and persists a key and returns its uncompressed P-256 public point.
	Create(ctx context.Context, v verification, rpID string, credID []byte, user User) ([]byte, error)
	Lookup(rpID string, credID []byte) (*storedKey, error)
	// NextSignCount returns the signature counter for the next assertion, or 0 if unsupported.
	NextSignCount(rpID string, k *storedKey) (uint32, error)
	// Sign returns a DER-encoded ECDSA-SHA256 signature over data.
	Sign(ctx context.Context, v verification, k *storedKey, data []byte) ([]byte, error)
	Delete(rpID string, credID []byte) error
}

type localAuthenticator struct {
	cfg       *config
	verifier  userVerifier
	keys      keyStore
	available func(ctx context.Context) (BiometryInfo, error)
	// mapErr converts platform errors into the package's errors.
	mapErr func(op string, err error) error
}

func (a *localAuthenticator) mapError(op string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return contextError(err)
	}
	if isSentinel(err) {
		return err
	}
	return a.mapErr(op, err)
}

func (a *localAuthenticator) reason(fallback string) string {
	if a.cfg.localizedReason != "" {
		return a.cfg.localizedReason
	}
	return fallback
}

func (a *localAuthenticator) Available(ctx context.Context) (BiometryInfo, error) {
	return a.available(ctx)
}

func (a *localAuthenticator) MakeCredential(ctx context.Context, opts MakeCredentialOptions) (*Credential, error) {
	if err := validateMakeCredential(&opts); err != nil {
		return nil, err
	}
	if !supportsES256(opts.PubKeyCredParams) {
		return nil, ErrUnsupportedAlgorithm
	}
	ctx, cancel := withRequestTimeout(ctx, opts.Timeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, contextError(err)
	}

	excluded := false
	for _, d := range opts.ExcludeCredentials {
		if _, err := a.keys.Lookup(opts.RP.ID, d.ID); err == nil {
			excluded = true
			break
		}
	}

	name := opts.RP.Name
	if name == "" {
		name = opts.RP.ID
	}
	v, err := a.verifier.VerifyUser(ctx, a.reason("Register with "+name))
	if err != nil {
		return nil, a.mapError("MakeCredential", err)
	}
	defer v.Release()
	// WebAuthn §6.3.2 step 3: report an excluded credential only after the
	// user consented, so that a page cannot silently probe for credentials.
	if excluded {
		return nil, ErrCredentialExcluded
	}

	credID := make([]byte, 32)
	if _, err := rand.Read(credID); err != nil {
		return nil, fmt.Errorf("bio: generate credential ID: %w", err)
	}
	raw, err := a.keys.Create(ctx, v, opts.RP.ID, credID, opts.User)
	if err != nil {
		return nil, a.mapError("MakeCredential", err)
	}
	cred, err := buildCredential(opts, credID, raw)
	if err != nil {
		_ = a.keys.Delete(opts.RP.ID, credID)
		return nil, err
	}
	return cred, nil
}

func buildCredential(opts MakeCredentialOptions, credID, rawPub []byte) (*Credential, error) {
	cose, err := webauthn.EncodeCOSEES256(rawPub)
	if err != nil {
		return nil, err
	}
	var aaguid [16]byte // zero AAGUID: "none" attestation
	authData, err := webauthn.BuildAuthenticatorData(opts.RP.ID, webauthn.FlagUP|webauthn.FlagUV, 0, aaguid, credID, cose)
	if err != nil {
		return nil, err
	}
	return &Credential{
		ID:                credID,
		PublicKey:         cose,
		AttestationObject: webauthn.EncodeAttestationObjectNone(authData),
		ClientDataJSON:    opts.ClientDataJSON,
		AuthenticatorData: authData,
		Transport:         []string{"internal"},
	}, nil
}

func (a *localAuthenticator) GetAssertion(ctx context.Context, opts GetAssertionOptions) (*Assertion, error) {
	if err := validateGetAssertion(&opts); err != nil {
		return nil, err
	}
	// Discoverable credentials are not supported: the caller must name them.
	if len(opts.AllowCredentials) == 0 {
		return nil, ErrNoCredentials
	}
	ctx, cancel := withRequestTimeout(ctx, opts.Timeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, contextError(err)
	}

	var key *storedKey
	for _, d := range opts.AllowCredentials {
		k, err := a.keys.Lookup(opts.RPID, d.ID)
		if err == nil {
			key = k
			break
		}
		if !errors.Is(err, errKeyNotFound) {
			return nil, a.mapError("GetAssertion", err)
		}
	}
	if key == nil {
		return nil, ErrNoCredentials
	}

	v, err := a.verifier.VerifyUser(ctx, a.reason("Sign in to "+opts.RPID))
	if err != nil {
		return nil, a.mapError("GetAssertion", err)
	}
	defer v.Release()

	count, err := a.keys.NextSignCount(opts.RPID, key)
	if err != nil {
		return nil, a.mapError("GetAssertion", err)
	}
	authData := webauthn.BuildAssertionAuthData(opts.RPID, webauthn.FlagUP|webauthn.FlagUV, count)
	sig, err := a.keys.Sign(ctx, v, key, webauthn.SignedData(authData, opts.ClientDataJSON))
	if err != nil {
		return nil, a.mapError("GetAssertion", err)
	}
	return &Assertion{
		CredentialID:      key.CredentialID,
		AuthenticatorData: authData,
		Signature:         sig,
		UserHandle:        key.UserHandle,
		ClientDataJSON:    opts.ClientDataJSON,
	}, nil
}

func (a *localAuthenticator) DeleteCredential(_ context.Context, rpID string, credentialID []byte) error {
	if rpID == "" || len(credentialID) == 0 {
		return invalidParam("empty rpID or credentialID")
	}
	err := a.keys.Delete(rpID, credentialID)
	if errors.Is(err, errKeyNotFound) {
		return ErrNoCredentials
	}
	return a.mapError("DeleteCredential", err)
}
