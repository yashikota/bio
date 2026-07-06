//go:build linux

package bio

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/yashikota/bio/internal/linux"
)

type linuxAuthenticator struct {
	cfg *config
}

func newAuthenticator(opts ...Option) (Authenticator, error) {
	cfg := defaultConfig()
	for _, o := range opts {
		o(cfg)
	}
	return &linuxAuthenticator{cfg: cfg}, nil
}

func (a *linuxAuthenticator) Available(_ context.Context) (BiometryInfo, error) {
	tpmOK := linux.IsTPMAvailable()

	client, err := linux.NewFprintdClient()
	if err != nil {
		return BiometryInfo{Available: false, BiometryType: BiometryFingerprint, Enrolled: false}, nil
	}
	defer client.Close() //nolint:errcheck

	enrolled, _ := client.HasEnrolledFingerprints()
	available := tpmOK && enrolled

	return BiometryInfo{
		Available:    available,
		BiometryType: BiometryFingerprint,
		Enrolled:     enrolled,
	}, nil
}

func (a *linuxAuthenticator) MakeCredential(ctx context.Context, opts MakeCredentialOptions) (*Credential, error) {
	if len(opts.Challenge) == 0 {
		return nil, ErrInvalidParameter
	}
	if opts.RP.ID == "" {
		return nil, ErrInvalidParameter
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	client, err := linux.NewFprintdClient()
	if err != nil {
		return nil, mapLinuxError("MakeCredential", err)
	}
	defer client.Close() //nolint:errcheck

	verifyCtx := ctx
	if a.cfg.verifyTimeout > 0 {
		var cancel context.CancelFunc
		verifyCtx, cancel = context.WithTimeout(ctx, a.cfg.verifyTimeout)
		defer cancel()
	}
	if err := client.Verify(verifyCtx); err != nil {
		return nil, mapLinuxError("MakeCredential", err)
	}

	credID := make([]byte, 32)
	if _, err := rand.Read(credID); err != nil {
		return nil, fmt.Errorf("bio: generate credential ID: %w", err)
	}

	pub, priv, rawPubKey, err := linux.CreateKey()
	if err != nil {
		return nil, mapLinuxError("MakeCredential", err)
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

	coseKey := linux.EncodeCOSEES256(rawPubKey)

	var aaguid [16]byte
	flags := byte(linux.FlagUP | linux.FlagUV | linux.FlagAT)
	authData := linux.BuildAuthenticatorData(opts.RP.ID, flags, 0, aaguid, credID, coseKey)

	attObj := linux.EncodeMap(
		linux.EncodeText("fmt"), linux.EncodeText("none"),
		linux.EncodeText("attStmt"), linux.EncodeMap(),
		linux.EncodeText("authData"), linux.EncodeBytes(authData),
	)

	store, err := linux.NewCredentialStore()
	if err != nil {
		return nil, mapLinuxError("MakeCredential", err)
	}
	if err := store.Save(&linux.CredentialRecord{
		RPID:         opts.RP.ID,
		CredentialID: credID,
		TPMPublic:    pub,
		TPMPrivate:   priv,
		UserHandle:   opts.User.ID,
	}); err != nil {
		return nil, mapLinuxError("MakeCredential", err)
	}

	return &Credential{
		ID:                credID,
		PublicKey:         coseKey,
		AttestationObject: attObj,
		ClientDataJSON:    clientDataJSON,
		AuthenticatorData: authData,
		Transport:         []string{"internal"},
	}, nil
}

func (a *linuxAuthenticator) GetAssertion(ctx context.Context, opts GetAssertionOptions) (*Assertion, error) {
	if len(opts.Challenge) == 0 {
		return nil, ErrInvalidParameter
	}
	if opts.RPID == "" {
		return nil, ErrInvalidParameter
	}
	if len(opts.AllowCredentials) == 0 {
		return nil, ErrNoCredentials
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	store, err := linux.NewCredentialStore()
	if err != nil {
		return nil, mapLinuxError("GetAssertion", err)
	}

	var rec *linux.CredentialRecord
	for _, desc := range opts.AllowCredentials {
		r, err := store.Lookup(opts.RPID, desc.ID)
		if err == nil {
			rec = r
			break
		}
	}
	if rec == nil {
		return nil, ErrNoCredentials
	}

	client, err := linux.NewFprintdClient()
	if err != nil {
		return nil, mapLinuxError("GetAssertion", err)
	}
	defer client.Close() //nolint:errcheck

	verifyCtx := ctx
	if a.cfg.verifyTimeout > 0 {
		var cancel context.CancelFunc
		verifyCtx, cancel = context.WithTimeout(ctx, a.cfg.verifyTimeout)
		defer cancel()
	}
	if err := client.Verify(verifyCtx); err != nil {
		return nil, mapLinuxError("GetAssertion", err)
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
	cdHash := clientDataHash(clientDataJSON)

	signCount, err := store.IncrementSignCount(opts.RPID, rec.CredentialID)
	if err != nil {
		return nil, mapLinuxError("GetAssertion", err)
	}

	flags := byte(linux.FlagUP | linux.FlagUV)
	authData := linux.BuildGetAssertionAuthData(opts.RPID, flags, signCount)

	dataToSign := make([]byte, len(authData)+len(cdHash))
	copy(dataToSign, authData)
	copy(dataToSign[len(authData):], cdHash)

	sig, err := linux.Sign(rec.TPMPublic, rec.TPMPrivate, dataToSign)
	if err != nil {
		return nil, mapLinuxError("GetAssertion", err)
	}

	return &Assertion{
		CredentialID:      rec.CredentialID,
		AuthenticatorData: authData,
		Signature:         sig,
		UserHandle:        rec.UserHandle,
		ClientDataJSON:    clientDataJSON,
	}, nil
}

func mapLinuxError(op string, err error) error {
	if err == nil {
		return nil
	}

	var fpErr *linux.FprintdError
	if errors.As(err, &fpErr) {
		switch fpErr.Status {
		case "verify-disconnected", "not-available":
			return ErrNotAvailable
		case "no-enrolled-prints":
			return ErrNotEnrolled
		case "user-canceled":
			return ErrUserCanceled
		}
		return &PlatformError{Op: op, Platform: "linux", Code: 0,
			Err: fmt.Errorf("fprintd: %s", fpErr.Status)}
	}

	var tpmErr *linux.TPMError
	if errors.As(err, &tpmErr) {
		if tpmErr.Code == 0 && tpmErr.Err != nil {
			return &PlatformError{Op: op, Platform: "linux", Code: 0, Err: tpmErr.Err}
		}
		return &PlatformError{Op: op, Platform: "linux", Code: int64(tpmErr.Code), Err: tpmErr}
	}

	if errors.Is(err, context.DeadlineExceeded) {
		return ErrTimeout
	}
	if errors.Is(err, context.Canceled) {
		return ErrUserCanceled
	}

	return &PlatformError{Op: op, Platform: "linux", Code: 0, Err: err}
}
