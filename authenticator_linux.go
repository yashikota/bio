//go:build linux

package bio

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/yashikota/bio/internal/linux"
)

// On Linux, user verification is a fingerprint match through fprintd and keys
// live in the TPM. Note the trust model: fprintd only reports a match, it does
// not release a secret, so the TPM key itself is not bound to the fingerprint.
// Any process running as the same user can load the key blob and sign. Use
// WithPINPrompt for keys whose use the TPM itself enforces.

func newAuthenticator(opts ...Option) (Authenticator, error) {
	cfg := newConfig(opts)
	return newLinuxAuthenticator(cfg, linux.NewFprintd(), linux.NewTPM(), func() (*linux.CredentialStore, error) {
		return linux.NewCredentialStore(cfg.namespace)
	}), nil
}

func newLinuxAuthenticator(cfg *config, fp *linux.Fprintd, tpm *linux.TPM, store func() (*linux.CredentialStore, error)) *localAuthenticator {
	return &localAuthenticator{
		cfg:      cfg,
		verifier: &fprintdVerifier{fprintd: fp, timeout: cfg.verifyTimeout, pinPrompt: cfg.pinPrompt},
		keys:     &tpmKeyStore{tpm: tpm, store: store},
		available: func(context.Context) (BiometryInfo, error) {
			return linuxAvailable(fp, tpm), nil
		},
		mapErr: mapLinuxError,
	}
}

func linuxAvailable(fp *linux.Fprintd, tpm *linux.TPM) BiometryInfo {
	info := BiometryInfo{BiometryType: BiometryFingerprint}
	client, err := fp.Open()
	if err != nil {
		return info
	}
	defer client.Close()
	enrolled, err := client.HasEnrolledFingerprints()
	info.Enrolled = err == nil && enrolled
	info.Available = info.Enrolled && tpm.Available()
	return info
}

type fprintdVerifier struct {
	fprintd   *linux.Fprintd
	timeout   time.Duration
	pinPrompt func(ctx context.Context) (string, error)
}

// pinVerification carries the PIN entered after a fingerprint match.
type pinVerification struct{ pin []byte }

func (p *pinVerification) Release() { clear(p.pin) }

func (v *fprintdVerifier) VerifyUser(ctx context.Context, _ string) (verification, error) {
	client, err := v.fprintd.Open()
	if err != nil {
		return nil, err
	}
	defer client.Close()
	verifyCtx := ctx
	if v.timeout > 0 {
		var cancel context.CancelFunc
		verifyCtx, cancel = context.WithTimeout(ctx, v.timeout)
		defer cancel()
	}
	if err := client.Verify(verifyCtx); err != nil {
		return nil, err
	}
	if v.pinPrompt == nil {
		return noVerification{}, nil
	}
	pin, err := v.pinPrompt(ctx)
	if err != nil {
		return nil, err
	}
	if pin == "" {
		return nil, invalidParam("empty PIN")
	}
	return &pinVerification{pin: []byte(pin)}, nil
}

// errPINRequired is returned for a PIN-protected key when no PIN prompt is configured.
var errPINRequired = errors.New("bio: credential is PIN-protected; configure WithPINPrompt")

type tpmKeyStore struct {
	tpm   *linux.TPM
	store func() (*linux.CredentialStore, error)
}

func pinOf(v verification) []byte {
	if p, ok := v.(*pinVerification); ok {
		return p.pin
	}
	return nil
}

func (s *tpmKeyStore) Create(_ context.Context, v verification, rpID string, credID []byte, user User) ([]byte, error) {
	store, err := s.store()
	if err != nil {
		return nil, err
	}
	pin := pinOf(v)
	pub, priv, raw, err := s.tpm.CreateKey(pin)
	if err != nil {
		return nil, err
	}
	if err := store.Save(&linux.CredentialRecord{
		RPID:         rpID,
		CredentialID: credID,
		TPMPublic:    pub,
		TPMPrivate:   priv,
		UserHandle:   bytes.Clone(user.ID),
		PINProtected: len(pin) > 0,
	}); err != nil {
		return nil, err
	}
	return raw, nil
}

func (s *tpmKeyStore) Lookup(rpID string, credID []byte) (*storedKey, error) {
	store, err := s.store()
	if err != nil {
		return nil, err
	}
	rec, err := store.Lookup(rpID, credID)
	if errors.Is(err, linux.ErrCredentialNotFound) {
		return nil, errKeyNotFound
	}
	if err != nil {
		return nil, err
	}
	return &storedKey{CredentialID: rec.CredentialID, UserHandle: rec.UserHandle, handle: rec}, nil
}

func (s *tpmKeyStore) NextSignCount(rpID string, k *storedKey) (uint32, error) {
	store, err := s.store()
	if err != nil {
		return 0, err
	}
	return store.IncrementSignCount(rpID, k.CredentialID)
}

func (s *tpmKeyStore) Sign(_ context.Context, v verification, k *storedKey, data []byte) ([]byte, error) {
	rec := k.handle.(*linux.CredentialRecord)
	pin := pinOf(v)
	if rec.PINProtected && len(pin) == 0 {
		return nil, errPINRequired
	}
	if !rec.PINProtected {
		pin = nil
	}
	return s.tpm.Sign(rec.TPMPublic, rec.TPMPrivate, pin, data)
}

func (s *tpmKeyStore) Delete(rpID string, credID []byte) error {
	store, err := s.store()
	if err != nil {
		return err
	}
	if err := store.Delete(rpID, credID); errors.Is(err, linux.ErrCredentialNotFound) {
		return errKeyNotFound
	} else if err != nil {
		return err
	}
	return nil
}

func mapLinuxError(op string, err error) error {
	var fpErr *linux.FprintdError
	if errors.As(err, &fpErr) {
		switch fpErr.Status {
		case "verify-disconnected", "net.reactivated.Fprint.Error.NoSuchDevice":
			return ErrNotAvailable
		case "net.reactivated.Fprint.Error.NoEnrolledPrints":
			return ErrNotEnrolled
		}
		if fpErr.Op == "connect" || fpErr.Op == "GetDefaultDevice" {
			return fmt.Errorf("%w: %w", ErrNotAvailable, err)
		}
		return &PlatformError{Op: op, Platform: "linux", Err: err}
	}

	var tpmErr *linux.TPMError
	if errors.As(err, &tpmErr) {
		return &PlatformError{Op: op, Platform: "linux", Code: int64(tpmErr.Code), Err: tpmErr}
	}
	if errors.Is(err, ErrInvalidParameter) {
		return err
	}
	return &PlatformError{Op: op, Platform: "linux", Err: err}
}
