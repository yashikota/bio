//go:build darwin

package bio

import (
	"context"
	"errors"
	"fmt"

	"github.com/yashikota/bio/internal/darwin"
)

// On macOS, user verification is LocalAuthentication (Touch ID / Face ID /
// Optic ID). By default keys are software P-256 keys in the login Keychain
// and the biometric check happens in this process only: code running in the
// same process, or another app the Keychain item's ACL trusts, can sign
// without biometrics. WithSecureEnclave makes the OS enforce it instead.

func newAuthenticator(opts ...Option) (Authenticator, error) {
	cfg := newConfig(opts)
	keys := &keychainStore{namespace: cfg.namespace, opts: darwin.KeyOptions{SecureEnclave: cfg.secureEnclave}}
	return newDarwinAuthenticator(cfg, laVerifier{}, keys), nil
}

func newDarwinAuthenticator(cfg *config, v userVerifier, keys keyStore) *localAuthenticator {
	return &localAuthenticator{
		cfg:       cfg,
		verifier:  v,
		keys:      keys,
		available: darwinAvailable,
		mapErr:    mapDarwinError,
	}
}

func darwinAvailable(context.Context) (BiometryInfo, error) {
	canEval, bt, err := darwin.CheckAvailability(darwin.LAPolicyDeviceOwnerAuthenticationWithBiometrics)
	info := BiometryInfo{Available: canEval, BiometryType: mapBiometryType(bt), Enrolled: canEval}
	var laErr *darwin.LAError
	if errors.As(err, &laErr) {
		switch laErr.Code {
		case darwin.LAErrorBiometryNotAvailable, darwin.LAErrorBiometryNotEnrolled, darwin.LAErrorPasscodeNotSet:
			return info, nil
		case darwin.LAErrorBiometryLockout:
			info.Enrolled = true
			return info, nil
		}
	}
	if err != nil {
		return info, mapDarwinError("Available", err)
	}
	return info, nil
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

// laVerifier evaluates the biometrics policy with a fresh LAContext.
type laVerifier struct{}

// laVerification keeps the evaluated LAContext so that a Secure Enclave key can use it.
type laVerification struct{ ctx *darwin.LAContext }

func (v *laVerification) Release() { v.ctx.Release() }

func (laVerifier) VerifyUser(ctx context.Context, reason string) (verification, error) {
	la, err := darwin.NewLAContext()
	if err != nil {
		return nil, err
	}
	if err := la.Evaluate(ctx, darwin.LAPolicyDeviceOwnerAuthenticationWithBiometrics, reason); err != nil {
		la.Release()
		return nil, err
	}
	return &laVerification{ctx: la}, nil
}

// keychainStore keeps credential keys in the Keychain, tagged
// "<namespace>:<rpID>:<credentialID>", and the user handle in a generic
// password item beside each key. macOS keys have no signature counter.
type keychainStore struct {
	namespace string
	opts      darwin.KeyOptions
}

func (s *keychainStore) tag(rpID string, credID []byte) []byte {
	return darwin.KeychainTag(s.namespace, rpID, credID)
}

func (s *keychainStore) service(rpID string) string {
	return s.namespace + ":" + rpID + ":user-handle"
}

func (s *keychainStore) Create(_ context.Context, _ verification, rpID string, credID []byte, user User) ([]byte, error) {
	label := rpID + "/" + user.Name
	raw, err := darwin.CreateKey(label, s.tag(rpID, credID), s.opts)
	if err != nil {
		return nil, err
	}
	if len(user.ID) > 0 {
		if err := darwin.StoreData(s.service(rpID), credID, user.ID, s.opts); err != nil {
			_ = darwin.DeleteKey(s.tag(rpID, credID), s.opts)
			return nil, err
		}
	}
	return raw, nil
}

func (s *keychainStore) Lookup(rpID string, credID []byte) (*storedKey, error) {
	ok, err := darwin.KeyExists(s.tag(rpID, credID), s.opts)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errKeyNotFound
	}
	uh, err := darwin.LoadData(s.service(rpID), credID, s.opts)
	if err != nil && !errors.Is(err, darwin.ErrNotFound) {
		return nil, err
	}
	return &storedKey{CredentialID: credID, UserHandle: uh, handle: rpID}, nil
}

func (s *keychainStore) NextSignCount(string, *storedKey) (uint32, error) { return 0, nil }

func (s *keychainStore) Sign(_ context.Context, v verification, k *storedKey, data []byte) ([]byte, error) {
	var la *darwin.LAContext
	if lv, ok := v.(*laVerification); ok {
		la = lv.ctx
	}
	sig, err := darwin.Sign(s.tag(k.handle.(string), k.CredentialID), s.opts, la, data)
	if errors.Is(err, darwin.ErrNotFound) {
		return nil, ErrNoCredentials
	}
	return sig, err
}

func (s *keychainStore) Delete(rpID string, credID []byte) error {
	err := darwin.DeleteKey(s.tag(rpID, credID), s.opts)
	if dErr := darwin.DeleteData(s.service(rpID), credID, s.opts); dErr != nil && !errors.Is(dErr, darwin.ErrNotFound) && err == nil {
		err = dErr
	}
	if errors.Is(err, darwin.ErrNotFound) {
		return errKeyNotFound
	}
	return err
}

func mapDarwinError(op string, err error) error {
	var laErr *darwin.LAError
	if errors.As(err, &laErr) {
		switch laErr.Code {
		case darwin.LAErrorUserCancel, darwin.LAErrorUserFallback, darwin.LAErrorSystemCancel, darwin.LAErrorAppCancel:
			return ErrUserCanceled
		case darwin.LAErrorPasscodeNotSet, darwin.LAErrorBiometryNotEnrolled:
			return ErrNotEnrolled
		case darwin.LAErrorBiometryNotAvailable:
			return ErrNotAvailable
		case darwin.LAErrorBiometryLockout:
			return &PlatformError{Op: op, Platform: "darwin", Code: laErr.Code, Err: errors.New("biometry locked out")}
		case darwin.LAErrorAuthenticationFailed:
			return &PlatformError{Op: op, Platform: "darwin", Code: laErr.Code, Err: errors.New("authentication failed")}
		default:
			return &PlatformError{Op: op, Platform: "darwin", Code: laErr.Code, Err: err}
		}
	}
	var secErr *darwin.SecError
	if errors.As(err, &secErr) {
		pe := &PlatformError{Op: op, Platform: "darwin", Code: secErr.Status, Err: err}
		if secErr.MissingEntitlement() {
			pe.Err = fmt.Errorf("%w (WithSecureEnclave needs a code-signed app with the keychain-access-groups entitlement)", err)
		}
		return pe
	}
	return &PlatformError{Op: op, Platform: "darwin", Err: err}
}
