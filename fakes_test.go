package bio

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"sync"
)

// fakeVerifier stands in for Touch ID / fprintd.
type fakeVerifier struct {
	mu      sync.Mutex
	next    error // returned by the next VerifyUser; nil means success
	block   bool  // block until ctx is done
	calls   int
	reasons []string
}

func (f *fakeVerifier) VerifyUser(ctx context.Context, reason string) (verification, error) {
	f.mu.Lock()
	f.calls++
	f.reasons = append(f.reasons, reason)
	err, block := f.next, f.block
	f.next = nil
	f.mu.Unlock()
	if block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, err
	}
	return noVerification{}, nil
}

func (f *fakeVerifier) Calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// softwareKeyStore is an in-memory keyStore backed by crypto/ecdsa.
type softwareKeyStore struct {
	mu   sync.Mutex
	keys map[string]*softwareKey
}

type softwareKey struct {
	priv       *ecdsa.PrivateKey
	userHandle []byte
	count      uint32
}

func newSoftwareKeyStore() *softwareKeyStore {
	return &softwareKeyStore{keys: map[string]*softwareKey{}}
}

func skey(rpID string, credID []byte) string { return rpID + "\x00" + string(credID) }

func (s *softwareKeyStore) Create(_ context.Context, _ verification, rpID string, credID []byte, user User) ([]byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[skey(rpID, credID)] = &softwareKey{priv: priv, userHandle: bytes.Clone(user.ID)}
	return priv.PublicKey.Bytes()
}

func (s *softwareKeyStore) Lookup(rpID string, credID []byte) (*storedKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[skey(rpID, credID)]
	if !ok {
		return nil, errKeyNotFound
	}
	return &storedKey{CredentialID: bytes.Clone(credID), UserHandle: k.userHandle, handle: k}, nil
}

func (s *softwareKeyStore) NextSignCount(_ string, k *storedKey) (uint32, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sk := k.handle.(*softwareKey)
	sk.count++
	return sk.count, nil
}

func (s *softwareKeyStore) Sign(_ context.Context, _ verification, k *storedKey, data []byte) ([]byte, error) {
	d := sha256.Sum256(data)
	return ecdsa.SignASN1(rand.Reader, k.handle.(*softwareKey).priv, d[:])
}

func (s *softwareKeyStore) Delete(rpID string, credID []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.keys[skey(rpID, credID)]; !ok {
		return errKeyNotFound
	}
	delete(s.keys, skey(rpID, credID))
	return nil
}

func identityMap(_ string, err error) error { return err }

func newFakeLocal(opts ...Option) (*localAuthenticator, *fakeVerifier) {
	v := &fakeVerifier{}
	return &localAuthenticator{
		cfg:      newConfig(opts),
		verifier: v,
		keys:     newSoftwareKeyStore(),
		available: func(context.Context) (BiometryInfo, error) {
			return BiometryInfo{Available: true, BiometryType: BiometryFingerprint, Enrolled: true}, nil
		},
		mapErr: identityMap,
	}, v
}
