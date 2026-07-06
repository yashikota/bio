//go:build linux

package linux

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

var ErrCredentialNotFound = errors.New("credential not found")

type CredentialRecord struct {
	RPID         string    `json:"rp_id"`
	CredentialID []byte    `json:"credential_id"`
	TPMPublic    []byte    `json:"tpm_public"`
	TPMPrivate   []byte    `json:"tpm_private"`
	UserHandle   []byte    `json:"user_handle"`
	SignCount    uint32    `json:"sign_count"`
	CreatedAt    time.Time `json:"created_at"`
}

type storeFile struct {
	Version     int                 `json:"version"`
	Credentials []*CredentialRecord `json:"credentials"`
}

type CredentialStore struct {
	path string
}

func NewCredentialStore() (*CredentialStore, error) {
	dir := credentialDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("bio store: mkdir %s: %w", dir, err)
	}
	return &CredentialStore{path: filepath.Join(dir, "credentials.json")}, nil
}

func credentialDir() string {
	if d := os.Getenv("XDG_DATA_HOME"); d != "" {
		return filepath.Join(d, "bio")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "share", "bio")
}

func (s *CredentialStore) load() (*storeFile, error) {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return &storeFile{Version: 1}, nil
	}
	if err != nil {
		return nil, err
	}
	var sf storeFile
	if err := json.Unmarshal(data, &sf); err != nil {
		return nil, fmt.Errorf("bio store: parse: %w", err)
	}
	return &sf, nil
}

func (s *CredentialStore) save(sf *storeFile) error {
	data, err := json.MarshalIndent(sf, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0600)
}

func (s *CredentialStore) Save(rec *CredentialRecord) error {
	sf, err := s.load()
	if err != nil {
		return err
	}
	sf.Credentials = append(sf.Credentials, rec)
	return s.save(sf)
}

func (s *CredentialStore) Lookup(rpID string, credentialID []byte) (*CredentialRecord, error) {
	sf, err := s.load()
	if err != nil {
		return nil, err
	}
	for _, r := range sf.Credentials {
		if r.RPID == rpID && bytesEqual(r.CredentialID, credentialID) {
			return r, nil
		}
	}
	return nil, ErrCredentialNotFound
}

// IncrementSignCount atomically increments the sign count for the given credential.
func (s *CredentialStore) IncrementSignCount(rpID string, credentialID []byte) (uint32, error) {
	sf, err := s.load()
	if err != nil {
		return 0, err
	}
	for _, r := range sf.Credentials {
		if r.RPID == rpID && bytesEqual(r.CredentialID, credentialID) {
			r.SignCount++
			if err := s.save(sf); err != nil {
				return 0, err
			}
			return r.SignCount, nil
		}
	}
	return 0, ErrCredentialNotFound
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
