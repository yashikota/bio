//go:build linux

package linux

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

// ErrCredentialNotFound is returned when no record matches.
var ErrCredentialNotFound = errors.New("credential not found")

// CredentialRecord is one stored credential.
type CredentialRecord struct {
	RPID         string    `json:"rp_id"`
	CredentialID []byte    `json:"credential_id"`
	TPMPublic    []byte    `json:"tpm_public"`
	TPMPrivate   []byte    `json:"tpm_private"` // wrapped by the TPM's SRK, useless off this TPM
	UserHandle   []byte    `json:"user_handle"`
	SignCount    uint32    `json:"sign_count"`
	PINProtected bool      `json:"pin_protected,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
}

type storeFile struct {
	Version     int                 `json:"version"`
	Credentials []*CredentialRecord `json:"credentials"`
}

// CredentialStore keeps credential records in a JSON file. Every operation
// holds an flock(2) on a sibling lock file, and writes go to a temporary file
// that is fsynced and renamed over the original, so concurrent processes do
// not lose updates and a crash never leaves a truncated file behind.
type CredentialStore struct {
	path     string
	lockPath string
}

// NewCredentialStore opens the store for namespace under $XDG_DATA_HOME
// (default ~/.local/share).
func NewCredentialStore(namespace string) (*CredentialStore, error) {
	dir, err := credentialDir(namespace)
	if err != nil {
		return nil, err
	}
	return OpenCredentialStore(dir)
}

// OpenCredentialStore opens the store in dir, creating it with mode 0700.
func OpenCredentialStore(dir string) (*CredentialStore, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("bio store: mkdir %s: %w", dir, err)
	}
	return &CredentialStore{
		path:     filepath.Join(dir, "credentials.json"),
		lockPath: filepath.Join(dir, "credentials.lock"),
	}, nil
}

func credentialDir(namespace string) (string, error) {
	if d := os.Getenv("XDG_DATA_HOME"); d != "" && filepath.IsAbs(d) {
		return filepath.Join(d, namespace), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("bio store: %w", err)
	}
	return filepath.Join(home, ".local", "share", namespace), nil
}

// update runs fn with the store locked; if fn returns write=true the result is persisted.
func (s *CredentialStore) update(exclusive bool, fn func(sf *storeFile) (write bool, err error)) error {
	lf, err := os.OpenFile(s.lockPath, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return fmt.Errorf("bio store: open lock: %w", err)
	}
	defer lf.Close()
	how := unix.LOCK_SH
	if exclusive {
		how = unix.LOCK_EX
	}
	for {
		err = unix.Flock(int(lf.Fd()), how)
		if !errors.Is(err, unix.EINTR) {
			break
		}
	}
	if err != nil {
		return fmt.Errorf("bio store: lock: %w", err)
	}
	defer unix.Flock(int(lf.Fd()), unix.LOCK_UN) //nolint:errcheck

	sf, err := s.load()
	if err != nil {
		return err
	}
	write, err := fn(sf)
	if err != nil || !write {
		return err
	}
	if !exclusive {
		panic("bio store: write under shared lock")
	}
	return s.save(sf)
}

func (s *CredentialStore) load() (*storeFile, error) {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return &storeFile{Version: 1}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("bio store: read: %w", err)
	}
	var sf storeFile
	if err := json.Unmarshal(data, &sf); err != nil {
		return nil, fmt.Errorf("bio store: parse %s: %w", s.path, err)
	}
	return &sf, nil
}

func (s *CredentialStore) save(sf *storeFile) error {
	data, err := json.MarshalIndent(sf, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, ".credentials-*.json")
	if err != nil {
		return fmt.Errorf("bio store: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("bio store: write: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("bio store: sync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("bio store: close: %w", err)
	}
	// CreateTemp already uses 0600; Rename keeps it.
	if err := os.Rename(tmp.Name(), s.path); err != nil {
		return fmt.Errorf("bio store: rename: %w", err)
	}
	if d, err := os.Open(dir); err == nil {
		d.Sync() //nolint:errcheck
		d.Close()
	}
	return nil
}

func (sf *storeFile) find(rpID string, credentialID []byte) (int, *CredentialRecord) {
	for i, r := range sf.Credentials {
		if r.RPID == rpID && bytes.Equal(r.CredentialID, credentialID) {
			return i, r
		}
	}
	return -1, nil
}

// Save adds a record.
func (s *CredentialStore) Save(rec *CredentialRecord) error {
	if rec.CreatedAt.IsZero() {
		rec.CreatedAt = time.Now().UTC()
	}
	return s.update(true, func(sf *storeFile) (bool, error) {
		if _, r := sf.find(rec.RPID, rec.CredentialID); r != nil {
			return false, fmt.Errorf("bio store: duplicate credential ID")
		}
		sf.Credentials = append(sf.Credentials, rec)
		return true, nil
	})
}

// Lookup returns the record for rpID and credentialID, or ErrCredentialNotFound.
func (s *CredentialStore) Lookup(rpID string, credentialID []byte) (*CredentialRecord, error) {
	var found *CredentialRecord
	err := s.update(false, func(sf *storeFile) (bool, error) {
		_, found = sf.find(rpID, credentialID)
		return false, nil
	})
	if err != nil {
		return nil, err
	}
	if found == nil {
		return nil, ErrCredentialNotFound
	}
	return found, nil
}

// IncrementSignCount increments and returns the signature counter under an exclusive lock.
func (s *CredentialStore) IncrementSignCount(rpID string, credentialID []byte) (uint32, error) {
	var count uint32
	err := s.update(true, func(sf *storeFile) (bool, error) {
		_, r := sf.find(rpID, credentialID)
		if r == nil {
			return false, ErrCredentialNotFound
		}
		r.SignCount++
		count = r.SignCount
		return true, nil
	})
	return count, err
}

// Delete removes a record, or returns ErrCredentialNotFound.
func (s *CredentialStore) Delete(rpID string, credentialID []byte) error {
	return s.update(true, func(sf *storeFile) (bool, error) {
		i, r := sf.find(rpID, credentialID)
		if r == nil {
			return false, ErrCredentialNotFound
		}
		sf.Credentials = append(sf.Credentials[:i], sf.Credentials[i+1:]...)
		return true, nil
	})
}
